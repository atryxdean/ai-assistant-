"""Machine Learning-based vulnerability detection and classification

This module provides a production-ready MLVulnerabilityAnalyzer with training,
loading, evaluation and runtime prediction capabilities. It replaces the
previous "stub" behaviour with deterministic, testable ML code using
scikit-learn's TF-IDF + RandomForest pipeline.

Design goals:
- Be deterministic for CI smoke tests (random_state=42)
- Expose train/load/save/evaluate helpers for automation
- Keep a fallback pattern matcher when sklearn is not installed
- Keep labels aligned with engin33r.core.vulnerability.VulnerabilityType enum values
"""

from __future__ import annotations

import logging
from pathlib import Path
from . import train
from typing import List, Dict, Any, Optional

import numpy as np

from engin33r.analyzers.base import VulnerabilityAnalyzer
from engin33r.core.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
    RemediationStatus,
)

logger = logging.getLogger(__name__)

try:
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder

    HAS_SKLEARN = True
except Exception:  # ImportError or sklearn not installed
    HAS_SKLEARN = False
    # Keep imports lazy for environments without ML deps


class MLVulnerabilityAnalyzer(VulnerabilityAnalyzer):
    """ML-based analyzer using TF-IDF + RandomForest.

    Usage:
        analyzer = MLVulnerabilityAnalyzer(model_path='models/engin33r_model.pkl')
        vulnerabilities = analyzer.analyze('/path/to/code.py')

    If a model path is provided and valid, the analyzer will load a serialized
    joblib dictionary containing {'model','vectorizer','label_encoder'}.
    Otherwise the analyzer will train a fast default model from built-in
    patterns (suitable for CI smoke tests) when sklearn is available.
    """

    # Built-in seed patterns used for quick default training. Keys must match
    # VulnerabilityType enum values (string form)
    TRAINING_PATTERNS: Dict[VulnerabilityType, List[str]] = {
        VulnerabilityType.INJECTION: [
            "SELECT * FROM",
            "execute(",
            "os.system(",
            "subprocess.call(",
        ],
        VulnerabilityType.XSS: [
            "document.write",
            "innerHTML",
            "eval(",
        ],
        VulnerabilityType.BROKEN_AUTH: [
            "password =",
            "hardcoded",
            "auth bypass",
        ],
        VulnerabilityType.SENSITIVE_DATA: [
            "api_key",
            "private_key",
            "secret",
        ],
        VulnerabilityType.BROKEN_ACCESS: [
            "is_authorized",
            "not authorized",
            "access control",
        ],
    }

    def __init__(
        self,
        model_path: Optional[str] = None,
        confidence_threshold: float = 0.6,
        train_if_missing: bool = True,
    ) -> None:
        super().__init__(
            name="MLVulnerabilityAnalyzer",
            description="Machine learning-based vulnerability detection using TF-IDF + RandomForest",
        )
        self.model_path = Path(model_path) if model_path else None
        self.model: Optional[Any] = None
        self.vectorizer: Optional[Any] = None
        self.label_encoder: Optional[Any] = None
        self.severity_predictor = self._create_severity_predictor()
        self.confidence_threshold = float(confidence_threshold)

        if HAS_SKLEARN:
            # Initialize model: load if path exists, else train default (if requested)
            if self.model_path and self.model_path.exists():
                try:
                    self._load_model_file(str(self.model_path))
                except Exception as exc:  # pragma: no cover - load error path
                    logger.warning(
                        "Failed to load model from %s: %s", self.model_path, exc
                    )
                    if train_if_missing:
                        self._train_default_model()
            else:
                if train_if_missing:
                    self._train_default_model()
        else:
            logger.warning(
                "scikit-learn not available: ML analyzer will use pattern fallback"
            )

    # ---------------------- Training / Persistence ----------------------
    def train_from_dataset(
        self,
        dataset_texts: List[str],
        dataset_labels: List[str],
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """Train a TF-IDF + RandomForest model from in-memory lists.

        Returns a metrics dict for quick inspection.
        """
        if not HAS_SKLEARN:
            raise RuntimeError("scikit-learn is required to train models")

        # Ensure labels are strings and consistent with VulnerabilityType values
        labels = [str(l) for l in dataset_labels]

        # Fit vectorizer
        self.vectorizer = TfidfVectorizer(max_features=100, lowercase=True)
        X = self.vectorizer.fit_transform(dataset_texts)

        # Encode labels
        self.label_encoder = LabelEncoder()
        y = self.label_encoder.fit_transform(labels)

        # Train classifier
        self.model = RandomForestClassifier(n_estimators=10, random_state=random_state)
        self.model.fit(X, y)

        # Quick evaluation on training data (not a recommended metric for production)
        preds = self.model.predict(X)
        try:
            from sklearn.metrics import precision_score, recall_score, f1_score

            precision = float(
                precision_score(y, preds, average="weighted", zero_division=0)
            )
            recall = float(recall_score(y, preds, average="weighted", zero_division=0))
            f1 = float(f1_score(y, preds, average="weighted", zero_division=0))
        except Exception:
            precision = recall = f1 = 0.0

        metrics = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "n_samples": len(labels),
        }
        return metrics

    def _train_default_model(self) -> None:
        """Train a small default model from the built-in TRAINING_PATTERNS.

        This is intentionally lightweight and deterministic for CI smoke checks.
        """
        if not HAS_SKLEARN:
            logger.warning("scikit-learn not available; cannot train default model")
            return

        texts: List[str] = []
        labels: List[str] = []
        for vuln_type, patterns in self.TRAINING_PATTERNS.items():
            for p in patterns:
                texts.append(p)
                labels.append(vuln_type.value)

        if not texts:
            logger.error("No training patterns available for default model")
            return

        self.train_from_dataset(texts, labels, random_state=42)
        logger.info("Default ML model trained (%d samples)", len(labels))

    def save_model_file(self, path: str) -> None:
        """Persist the model, vectorizer and label encoder to disk using joblib."""
        if not HAS_SKLEARN:
            raise RuntimeError("scikit-learn is required to save models")
        if self.model is None or self.vectorizer is None or self.label_encoder is None:
            raise RuntimeError("Model is not trained and cannot be saved")

        model_data = {
            "model": self.model,
            "vectorizer": self.vectorizer,
            "label_encoder": self.label_encoder,
        }
        joblib.dump(model_data, path)
        logger.info("Saved ML model to %s", path)

    def _load_model_file(self, path: str) -> None:
        """Internal loader used at initialization."""
        model_data = joblib.load(path)
        self.model = model_data.get("model")
        self.vectorizer = model_data.get("vectorizer")
        self.label_encoder = model_data.get("label_encoder")
        if self.model is None or self.vectorizer is None or self.label_encoder is None:
            raise ValueError("Model file missing required components")
        logger.info("Loaded ML model from %s", path)

    def load_model(self, path: str) -> None:
        """Public loader that sets model_path and loads the model."""
        self.model_path = Path(path)
        self._load_model_file(str(self.model_path))

    # ---------------------- Analysis / Prediction ----------------------
    def analyze(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """Analyze a file path or code string and return discovered vulnerabilities."""
        vulnerabilities: List[Vulnerability] = []
        context = context or {}

        # Read code content if target is a file path
        code_content = None
        file_path: Optional[str] = None
        try:
            p = Path(target)
            if p.is_file():
                code_content = p.read_text(encoding="utf-8", errors="ignore")
                file_path = str(p)
            else:
                code_content = target
        except (OSError, ValueError):
            # Not a valid path — treat target as raw content
            code_content = target

        if not code_content:
            return vulnerabilities

        # If sklearn model available, run ML pipeline
        if (
            HAS_SKLEARN
            and self.model is not None
            and self.vectorizer is not None
            and self.label_encoder is not None
        ):
            vulnerabilities.extend(self._ml_analyze(code_content, file_path))
        else:
            vulnerabilities.extend(self._pattern_analyze(code_content, file_path))

        return vulnerabilities

    def _ml_analyze(
        self, code_content: str, file_path: Optional[str]
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        try:
            lines = code_content.splitlines()
            chunk_size = 5
            for i in range(0, len(lines), chunk_size):
                chunk = " ".join(lines[i : min(i + chunk_size, len(lines))])
                if len(chunk.strip()) < 10:
                    continue

                X = self.vectorizer.transform([chunk])
                probs = self.model.predict_proba(X)[0]
                pred = int(np.argmax(probs))
                max_prob = float(probs[pred])

                if max_prob < self.confidence_threshold:
                    continue

                label_str = str(self.label_encoder.inverse_transform([pred])[0])
                try:
                    vuln_type = VulnerabilityType(label_str)
                except Exception:
                    # Unknown label produced by model; fallback to logic error type
                    vuln_type = VulnerabilityType.LOGIC_ERROR

                severity = self._predict_severity(label_str, max_prob)

                vuln = Vulnerability(
                    title=f"ML-detected {vuln_type.value.replace('_', ' ').title()}",
                    description=f"ML-detected pattern with confidence {max_prob:.2%}",
                    vulnerability_type=vuln_type,
                    severity=severity,
                    file_path=file_path,
                    line_number=i + 1,
                    code_snippet=chunk[:200],
                    remediation_status=RemediationStatus.OPEN,
                )
                vulnerabilities.append(vuln)
        except Exception as exc:  # pragma: no cover - runtime ML errors
            logger.exception("ML analysis failed: %s", exc)
        return vulnerabilities

    # ---------------------- Pattern fallback ----------------------
    def _pattern_analyze(
        self, code_content: str, file_path: Optional[str]
    ) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        for line_num, line in enumerate(code_content.splitlines(), 1):
            lower = line.lower()
            for vuln_type, patterns in self.TRAINING_PATTERNS.items():
                for pat in patterns:
                    if pat.lower() in lower:
                        severity = self._predict_severity(vuln_type.value, 0.7)
                        vuln = Vulnerability(
                            title=f"Potential {vuln_type.value.replace('_', ' ').title()}",
                            description=f"Pattern match: {pat}",
                            vulnerability_type=vuln_type,
                            severity=severity,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip()[:200],
                            remediation_status=RemediationStatus.OPEN,
                        )
                        vulnerabilities.append(vuln)
                        break
        return vulnerabilities

    # ---------------------- Severity prediction ----------------------
    def _create_severity_predictor(self) -> Dict[str, float]:
        return {
            "injection": 0.95,
            "cross_site_scripting": 0.80,
            "broken_authentication": 0.85,
            "sensitive_data_exposure": 0.80,
            "broken_access_control": 0.85,
            "security_misconfiguration": 0.60,
            "insecure_deserialization": 0.75,
            "using_components_with_known_vulns": 0.70,
            "insufficient_logging_monitoring": 0.50,
            "logic_error": 0.40,
        }

    def _predict_severity(
        self, vuln_type: str, confidence: float
    ) -> VulnerabilitySeverity:
        predictor = self.severity_predictor or {}
        base = predictor.get(vuln_type, 0.5)
        risk_score = base * confidence
        if risk_score >= 0.85:
            return VulnerabilitySeverity.CRITICAL
        if risk_score >= 0.70:
            return VulnerabilitySeverity.HIGH
        if risk_score >= 0.50:
            return VulnerabilitySeverity.MEDIUM
        if risk_score >= 0.30:
            return VulnerabilitySeverity.LOW
        return VulnerabilitySeverity.INFO
