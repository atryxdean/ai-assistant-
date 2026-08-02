"""ML-based analyzer for anomaly detection in code"""

import numpy as np
from typing import List, Dict, Any, Optional
import json
import logging
from pathlib import Path

from engin33r.analyzers.base import VulnerabilityAnalyzer
from engin33r.core.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
    RemediationStatus,
)

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class AnomalyDetector(VulnerabilityAnalyzer):
    """Detects code anomalies that may indicate vulnerabilities"""

    # Code metrics that can indicate vulnerabilities
    RISK_INDICATORS = {
        "function_length": (50, 200),  # Lines, high = suspicious
        "cyclomatic_complexity": (5, 20),  # High complexity = risk
        "comment_ratio": (0.05, 0.5),  # Low comments = risk
        "variable_name_length": (1, 50),  # Very short/long = suspicious
        "nesting_depth": (3, 10),  # Deep nesting = risk
    }

    def __init__(self):
        super().__init__(
            name="AnomalyDetector",
            description="Detects code anomalies and unusual patterns that may indicate vulnerabilities",
        )
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.anomaly_model = None
        if HAS_SKLEARN:
            self.anomaly_model = IsolationForest(contamination=0.1, random_state=42)

    def analyze(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """
        Analyze code for anomalies

        Args:
            target: File path or code string
            context: Additional context

        Returns:
            List of detected anomalies as vulnerabilities
        """
        vulnerabilities = []
        context = context or {}

        # Read code
        code_content = None
        file_path = None

        try:
            path = Path(target)
            if path.is_file():
                code_content = path.read_text()
                file_path = str(path)
        except Exception:
            code_content = target

        if not code_content:
            return vulnerabilities

        # Extract metrics
        metrics = self._extract_metrics(code_content)

        # Detect anomalies
        anomalies = self._detect_anomalies(metrics)

        # Convert anomalies to vulnerabilities
        for anomaly_info in anomalies:
            vuln = Vulnerability(
                title=f"Code Anomaly Detected: {anomaly_info['type']}",
                description=anomaly_info["description"],
                vulnerability_type=VulnerabilityType.LOGIC_ERROR,
                severity=VulnerabilitySeverity.MEDIUM,
                file_path=file_path,
                line_number=anomaly_info.get("line"),
                code_snippet=anomaly_info.get("snippet", ""),
                remediation_status=RemediationStatus.OPEN,
                remediation_guidance="Review the code section for potential issues",
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _extract_metrics(self, code: str) -> Dict[str, Any]:
        """Extract code metrics"""
        lines = code.split("\n")
        metrics = {
            "total_lines": len(lines),
            "blank_lines": sum(1 for line in lines if not line.strip()),
            "comment_lines": sum(1 for line in lines if line.strip().startswith("#")),
            "avg_line_length": np.mean([len(line) for line in lines]) if lines else 0,
            "max_line_length": max([len(line) for line in lines]) if lines else 0,
        }
        return metrics

    def _detect_anomalies(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in code metrics"""
        anomalies = []

        # Check for unusually long lines
        if metrics["max_line_length"] > 150:
            anomalies.append(
                {
                    "type": "Excessive Line Length",
                    "description": f"Line exceeds 150 characters (found {metrics['max_line_length']}). May indicate hidden complexity.",
                    "severity": VulnerabilitySeverity.LOW,
                }
            )

        # Check for low comment ratio
        total_code_lines = metrics["total_lines"] - metrics["blank_lines"]
        if total_code_lines > 0:
            comment_ratio = metrics["comment_lines"] / total_code_lines
            if comment_ratio < 0.05 and total_code_lines > 20:
                anomalies.append(
                    {
                        "type": "Low Documentation",
                        "description": f"Very few comments ({comment_ratio:.1%}). Under-documented code may contain hidden vulnerabilities.",
                        "severity": VulnerabilitySeverity.LOW,
                    }
                )

        # Check for high density of code
        if metrics["avg_line_length"] > 80 and total_code_lines > 50:
            anomalies.append(
                {
                    "type": "Dense Code Structure",
                    "description": f"Average line length is {metrics['avg_line_length']:.0f} chars. Dense code is harder to audit.",
                    "severity": VulnerabilitySeverity.LOW,
                }
            )

        return anomalies


class CodeComplexityAnalyzer(VulnerabilityAnalyzer):
    """Analyzes code complexity which can hide vulnerabilities"""

    def __init__(self):
        super().__init__(
            name="CodeComplexityAnalyzer",
            description="Analyzes code complexity metrics that may indicate vulnerabilities",
        )

    def analyze(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """
        Analyze code complexity

        Args:
            target: File path or code string
            context: Additional context

        Returns:
            List of complexity-related concerns
        """
        vulnerabilities = []
        context = context or {}

        # Read code
        code_content = None
        file_path = None

        try:
            path = Path(target)
            if path.is_file():
                code_content = path.read_text()
                file_path = str(path)
        except Exception:
            code_content = target

        if not code_content:
            return vulnerabilities

        # Calculate complexity metrics
        complexity_score = self._calculate_complexity(code_content)

        if complexity_score > 15:
            vuln = Vulnerability(
                title="High Code Complexity Detected",
                description=f"Cyclomatic complexity score of {complexity_score} indicates high complexity. Complex code is harder to audit for vulnerabilities.",
                vulnerability_type=VulnerabilityType.LOGIC_ERROR,
                severity=VulnerabilitySeverity.MEDIUM,
                file_path=file_path,
                remediation_guidance="Refactor complex functions into smaller, testable units. Use code review to identify logic errors.",
                remediation_status=RemediationStatus.OPEN,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _calculate_complexity(self, code: str) -> int:
        """Simple cyclomatic complexity estimation"""
        complexity = 1
        keywords = ["if", "elif", "else", "for", "while", "except", "and", "or", "case"]

        for keyword in keywords:
            complexity += code.count(f" {keyword} ")
            complexity += code.count(f" {keyword}(")

        return max(1, complexity)
