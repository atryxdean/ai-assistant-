import os
import json
import tempfile
from pathlib import Path

import pytest

from engin33r import ml

pytest.importorskip("sklearn")


def test_train_and_load_model(tmp_path):
    # Paths
    data_path = Path("data/ml_dataset.csv")
    assert data_path.exists(), "data/ml_dataset.csv must exist for this test"

    out_model = tmp_path / "test_model.pkl"

    # Train model
    model_path_str, metrics = ml.train.train_model(str(data_path), str(out_model))
    assert Path(model_path_str).exists()
    assert "precision" in metrics

    # Load with analyzer
    analyzer = ml.MLVulnerabilityAnalyzer(model_path=str(out_model))
    # Analyzer should have vectorizer and model if sklearn available
    if ml.HAS_SKLEARN:
        assert analyzer.model is not None
        assert analyzer.vectorizer is not None

    # Run a quick analyze on a sample snippet
    sample = "SELECT * FROM users WHERE id='" + "1'"
    vulns = analyzer.analyze(sample)
    # Should return a list (can be empty depending on classifier thresholds), but must not raise
    assert isinstance(vulns, list)


def test_analyze_raw_code_string_detects_pattern():
    analyzer = ml.MLVulnerabilityAnalyzer(
        confidence_threshold=0.0, train_if_missing=False
    )
    analyzer.model = None
    analyzer.vectorizer = None
    analyzer.label_encoder = None

    vulns = analyzer.analyze("password = 'supersecret'\n")

    assert vulns
    assert vulns[0].file_path is None
