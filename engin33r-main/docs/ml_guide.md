# engin33r - ML Configuration Guide

## Machine Learning Components

engin33r includes advanced machine learning capabilities for enhanced vulnerability detection.

### 1. ML Vulnerability Analyzer

**Location**: `engin33r.ml.MLVulnerabilityAnalyzer`

Uses pattern recognition to identify vulnerabilities.

```python
from engin33r.ml import MLVulnerabilityAnalyzer
from engin33r.core.engine import VulnerabilityEngine

engine = VulnerabilityEngine()
engine.register_analyzer(MLVulnerabilityAnalyzer())

vulnerabilities = engine.scan("code.py")
```

**Features**:
- TF-IDF vectorization of code snippets
- Random Forest classification
- Confidence-based vulnerability prediction
- Severity scoring based on vulnerability type

### 2. Anomaly Detector

**Location**: `engin33r.ml.anomaly.AnomalyDetector`

Detects code patterns that may hide vulnerabilities.

```python
from engin33r.ml.anomaly import AnomalyDetector

engine = VulnerabilityEngine()
engine.register_analyzer(AnomalyDetector())
```

**Detects**:
- Excessive line lengths
- Low documentation ratio
- Dense code structures
- Unusual variable naming patterns

### 3. Code Complexity Analyzer

**Location**: `engin33r.ml.anomaly.CodeComplexityAnalyzer`

Analyzes cyclomatic complexity which often correlates with vulnerabilities.

```python
from engin33r.ml.anomaly import CodeComplexityAnalyzer

engine = VulnerabilityEngine()
engine.register_analyzer(CodeComplexityAnalyzer())
```

## Installation with ML Support

```bash
pip install engin33r[ml]
```

Required ML dependencies:
- scikit-learn >= 0.24
- numpy >= 1.19
- joblib >= 1.0
- pandas >= 1.1

## Model Training and Saving

### Train Custom Model (reproducible)

A minimal reproducible training pipeline is included in `engin33r/ml/train.py`. The repository includes a tiny example dataset at `data/ml_dataset.csv` for local experiments and CI smoke-tests.

Commands:

```bash
# Install ML extras
pip install -e ".[ml]"

# Train a baseline model using the example dataset
python -m engin33r.ml.train --data data/ml_dataset.csv --out models/engin33r_model.pkl

# Inspect produced evaluation metrics
cat models/engin33r_model.pkl.metrics.json
```

If you maintain a large model artifact externally, use the downloader script to fetch it to `models/`:

```bash
# Provide MODEL_URL environment variable pointing to the model artifact
MODEL_URL="https://internal.example.com/engin33r_model.pkl" OUT_DIR=models ./scripts/download_models.sh
```

### Load Existing Model

```python
analyzer = MLVulnerabilityAnalyzer(model_path='models/engin33r_model.pkl')
```

## Retraining and evaluation

The repository includes `engin33r/ml/evaluate.py` which will load a saved model and dataset and write per-class and aggregate metrics (precision, recall, f1, false positive rate) to a JSON file next to the model.

```bash
python -m engin33r.ml.evaluate --model models/engin33r_model.pkl --data data/ml_dataset.csv
```

## Confidence Thresholds

Control ML detection sensitivity:

```python
# Only report high-confidence detections
for vuln in vulnerabilities:
    if vuln.cvss_score and vuln.cvss_score > 0.7:
        print(f"High confidence: {vuln.title}")
```

## Performance Tuning

### Reduce False Positives
```python
from engin33r.ml import MLVulnerabilityAnalyzer

analyzer = MLVulnerabilityAnalyzer()
# Filter by confidence
vulnerabilities = [
    v for v in vulnerabilities 
    if v.get_risk_score() > 0.75
]
```

### Improve Detection Coverage
```python
# Register multiple complementary analyzers
engine.register_analyzer(StaticAnalyzer())
engine.register_analyzer(MLVulnerabilityAnalyzer())
engine.register_analyzer(AnomalyDetector())
engine.register_analyzer(CodeComplexityAnalyzer())
engine.register_analyzer(DependencyAnalyzer())
```

## ML Model Architecture

### Feature Extraction
- TF-IDF vectorization of code patterns
- Vocabulary size: 100 features
- Lowercase normalization

### Classification
- Algorithm: Random Forest
- Estimators: 10 trees
- Random state: 42

### Severity Prediction
- Confidence-weighted CVSS scoring
- Vulnerability-type mapping
- Risk score calculation: `confidence * vulnerability_weight`

## Limitations and Notes

1. **No internet access required** - All models are self-contained
2. **Lightweight** - Models load quickly for small baselines
3. **Deterministic** - Same code with same random seed yields same results
4. **Extensible** - Easy to add custom patterns and training data
5. **Works offline** - No cloud API calls (unless you configure external downloaders)

## Troubleshooting

### scikit-learn not found
```bash
pip install scikit-learn
```

### Low detection rates
- Check model confidence thresholds
- Ensure code has sufficient content
- Verify analyzer is registered

### High false positives
- Increase confidence threshold
- Use in combination with static analyzer
- Review and filter results manually
