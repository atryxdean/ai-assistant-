# Models for engin33r

This directory holds ML model artifacts used by engin33r's ML analyzers. Models saved here should follow the joblib format used by engin33r.ml.MLVulnerabilityAnalyzer: a dictionary with keys `model`, `vectorizer`, and `label_encoder`.

Files
- `engin33r_model.pkl` - Primary RandomForest model + TfidfVectorizer + LabelEncoder (joblib dump). If the model is large, do not commit the binary; use the downloader script `scripts/download_models.sh` and publish the model to an internal HTTP server or artifact store.
- `checksums.txt` - SHA256 checksums for model artifacts. Use `sha256sum` to verify downloads.
- `MODEL_VERSION` - Simple text file with the model version string.

How to produce a local model (recommended for contributors)
1. Ensure ML extras are installed:

```bash
pip install -e ".[ml]"
```

2. Train on the included small dataset and produce a model:

```bash
python -m engin33r.ml.train --data data/ml_dataset.csv --out models/engin33r_model.pkl
```

3. Verify metrics were produced next to the model:

```bash
cat models/engin33r_model.pkl.metrics.json
```

If you publish models externally, add an entry to `models/checksums.txt` in the format:

```
<sha256sum>  <filename>
```
