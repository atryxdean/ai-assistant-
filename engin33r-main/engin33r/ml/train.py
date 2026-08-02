"""Train and save a baseline ML model for engin33r.

Usage:
  python -m engin33r.ml.train --data data/ml_dataset.csv --out models/engin33r_model.pkl

This module exposes a train_model function so it can be imported by tests.
"""

from pathlib import Path
import argparse
import json
import logging

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support
from collections import Counter

logger = logging.getLogger(__name__)


def load_data(path: str):
    df = pd.read_csv(path)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain `text` and `label` columns")
    texts = df["text"].astype(str).tolist()
    labels = df["label"].astype(str).tolist()
    return texts, labels


def train_model(
    data_path: str, out_path: str, test_size: float = 0.2, random_state: int = 42
):
    texts, labels = load_data(data_path)

    label_counts = Counter(labels)
    stratify = (
        labels if len(label_counts) > 1 and min(label_counts.values()) >= 2 else None
    )

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=random_state, stratify=stratify
    )

    vectorizer = TfidfVectorizer(max_features=100, lowercase=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    label_encoder = LabelEncoder()
    label_encoder.fit(labels)
    y_train_enc = label_encoder.transform(y_train)
    y_test_enc = label_encoder.transform(y_test)

    model = RandomForestClassifier(n_estimators=10, random_state=random_state)
    model.fit(X_train_vec, y_train_enc)

    preds = model.predict(X_test_vec)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test_enc, preds, average="weighted", zero_division=0
    )

    metrics = {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "n_test": len(y_test),
    }

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {"model": model, "vectorizer": vectorizer, "label_encoder": label_encoder},
        str(out_path),
    )

    metrics_path = str(out_path) + ".metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)

    logger.info("Trained model saved to %s", out_path)
    logger.info("Metrics written to %s", metrics_path)

    return str(out_path), metrics


def _cli():
    p = argparse.ArgumentParser(prog="engin33r-train")
    p.add_argument("--data", required=True, help="Path to CSV dataset with text,label")
    p.add_argument(
        "--out", default="models/engin33r_model.pkl", help="Output model path"
    )
    p.add_argument("--test-size", type=float, default=0.2)
    args = p.parse_args()

    train_model(args.data, args.out, test_size=args.test_size)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _cli()
