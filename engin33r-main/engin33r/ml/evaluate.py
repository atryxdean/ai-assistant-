"""Evaluate a saved ML model against a dataset and produce metrics.

Usage:
  python -m engin33r.ml.evaluate --model models/engin33r_model.pkl --data data/ml_dataset.csv

Outputs a JSON metrics file next to the model: <model>.evaluation.json
"""

from pathlib import Path
import argparse
import json
import logging

import joblib
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

logger = logging.getLogger(__name__)


def load_model(path: str):
    model_data = joblib.load(path)
    model = model_data.get("model")
    vectorizer = model_data.get("vectorizer")
    label_encoder = model_data.get("label_encoder")
    if model is None or vectorizer is None or label_encoder is None:
        raise ValueError(
            "Model file is missing required components (model/vectorizer/label_encoder)"
        )
    return model, vectorizer, label_encoder


def load_dataset(path: str):
    df = pd.read_csv(path)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain `text` and `label` columns")
    return df["text"].astype(str).tolist(), df["label"].astype(str).tolist()


def false_positive_rate_per_class(y_true, y_pred, labels):
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fpr = {}
    # For each class: FP / (FP + TN)
    for i, label in enumerate(labels):
        tp = cm[i, i]
        fp = cm[:, i].sum() - tp
        fn = cm[i, :].sum() - tp
        tn = cm.sum() - (tp + fp + fn)
        denom = fp + tn
        fpr[label] = float(fp / denom) if denom > 0 else 0.0
    return fpr


def evaluate_model(model_path: str, data_path: str):
    model, vectorizer, label_encoder = load_model(model_path)
    texts, labels = load_dataset(data_path)

    X = vectorizer.transform(texts)
    y_true_enc = label_encoder.transform(labels)
    y_pred_enc = model.predict(X)

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true_enc, y_pred_enc, average=None, zero_division=0
    )
    labels_decoded = label_encoder.inverse_transform(range(len(label_encoder.classes_)))

    # Map metrics per-class
    per_class = {}
    for i, lab in enumerate(label_encoder.classes_):
        per_class[lab] = {
            "precision": float(precision[i]) if i < len(precision) else 0.0,
            "recall": float(recall[i]) if i < len(recall) else 0.0,
            "f1": float(f1[i]) if i < len(f1) else 0.0,
            "support": int(support[i]) if i < len(support) else 0,
        }

    # Micro/macro metrics
    p_micro, r_micro, f1_micro, _ = precision_recall_fscore_support(
        y_true_enc, y_pred_enc, average="micro", zero_division=0
    )
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true_enc, y_pred_enc, average="macro", zero_division=0
    )

    fpr = false_positive_rate_per_class(
        y_true_enc, y_pred_enc, labels=list(range(len(label_encoder.classes_)))
    )
    # Map numeric labels back to class strings
    fpr_named = {
        label_encoder.inverse_transform([int(k)])[0]: float(v) for k, v in fpr.items()
    }

    metrics = {
        "per_class": per_class,
        "micro": {
            "precision": float(p_micro),
            "recall": float(r_micro),
            "f1": float(f1_micro),
        },
        "macro": {
            "precision": float(p_macro),
            "recall": float(r_macro),
            "f1": float(f1_macro),
        },
        "false_positive_rate_per_class": fpr_named,
        "n_samples": len(labels),
    }

    out_path = Path(model_path).with_suffix(
        Path(model_path).suffix + ".evaluation.json"
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)

    logger.info("Evaluation written to %s", out_path)
    return metrics


def _cli():
    p = argparse.ArgumentParser(prog="engin33r-evaluate")
    p.add_argument("--model", required=True, help="Path to joblib model file")
    p.add_argument("--data", required=True, help="Path to CSV dataset with text,label")
    args = p.parse_args()

    evaluate_model(args.model, args.data)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _cli()
