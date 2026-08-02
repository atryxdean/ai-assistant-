#!/usr/bin/env python3
"""Dataset generator for engin33r ML pipeline.

This module generates synthetic, labeled examples suitable for training or
smoke-testing ML models in engin33r. It purposely avoids producing realistic
CVE identifiers or any sensitive/secret data. The output can be CSV (text,label)
for the training pipeline or full JSONL with metadata for other uses.

Usage (CSV):
    python -m engin33r.ml.dataset_generator --size 1000 --out data/generated_ml.csv --format csv --seed 42

Usage (JSONL):
    python -m engin33r.ml.dataset_generator --size 1000 --out data/generated_ml.jsonl --format jsonl --seed 42

Design notes:
- Deterministic when seed is provided.
- Produces `text` suitable for TF-IDF feature extraction (short code/evidence snippets).
- Labels map to engin33r.core.vulnerability.VulnerabilityType enum values.
- No real CVE IDs are emitted; synthetic IDs use a safe prefix.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Map generator categories to vulnerability label strings used by the ML pipeline
LABEL_MAP: Dict[str, str] = {
    "RCE": "injection",
    "UAF": "buffer_overflow",
    "HeapOverflow": "buffer_overflow",
    "RaceCondition": "race_condition",
    # Provide other direct mappings for convenience
    "XSS": "cross_site_scripting",
    "BrokenAuth": "broken_authentication",
    "SensitiveData": "sensitive_data_exposure",
    "BrokenAccess": "broken_access_control",
}

# Templates for generating short "text" examples matching label types.
TEXT_TEMPLATES: Dict[str, List[str]] = {
    "injection": [
        'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
        "query = 'SELECT * FROM products WHERE name = ' + name",
        "requests.get('http://' + host)",
    ],
    "cross_site_scripting": [
        "document.write(userInput);",
        "element.innerHTML = userProvidedHtml;",
        "eval(userSuppliedCode)",
    ],
    "broken_authentication": [
        "password = '123456'",
        "if password == 'admin': login()",
        "auth_token = 'hardcoded-token'",
    ],
    "sensitive_data_exposure": [
        "api_key = 'AKIA...'",
        "private_key = '-----BEGIN PRIVATE KEY-----'",
        "print(secret_token)",
    ],
    "broken_access_control": [
        "if user.id != current_user.id: return data",
        "allow_all_users()  # missing access control",
        "if not is_authorized(user): return data",
    ],
    "buffer_overflow": [
        "strcpy(dest, src)  # possible overflow",
        "buffer = 'A' * 1024",
        "memcpy(dest, src, len)",
    ],
    "race_condition": [
        "thread.start(); shared += 1;",
        "if (!locked) { write_shared(); }",
        "open('/tmp/file'); sleep(0.1); write()",
    ],
    "information_disclosure": [
        "print(debug_info)",
        "log.info(secret)",
    ],
    "logic_error": [
        "result = compute(value)  # TODO: validate inputs",
        "if x and not y: return True",
    ],
}

DEFAULT_PLATFORMS = ["Windows", "Linux", "Android", "Network"]
DEFAULT_SEVERITIES = ["Critical", "High", "Medium", "Low"]


@dataclass
class GeneratedRecord:
    id: str
    timestamp: str
    platform: str
    original_vuln_type: str
    label: str
    severity: str
    confidence: float
    text: str
    metadata: Dict[str, object]


def _safe_synthetic_id(rng: random.Random, prefix: str = "SYNTH-") -> str:
    # Produce a short synthetic identifier that should not collide with CVE IDs
    return f"{prefix}{rng.randint(100000, 999999)}"


def _choose_label_from_original(orig: str) -> str:
    return LABEL_MAP.get(orig, "logic_error")


def _generate_text_for_label(rng: random.Random, label: str) -> str:
    templates = TEXT_TEMPLATES.get(label)
    if templates:
        return rng.choice(templates)
    # Fallback: construct a short evidence string
    return f"evidence: suspected {label} pattern"


def generate_single_record(
    rng: Optional[random.Random] = None,
    original_type_choices: Optional[List[str]] = None,
) -> GeneratedRecord:
    rng = rng or random.Random()
    original_type_choices = original_type_choices or list(LABEL_MAP.keys())

    orig = rng.choice(original_type_choices)
    label = _choose_label_from_original(orig)
    text = _generate_text_for_label(rng, label)

    rec_id = _safe_synthetic_id(rng)
    ts = datetime.utcnow().isoformat() + "Z"
    platform = rng.choice(DEFAULT_PLATFORMS)
    severity = rng.choice(DEFAULT_SEVERITIES)
    confidence = round(rng.uniform(0.5, 0.99), 4)

    metadata = {
        "generated_id": rec_id,
        "platform": platform,
        "original_type": orig,
        "severity": severity,
        "confidence": confidence,
    }

    return GeneratedRecord(
        id=rec_id,
        timestamp=ts,
        platform=platform,
        original_vuln_type=orig,
        label=label,
        severity=severity,
        confidence=confidence,
        text=text,
        metadata=metadata,
    )


def write_csv(records: List[GeneratedRecord], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["text", "label"])
        for r in records:
            writer.writerow([r.text, r.label])


def write_jsonl(records: List[GeneratedRecord], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for r in records:
            obj = {
                "id": r.id,
                "timestamp": r.timestamp,
                "platform": r.platform,
                "original_vuln_type": r.original_vuln_type,
                "label": r.label,
                "severity": r.severity,
                "confidence": r.confidence,
                "text": r.text,
                "metadata": r.metadata,
            }
            fh.write(json.dumps(obj) + "\n")


def generate_corpus(
    size: int = 1000,
    seed: Optional[int] = None,
    out: str = "data/generated_ml.csv",
    fmt: str = "csv",
) -> Tuple[Path, List[GeneratedRecord]]:
    rng = random.Random(seed)
    records: List[GeneratedRecord] = [
        generate_single_record(rng=rng) for _ in range(size)
    ]
    out_path = Path(out)
    if fmt == "csv":
        write_csv(records, out_path)
    elif fmt == "jsonl":
        write_jsonl(records, out_path)
    else:
        raise ValueError("Unsupported format: " + fmt)
    return out_path, records


def _cli() -> None:
    p = argparse.ArgumentParser(prog="engin33r-dataset-generator")
    p.add_argument(
        "--size", type=int, default=1000, help="Number of examples to generate"
    )
    p.add_argument(
        "--seed", type=int, default=None, help="Random seed for deterministic output"
    )
    p.add_argument(
        "--out", type=str, default="data/generated_ml.csv", help="Output file path"
    )
    p.add_argument(
        "--format",
        type=str,
        default="csv",
        choices=["csv", "jsonl"],
        help="Output format",
    )
    args = p.parse_args()

    out_path, _ = generate_corpus(
        size=args.size, seed=args.seed, out=args.out, fmt=args.format
    )
    print(f"Generated {args.size} examples -> {out_path} (seed={args.seed})")


if __name__ == "__main__":
    _cli()
