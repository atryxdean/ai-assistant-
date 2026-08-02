import csv
from pathlib import Path
import tempfile

from engin33r.ml import dataset_generator as dg


def test_generate_small_csv(tmp_path):
    out = tmp_path / "gen.csv"
    out_path, records = dg.generate_corpus(size=25, seed=123, out=str(out), fmt="csv")
    assert out_path.exists()

    # Validate CSV structure
    with out.open("r", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        headers = next(reader)
        assert headers == ["text", "label"]
        rows = list(reader)
        assert len(rows) == 25
        # Check labels are among allowed set
        allowed = set(dg.TEXT_TEMPLATES.keys())
        for _, label in rows:
            assert label in allowed


def test_deterministic_with_seed(tmp_path):
    out1 = tmp_path / "a.csv"
    out2 = tmp_path / "b.csv"
    _, recs1 = dg.generate_corpus(size=50, seed=42, out=str(out1), fmt="csv")
    _, recs2 = dg.generate_corpus(size=50, seed=42, out=str(out2), fmt="csv")
    # Compare text,label pairs for deterministic equality
    pairs1 = [(r.text, r.label) for r in recs1]
    pairs2 = [(r.text, r.label) for r in recs2]
    assert pairs1 == pairs2
