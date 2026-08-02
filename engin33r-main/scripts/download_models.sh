#!/usr/bin/env bash
set -euo pipefail

# Simple downloader for model artifacts. Provide MODEL_URL and OUT_DIR.
# Example:
# MODEL_URL="https://example.com/engin33r_model.pkl" OUT_DIR=models ./scripts/download_models.sh

MODEL_URL="${MODEL_URL:-}"
OUT_DIR="${OUT_DIR:-models}"
CHECKSUMS="${CHECKSUMS:-${OUT_DIR}/checksums.txt}"

if [ -z "${MODEL_URL}" ]; then
  echo "ERROR: MODEL_URL environment variable must be set to the model artifact URL"
  exit 2
fi

mkdir -p "${OUT_DIR}"
MODEL_NAME=$(basename "${MODEL_URL}")
OUT_PATH="${OUT_DIR}/${MODEL_NAME}"

echo "Downloading ${MODEL_URL} -> ${OUT_PATH}"
curl -fSL "${MODEL_URL}" -o "${OUT_PATH}"

if [ -f "${CHECKSUMS}" ]; then
  echo "Verifying checksums using ${CHECKSUMS}"
  pushd "${OUT_DIR}" >/dev/null
  sha256sum -c "$(basename "${CHECKSUMS}")"
  popd >/dev/null
else
  echo "No checksums file found at ${CHECKSUMS}; skipping verification. Consider adding ${OUT_DIR}/checksums.txt"
fi

echo "Download complete: ${OUT_PATH}"
