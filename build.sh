#!/usr/bin/env bash
# Builds dist/namawin-app.zip for Elastic Beanstalk.
# Files sit at the ROOT of the zip (EB requires this), not inside a folder.
set -euo pipefail

cd "$(dirname "$0")"
OUT="dist/namawin-app.zip"

mkdir -p dist
rm -f "$OUT"

zip -r -q "$OUT" \
  application.py app Procfile requirements.txt .platform \
  -x '*/__pycache__/*' '*.pyc' '*.sqlite' '*.sqlite3' '*.db' '.env' '*/.env' \
     '*/.DS_Store' '.DS_Store' 'local_uploads/*' 'tests/*' 'dist/*' '.git/*' '.venv/*' 'venv/*'

echo "Built $OUT"
unzip -l "$OUT"
