#!/bin/bash
set -e

# Timestamp for this run (e.g. 20260518-160429) — used for log lines and artifacts
RUN_TS=$(date +%Y%m%d-%H%M%S)
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Pick python: 'python' on Windows (Git Bash), 'python3' on Linux/macOS
if command -v python3 >/dev/null 2>&1; then
    PY=python3
else
    PY=python
fi

resolve_path() {
    "$PY" -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$1"
}

# Create venv if missing
if [ ! -d "venv" ]; then
    log "Creating virtual environment..."
    $PY -m venv venv
fi

# Activate venv (Linux/macOS use bin/, Windows Git Bash uses Scripts/)
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    log "Could not find venv activate script."
    exit 1
fi

log "Run timestamp: $RUN_TS"

log "Installing dependencies..."
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt

log "Downloading dataset..."
python download_dataset.py

log "Adding synthetic_data/ CSVs to csv_files.txt..."
touch csv_files.txt
# Ensure file ends with a newline before appending (avoid joining onto the last line)
if [ -s csv_files.txt ] && [ "$(tail -c 1 csv_files.txt)" != "$(printf '\n')" ]; then
    echo "" >> csv_files.txt
fi
added=0
while IFS= read -r -d '' csv; do
    abspath="$(resolve_path "$csv")"
    if ! grep -Fxq "$abspath" csv_files.txt; then
        echo "$abspath" >> csv_files.txt
        added=$((added + 1))
    fi
done < <(find synthetic_data -type f -name "*.csv" -print0 2>/dev/null)
log "Added $added new CSV path(s) from synthetic_data/"

log "Starting training..."
python train.py --save "model.pt"
cp model.pt "model_${RUN_TS}.pt"
log "Saved checkpoint: model.pt  (also archived as model_${RUN_TS}.pt)"

log "Exporting ONNX model for demo..."
python export_onnx.py --model "model.pt" --out "model.onnx"
cp model.onnx "model_${RUN_TS}.onnx"
log "Wrote model.onnx  (also archived as model_${RUN_TS}.onnx)"

log "Done."
