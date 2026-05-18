#!/bin/bash

# Pick python: 'python' on Windows (Git Bash), 'python3' on Linux/macOS
if command -v python3 >/dev/null 2>&1; then
    PY=python3
else
    PY=python
fi

# Create venv if missing
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    $PY -m venv venv
fi

# Activate venv (Linux/macOS use bin/, Windows Git Bash uses Scripts/)
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    echo "Could not find venv activate script."
    exit 1
fi

echo "Installing dependencies..."
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt

echo "Downloading dataset..."
python download_dataset.py

echo "Starting training..."
python train.py
