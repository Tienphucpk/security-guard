#!/bin/bash
set -e

echo "======================================================="
echo "  SECURITY GUARD - Setting Up Development Environment  "
echo "======================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "[1/3] Installing Web Application dependencies..."
cd "$ROOT_DIR/web-app"
npm install

echo "[2/3] Setting up Detection Engine Python virtualenv..."
cd "$ROOT_DIR/detection-engine"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

echo "[3/3] Installing Dashboard dependencies..."
cd "$ROOT_DIR/dashboard"
npm install

echo "======================================================="
echo "  Setup completed successfully!                        "
echo "======================================================="
