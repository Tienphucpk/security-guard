#!/bin/bash
set -e

echo "======================================================="
echo "  Running SECURITY GUARD Automated Tests               "
echo "======================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "[1/2] Testing Web Application..."
cd "$ROOT_DIR/web-app"
npm test

echo "[2/2] Testing Detection Engine API..."
cd "$ROOT_DIR/detection-engine"
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python3 -m unittest discover tests

echo "======================================================="
echo "  All tests PASSED successfully!                       "
echo "======================================================="
