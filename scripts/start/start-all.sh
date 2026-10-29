#!/bin/bash

echo "======================================================="
echo "  Starting SECURITY GUARD Services (Native Linux)      "
echo "======================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Start Detection Engine in background
cd "$ROOT_DIR/detection-engine"
if [ -d "venv" ]; then
    source venv/bin/activate
fi
uvicorn main:app --host 0.0.0.0 --port 5000 --reload &
ENGINE_PID=$!
echo "Detection Engine started with PID: $ENGINE_PID"

# Start Web App in background
cd "$ROOT_DIR/web-app"
npm run dev &
WEB_PID=$!
echo "Web Application started with PID: $WEB_PID"

# Start Dashboard in background
cd "$ROOT_DIR/dashboard"
npm run dev &
DASH_PID=$!
echo "Dashboard started with PID: $DASH_PID"

echo "======================================================="
echo "Services running in background:"
echo "- Web App:          http://localhost:3000"
echo "- Detection Engine: http://localhost:5000"
echo "- Dashboard:        http://localhost:5173"
echo "To stop them, run: ./scripts/stop/stop-all.sh"
echo "======================================================="

# Save PIDs
echo "$ENGINE_PID" > /tmp/sg_engine.pid
echo "$WEB_PID" > /tmp/sg_web.pid
echo "$DASH_PID" > /tmp/sg_dash.pid
