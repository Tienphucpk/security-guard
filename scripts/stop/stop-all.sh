#!/bin/bash

echo "======================================================="
echo "  Stopping SECURITY GUARD Services                     "
echo "======================================================="

# Stop docker if running
if command -v docker &> /dev/null; then
    docker compose down 2>/dev/null || true
fi

# Stop recorded PIDs
for pid_file in /tmp/sg_engine.pid /tmp/sg_web.pid /tmp/sg_dash.pid; do
    if [ -f "$pid_file" ]; then
        PID=$(cat "$pid_file")
        echo "Killing process $PID..."
        kill -9 "$PID" 2>/dev/null || true
        rm -f "$pid_file"
    fi
done

echo "Done! Services stopped."
