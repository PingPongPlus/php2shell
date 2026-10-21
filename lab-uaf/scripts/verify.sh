#!/bin/bash
# PHP2Shell Lab Verification
# Run from the lab/ directory after `docker compose up -d`.

set -e
CONTAINER="${1:-php2shell-lab}"
PORT="${2:-19268}"

echo "=== PHP2Shell Lab Verification ==="

echo -e "\n[1/3] Container status"
STATUS=$(docker inspect --format '{{.State.Status}}' "$CONTAINER" 2>/dev/null) || {
    echo "FAIL: container '$CONTAINER' not found. Run: docker compose up -d"
    exit 1
}
echo "  Status: $STATUS"

echo -e "\n[2/3] PHP runtime info"
curl -s "http://127.0.0.1:${PORT}/index.php" | sed 's/^/  /'

echo -e "\n[3/3] upload_progress status"
ENABLED=$(curl -s "http://127.0.0.1:${PORT}/index.php" | grep 'upload_progress.enabled')
if echo "$ENABLED" | grep -q "= 1"; then
    echo "  VULNERABLE: session.upload_progress.enabled = On"
    echo "  The rfc1867 callback will fire on multipart uploads."
else
    echo "  MITIGATED: session.upload_progress.enabled = Off"
    echo "  The rfc1867 callback is disabled."
fi

echo -e "\n=== Commands ==="
echo "Trigger:    python3 scripts/trigger.py --monitor --port $PORT"
echo "Mitigate:   docker compose -f docker-compose.yml -f docker-compose.mitigated.yml up -d"
echo "Revert:     docker compose up -d"
