#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FRONTEND_DIR="$PROJECT_ROOT/services/web_dashboard"

IMAGE="${FRONTEND_NODE_IMAGE:-node:22.16.0-bookworm}"
HOST_PORT="${FRONTEND_DEV_PORT:-3000}"
CONTAINER_PORT=3000

echo "=========================================="
echo "  Frontend Dev Container"
echo "=========================================="
echo "Image: $IMAGE"
echo "Frontend: $FRONTEND_DIR"
echo "URL: http://localhost:$HOST_PORT"
echo ""

exec docker run --rm \
  -p "$HOST_PORT:$CONTAINER_PORT" \
  -v "$FRONTEND_DIR:/app" \
  -w /app \
  "$IMAGE" \
  bash -lc "npm run dev -- --host 0.0.0.0 --port $CONTAINER_PORT"
