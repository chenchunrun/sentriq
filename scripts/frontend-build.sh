#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FRONTEND_DIR="$PROJECT_ROOT/services/web_dashboard"

IMAGE="${FRONTEND_NODE_IMAGE:-node:22.16.0-bookworm}"

echo "=========================================="
echo "  Frontend Build Container"
echo "=========================================="
echo "Image: $IMAGE"
echo "Frontend: $FRONTEND_DIR"
echo ""

exec docker run --rm \
  -v "$FRONTEND_DIR:/app" \
  -w /app \
  "$IMAGE" \
  bash -lc "npm ci && npm run build"
