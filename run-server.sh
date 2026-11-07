#!/usr/bin/env bash
# Run the Huma backend server (frontend/registry.mjs) locally.
#
#   ./run-server.sh             run with Node on http://127.0.0.1:4318
#   ./run-server.sh --docker    build and run the production container instead (same as hosting)
#   PORT=8080 ./run-server.sh   use another port
#
# Settings come from .env.local when it exists (copy .env.example to start one). Without R2 keys, pages are stored
# locally in frontend/data. Without World ID keys, sharing is allowed (HUMA_WORLD_OPTIONAL=true) for local testing.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-4318}"
ENV_FILE=".env.local"

if [[ "${1:-}" == "--docker" ]]; then
  command -v docker >/dev/null || { echo "Docker is not installed or not on PATH." >&2; exit 1; }
  BUNDLE="$(mktemp -d)/host"
  echo "Packaging the host bundle into $BUNDLE ..."
  node backend/scripts/package-publication.mjs "$BUNDLE" >/dev/null
  echo "Building the image ..."
  docker build -q -t huma-host:local "$BUNDLE" >/dev/null
  docker rm -f huma-local >/dev/null 2>&1 || true
  ENV_ARGS=()
  [[ -f "$ENV_FILE" ]] && ENV_ARGS=(--env-file "$ENV_FILE")
  # The image defaults to R2 storage and requires World ID; fall back to local/optional unless .env.local sets them.
  grep -q '^HUMA_STORAGE_BACKEND=' "$ENV_FILE" 2>/dev/null || ENV_ARGS+=(-e HUMA_STORAGE_BACKEND=local)
  grep -q '^HUMA_WORLD_APP_ID=.' "$ENV_FILE" 2>/dev/null || ENV_ARGS+=(-e HUMA_WORLD_OPTIONAL=true)
  echo "Huma server: http://127.0.0.1:$PORT  (Ctrl+C to stop)"
  exec docker run --rm --name huma-local -p "$PORT:4318" "${ENV_ARGS[@]}" \
    -v huma-local-data:/app/frontend/data huma-host:local
fi

command -v node >/dev/null || { echo "Node.js is not installed (Node 22+ needed)." >&2; exit 1; }

# Install the server's packages when they are missing or incomplete.
if ! (cd frontend && npm ls --depth=0 >/dev/null 2>&1); then
  echo "Installing frontend packages ..."
  npm --prefix frontend ci --no-audit --no-fund
fi

# The writer and verifier pages need the built assets in frontend/dist.
if [[ ! -f frontend/dist/write/write.js ]]; then
  echo "Warning: frontend/dist is not built; /write and /verify won't work fully. Run: make build-frontend" >&2
fi

# Storage defaults to local and World ID is optional outside production, so .env.local alone decides those here.
export HUMA_REGISTRY_PORT="$PORT"

cd frontend
echo "Huma server: http://127.0.0.1:$PORT  (Ctrl+C to stop)"
if [[ -f "../$ENV_FILE" ]]; then
  exec node --env-file="../$ENV_FILE" registry.mjs
else
  exec node registry.mjs
fi
