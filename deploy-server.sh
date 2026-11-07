#!/usr/bin/env bash
# Deploy the Huma backend on the server (EC2) straight from this git checkout. Needs only git and Docker.
#
#   ./deploy-server.sh            pull, package, build and (re)start the server on 127.0.0.1:$HUMA_REGISTRY_PORT (default 4318)
#   ENV_FILE=/path/.env ./deploy-server.sh
#
# Settings come from .env in this folder (or ENV_FILE). No R2 keys? Put HUMA_STORAGE_BACKEND=local in it.
# No World ID keys? Put HUMA_WORLD_OPTIONAL=true in it, or every share answers 503.
# Put Caddy (or nginx) in front for the public site: reverse_proxy 127.0.0.1:<that port>.
set -euo pipefail
cd "$(dirname "$0")"
ENV_FILE="${ENV_FILE:-$PWD/.env}"
[[ -f "$ENV_FILE" ]] || { echo "Missing $ENV_FILE (copy .env.example and fill it in)." >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker is not installed: sudo apt install -y docker.io" >&2; exit 1; }

echo "==> Pulling the latest code"
git pull --ff-only

echo "==> Packaging the server bundle"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
# Node runs in a container, so the server needs no Node install. The script uses only Node's built-in modules.
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/repo:ro" -v "$OUT:/out" -w /repo \
  node:24-bookworm-slim node backend/scripts/package-publication.mjs /out/host >/dev/null

echo "==> Building the image"
docker build -q -t huma-host "$OUT/host" >/dev/null

echo "==> Starting the server"
docker rm -f huma >/dev/null 2>&1 || true
# Host networking: Caddy reaches it from 127.0.0.1, so the server sees each visitor's real address (client-ip.mjs).
docker run -d --name huma --restart unless-stopped --network host \
  --env-file "$ENV_FILE" -e HUMA_REGISTRY_HOST=127.0.0.1 \
  -v huma-data:/app/frontend/data huma-host >/dev/null

# The port is HUMA_REGISTRY_PORT from the env file, 4318 when it isn't set. Caddy must proxy to the same one.
PORT="$(grep -E '^HUMA_REGISTRY_PORT=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"' \r')"
PORT="${PORT:-4318}"
for _ in $(seq 1 30); do
  if curl -fs -o /dev/null "http://127.0.0.1:$PORT/"; then
    echo "==> Huma is up on http://127.0.0.1:$PORT (point Caddy's reverse_proxy at 127.0.0.1:$PORT)"
    exit 0
  fi
  sleep 1
done
echo "The server didn't answer. Recent logs:" >&2
docker logs --tail 30 huma >&2
exit 1
