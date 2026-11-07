#!/bin/bash
# Updates huma.social (website and server code). The server package goes to Cloudflare R2 and the server downloads it
# from there, so only short commands cross the (slow) ssh link; then the server rebuilds and restarts the container.
# Settings: .env.deploy (server, key, example page) and .env.local (R2). backend/scripts/ship.sh runs this.
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a; source .env.deploy; set +a
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
SSH=(ssh -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=8 -i "${HUMA_DEPLOY_KEY/#\~/$HOME}" -o IdentitiesOnly=yes "$HUMA_DEPLOY_SSH")
node backend/scripts/package-publication.mjs "$TMP/host" >/dev/null
COPYFILE_DISABLE=1 tar -C "$TMP/host" --no-xattrs --exclude=node_modules -czf "$TMP/host.tgz" .
(cd frontend && node --env-file=../.env.local ../backend/scripts/stage-host.mjs "$TMP/host.tgz" "$TMP/host-url.txt")
# Only the page link in the example (/original/<id>#<token>, or a short /p/<code>#<key>) is kept.
EXAMPLE=$(grep -oE "/original/[a-f0-9]{64}#[a-f0-9]{64}|/p/[A-Za-z0-9]{8,12}#[A-Za-z0-9]{16}" <<<"${HUMA_EXAMPLE_LINK:-}" | head -1 || true)
# Turnstile's keys (.env.local), when set, become the server's: read here without being shown.
key() { grep -E "^$1=" .env.local 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"' \r' || true; }
TURNSTILE_SITE=$(key HUMA_TURNSTILE_SITE_KEY); TURNSTILE_SECRET=$(key TURNSTILE_SECRET_KEY)
# PostHog's project key and region (frontend/events.mjs), the same way.
POSTHOG_KEY=$(key POSTHOG_KEY); POSTHOG_HOST=$(key POSTHOG_HOST)
# The signed link, checksum, example and keys go over stdin, never on a command line.
"${SSH[@]}" 'set -e; read -r URL; read -r SUM; read -r EXAMPLE || true; read -r TSITE || true; read -r TSECRET || true; read -r PKEY || true; read -r PHOST || true
curl -fsS --retry 3 -o /tmp/host.tgz "$URL"
echo "$SUM  /tmp/host.tgz" | sha256sum -c --quiet
# On-chain verification (frontend/onchain.mjs) reads HUMA_RELAYER_KEY, HUMA_ONCHAIN_CONTRACT, HUMA_CHAIN and
# HUMA_CHAIN_RPC from the server's .env, so those stay. Only the retired HUMA_PAGES_ADDRESS name is removed.
sudo sed -i "/^HUMA_PAGES_ADDRESS=/d" /opt/huma/.env
if echo "$EXAMPLE" | grep -Eq "^(/original/[a-f0-9]{64}(#[a-f0-9]{64})?|/p/[A-Za-z0-9]{8,12}(#[A-Za-z0-9]{16})?)$"; then
  sudo sed -i "/^HUMA_EXAMPLE_LINK=/d" /opt/huma/.env; echo "HUMA_EXAMPLE_LINK=$EXAMPLE" | sudo tee -a /opt/huma/.env >/dev/null
fi
if echo "$TSITE" | grep -Eq "^0x[A-Za-z0-9_-]{10,100}$" && echo "$TSECRET" | grep -Eq "^0x[A-Za-z0-9_-]{10,100}$"; then
  sudo sed -i "/^HUMA_TURNSTILE_SITE_KEY=/d; /^TURNSTILE_SECRET_KEY=/d; /^HUMA_TURNSTILE_HOSTNAMES=/d" /opt/huma/.env
  # The hostname Turnstile vouches for, so the check does not depend on the Host header the proxy passes on.
  printf "HUMA_TURNSTILE_SITE_KEY=%s\nTURNSTILE_SECRET_KEY=%s\nHUMA_TURNSTILE_HOSTNAMES=huma.social\n" "$TSITE" "$TSECRET" | sudo tee -a /opt/huma/.env >/dev/null
fi
if echo "$PKEY" | grep -Eq "^phc_[A-Za-z0-9_-]{20,80}$"; then
  sudo sed -i "/^POSTHOG_KEY=/d; /^POSTHOG_HOST=/d" /opt/huma/.env
  echo "$PHOST" | grep -Eq "^https://[a-z]+\.i\.posthog\.com$" || PHOST=https://us.i.posthog.com
  printf "POSTHOG_KEY=%s\nPOSTHOG_HOST=%s\n" "$PKEY" "$PHOST" | sudo tee -a /opt/huma/.env >/dev/null
fi
sudo rm -rf /opt/huma/app && sudo mkdir -p /opt/huma/app && sudo tar -C /opt/huma/app -xzf /tmp/host.tgz 2>/dev/null; rm /tmp/host.tgz
cd /opt/huma/app && sudo docker build -q -t huma-host . >/dev/null
sudo docker rm -f huma >/dev/null
sudo docker run -d --name huma --restart unless-stopped --env-file /opt/huma/.env -p 127.0.0.1:4318:4318 -v huma-data:/app/frontend/data huma-host >/dev/null
sleep 4 && echo DEPLOYED' < <(cat "$TMP/host-url.txt"; echo "$EXAMPLE"; echo "$TURNSTILE_SITE"; echo "$TURNSTILE_SECRET"; echo "$POSTHOG_KEY"; echo "$POSTHOG_HOST")
(cd frontend && node --env-file=../.env.local --input-type=module -e '
const { S3Client, DeleteObjectCommand } = await import("@aws-sdk/client-s3");
const c = new S3Client({ region: "auto", endpoint: process.env.R2_ENDPOINT, credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
await c.send(new DeleteObjectCommand({ Bucket: process.env.R2_BUCKET, Key: "deploy/host.tgz" }));')
curl -s -o /dev/null -w "website: %{http_code}\n" https://huma.social/
