#!/bin/bash
# Deploys huma to Vercel from this machine: builds the web assets (Rust, Noir outputs, proving setup), packages them
# for Vercel (vercel-build.mjs) and uploads the result as a prebuilt deployment. Vercel can't build these itself.
#   backend/scripts/deploy-vercel.sh            production deployment
#   backend/scripts/deploy-vercel.sh --preview  preview deployment
#   SKIP_ASSETS=1 backend/scripts/deploy-vercel.sh   reuse frontend/dist from the last build
# First time: `npx vercel@latest login`, then `npx vercel@latest link` here. Server settings (Arkiv, Privy, World ID,
# HUMA_SESSION_SECRET, …) are the project's Environment Variables on Vercel, never files in the upload. The bundle has
# over 15,000 files, more than Vercel takes one by one, so it goes up as one archive.
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -f .vercel/project.json ] || { echo 'Not linked to a Vercel project: run `npx vercel@latest link` first.'; exit 1; }
if [ "${SKIP_ASSETS:-}" != 1 ]; then
    make build-frontend
    # The zkVM verifier's crates need Rust 1.90 or newer (ZKVM_RUST picks the installed toolchain).
    RUSTUP_TOOLCHAIN="${ZKVM_RUST:-1.98.0}" make build-zkvm-browser
fi
node backend/scripts/vercel-build.mjs
if [ "${1:-}" = --preview ]; then
    npx --yes vercel@latest deploy --prebuilt --archive=tgz
else
    npx --yes vercel@latest deploy --prebuilt --archive=tgz --prod
fi
