#!/bin/bash
# One command to release Huma.
#   backend/scripts/ship.sh 0.1.5 "First note." "Second note."   tests, new version, notarized installer, signed update feed,
#                                                         uploads, website, older installers removed, live checks
#   backend/scripts/ship.sh --built                              ship the installer backend/scripts/release.sh last built, and the website
#   backend/scripts/ship.sh --web                                the website only (nothing about the Mac app)
# Needs .env.local (R2) and .env.deploy (server). Every upload is checked; anything already uploaded is left as it is.
set -euo pipefail
cd "$(dirname "$0")/../.."
MODE=${1:-}
if [[ ! $MODE =~ ^([0-9]+\.[0-9]+\.[0-9]+|--built|--web)$ ]]; then
    echo 'Usage: backend/scripts/ship.sh <version> "note" … | --built | --web'; exit 64
fi
step() { printf '\n== %s\n' "$1"; }

if [[ $MODE =~ ^[0-9] ]]; then
    shift
    [ $# -gt 0 ] || { echo "Add at least one release note, e.g. backend/scripts/ship.sh $MODE \"Faster proofs.\""; exit 64; }
    step "Tests"
    swift test --package-path extra --scratch-path .build 2>&1 | grep -E "Executed [0-9]+ tests" | tail -1
    (cd frontend && npm test 2>&1 | grep -E "^ℹ (pass|fail)")
    step "Version $MODE"
    BUILD=$(( $(/usr/libexec/PlistBuddy -c "Print CFBundleVersion" extra/Resources/Info.plist) + 1 ))
    /usr/libexec/PlistBuddy -c "Set CFBundleShortVersionString $MODE" -c "Set CFBundleVersion $BUILD" extra/Resources/Info.plist
    sed -i '' "s/^const HUMA_RELEASE = '[0-9.]*';/const HUMA_RELEASE = '$MODE';/" frontend/registry.mjs
    step "Signed, notarized installer (a few minutes)"
    ./backend/scripts/release.sh
    NOTES=""
    for NOTE in "$@"; do
        NOTE=${NOTE//&/&amp;}; NOTE=${NOTE//</&lt;}; NOTE=${NOTE//>/&gt;}
        NOTES+="<li>$NOTE</li>"
    done
    HUMA_RELEASE_NOTES="$NOTES" ./backend/scripts/appcast.sh
fi
if [ "$MODE" != "--web" ]; then
    VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" extra/Resources/Info.plist)
    SIGNATURE=$(grep -o 'sparkle:edSignature="[^"]*"' frontend/pages/appcast.xml | cut -d'"' -f2)
    .build/artifacts/sparkle/Sparkle/bin/sign_update --account huma --verify build/release/Huma.dmg "$SIGNATURE"
    grep -q "<sparkle:shortVersionString>$VERSION<" frontend/pages/appcast.xml || { echo "The update feed isn't for $VERSION."; exit 1; }
fi

cd frontend
# The website ships frontend/dist as built, so rebuild the share, deck and proof-checking bundles from their current sources.
step "Web bundles"
npm run build --silent >/dev/null
node ../experiments/noir-compact/browser/build.mjs --web >/dev/null
node write/build.mjs >/dev/null
if [ "$MODE" != "--web" ]; then
    step "R2: the Mac app's proving points"
    node --env-file=../.env.local ../backend/scripts/upload-engine.mjs
    step "Installer $VERSION"
    node --env-file=../.env.local ../backend/scripts/upload-release.mjs
fi
cd ..
step "Website"
./backend/scripts/deploy-web.sh
if [ "$MODE" != "--web" ]; then
    step "Removing older installers"
    (cd frontend && HUMA_KEEP="releases/Huma-$VERSION.dmg" node --env-file=../.env.local --input-type=module -e '
const { S3Client, DeleteObjectCommand, ListObjectsV2Command } = await import("@aws-sdk/client-s3");
const c = new S3Client({ region: "auto", endpoint: process.env.R2_ENDPOINT, credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const Bucket = process.env.R2_BUCKET, list = async () => ((await c.send(new ListObjectsV2Command({ Bucket, Prefix: "releases/" }))).Contents ?? []).map(o => o.Key);
if (!(await list()).includes(process.env.HUMA_KEEP)) throw new Error("The new installer is missing; nothing removed.");
for (const Key of await list()) if (Key !== process.env.HUMA_KEEP) await c.send(new DeleteObjectCommand({ Bucket, Key }));
console.log("installers now:", (await list()).join(", "));')
fi

step "Live checks"
if [ "$MODE" != "--web" ]; then
    echo "update feed: $(curl -s https://huma.social/appcast.xml | grep -o 'shortVersionString>[0-9.]*' | head -1 | cut -d'>' -f2)"
    echo "download matches this build: $([ "$(curl -sSL https://huma.social/download/Huma.dmg | shasum -a 256 | cut -c1-64)" = "$(shasum -a 256 build/release/Huma.dmg | cut -c1-64)" ] && echo yes || echo NO)"
    echo "proving points: $(curl -s -o /dev/null -w '%{http_code}' https://huma.social/engine/proving-setup)"
fi
echo "home picture: $(curl -s -o /dev/null -w '%{http_code}' https://huma.social/foundation-media/hero-art.webp)"
echo "example page: $(curl -s -o /dev/null -w '%{http_code}' https://huma.social/example)"
