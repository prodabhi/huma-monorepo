#!/bin/bash
# One command to release Huma.
#   backend/scripts/ship.sh 0.1.5 "First note." "Second note."   tests, new version, notarized installer, signed update feed,
#                                                         uploads (GitHub release), website (Vercel), live checks
#   backend/scripts/ship.sh --built                              ship the installer backend/scripts/release.sh last built, and the website
#   backend/scripts/ship.sh --web                                the website only (nothing about the Mac app)
# Needs GITHUB_TOKEN (in .env.local) for the release uploads, and this folder linked to Vercel (`npx vercel link`).
# Every upload is checked; anything already uploaded is left as it is.
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

if [ "$MODE" != "--web" ]; then
    step "GitHub release: the Mac app's proving points"
    node --env-file=.env.local backend/scripts/github-release.mjs engine
    step "GitHub release: installer $VERSION"
    node --env-file=.env.local backend/scripts/github-release.mjs installer
fi
# The website (deploy-vercel.sh rebuilds every web bundle from its current sources first).
step "Website"
./backend/scripts/deploy-vercel.sh

step "Live checks"
if [ "$MODE" != "--web" ]; then
    echo "update feed: $(curl -s https://huma.social/appcast.xml | grep -o 'shortVersionString>[0-9.]*' | head -1 | cut -d'>' -f2)"
    echo "download matches this build: $([ "$(curl -sSL https://huma.social/download/Huma.dmg | shasum -a 256 | cut -c1-64)" = "$(shasum -a 256 build/release/Huma.dmg | cut -c1-64)" ] && echo yes || echo NO)"
    echo "proving points: $(curl -s -o /dev/null -w '%{http_code}' https://huma.social/engine/proving-setup)"
fi
echo "home picture: $(curl -s -o /dev/null -w '%{http_code}' https://huma.social/foundation-media/hero-art.webp)"
echo "example page: $(curl -s -o /dev/null -w '%{http_code}' https://huma.social/example)"
