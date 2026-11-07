#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
CONFIG="${HUMA_CONFIG:-debug}"
swift build --package-path extra --scratch-path .build -c "$CONFIG" --jobs 2
BIN_DIR="$(swift build --package-path extra --scratch-path .build -c "$CONFIG" --jobs 2 --show-bin-path)"
# Ad-hoc by default. A Developer ID (HUMA_SIGN_IDENTITY) adds the hardened runtime and a
# timestamp, which notarization requires.
IDENTITY="${HUMA_SIGN_IDENTITY:--}"
sign() {
    if [ "$IDENTITY" = "-" ]; then codesign --force --sign - "$@"
    else codesign --force --options runtime --timestamp --sign "$IDENTITY" "$@"; fi
}
APP_DIR="${HUMA_APP_DIR:-$PWD/build/Huma.app}"
if pgrep -f "^$APP_DIR/Contents/MacOS/Huma($| )" >/dev/null; then
    printf 'Quit Huma before replacing its running app bundle, or set HUMA_APP_DIR to a new path.\n' >&2
    exit 1
fi
# Resources are generated from the supported engines below. Rebuild them from
# scratch so retired service runtimes cannot survive an incremental package.
rm -rf "$APP_DIR/Contents/Resources"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BIN_DIR/Huma" "$APP_DIR/Contents/MacOS/Huma"
# Frameworks load only from inside the app: drop the build machine's absolute search paths.
otool -l "$APP_DIR/Contents/MacOS/Huma" | awk '/LC_RPATH/ {getline; getline; print $2}' | grep '^/' | grep -v '^/usr/lib' \
    | while read -r RPATH; do install_name_tool -delete_rpath "$RPATH" "$APP_DIR/Contents/MacOS/Huma"; done
cp extra/Resources/Info.plist "$APP_DIR/Contents/Info.plist"
cp extra/Resources/Huma.icns "$APP_DIR/Contents/Resources/Huma.icns"
# Writers' faces, drawn on the Mac with the site's DiceBear code (npm run build:faces in frontend/).
cp extra/Resources/Faces.js "$APP_DIR/Contents/Resources/Faces.js"
# The website's fonts (Inter and Geist Mono, both SIL OFL), so the app reads like huma.social.
mkdir -p "$APP_DIR/Contents/Resources/Fonts"
cp frontend/pages/fonts/inter.woff2 frontend/pages/fonts/OFL.txt "$APP_DIR/Contents/Resources/Fonts/"
cp frontend/pages/fonts/geist-mono.woff2 "$APP_DIR/Contents/Resources/Fonts/"
cp frontend/pages/fonts/GEIST-OFL.txt "$APP_DIR/Contents/Resources/Fonts/GEIST-OFL.txt"
# Sparkle (updates): its helpers are signed inside out, then the framework, as Sparkle documents.
rm -rf "$APP_DIR/Contents/Frameworks"
mkdir -p "$APP_DIR/Contents/Frameworks"
ditto "$BIN_DIR/Sparkle.framework" "$APP_DIR/Contents/Frameworks/Sparkle.framework"
SPARKLE="$APP_DIR/Contents/Frameworks/Sparkle.framework/Versions/B"
sign "$SPARKLE/XPCServices/Installer.xpc"
sign --preserve-metadata=entitlements "$SPARKLE/XPCServices/Downloader.xpc"
sign "$SPARKLE/Autoupdate"
sign "$SPARKLE/Updater.app"
sign "$APP_DIR/Contents/Frameworks/Sparkle.framework"
COMPACT_LIBRARY="$PWD/build/research/noir-compact-native-target/release/libhuma_compact_experiment.dylib"
if [ -f "$COMPACT_LIBRARY" ]; then
    COMPACT="$APP_DIR/Contents/Resources/CompactCapture"
    mkdir -p "$COMPACT"
    cp "$COMPACT_LIBRARY" "$COMPACT/libhuma_compact_experiment.dylib"
    sign "$COMPACT/libhuma_compact_experiment.dylib"
else
    rm -rf "$APP_DIR/Contents/Resources/CompactCapture"
fi
# Grammar suggestions: Harper (Apache-2.0), built from backend/integrations/grammar with its pinned Rust. Without it the app
# still suggests fixes with the Mac's own checker and the on-device model.
if command -v cargo >/dev/null; then
    cargo build --release --quiet --manifest-path backend/integrations/grammar/Cargo.toml --target-dir "$PWD/build/grammar-target"
fi
GRAMMAR_LIBRARY="$PWD/build/grammar-target/release/libhuma_grammar.dylib"
if [ -f "$GRAMMAR_LIBRARY" ]; then
    mkdir -p "$APP_DIR/Contents/Resources/Grammar"
    cp "$GRAMMAR_LIBRARY" "$APP_DIR/Contents/Resources/Grammar/libhuma_grammar.dylib"
    cp backend/integrations/grammar/LICENSE-HARPER.txt "$APP_DIR/Contents/Resources/Grammar/LICENSE.txt"
    sign "$APP_DIR/Contents/Resources/Grammar/libhuma_grammar.dylib"
else
    rm -rf "$APP_DIR/Contents/Resources/Grammar"
fi
# Witnesses: Noir's own solver, built natively from its pinned release (backend/integrations/noir/witness).
cargo build --release --quiet --locked --manifest-path backend/integrations/noir/witness/Cargo.toml --target-dir "$PWD/build/witness-target"
# The engine runs its JavaScript on macOS's own JavaScriptCore through HumaScriptHost (no bundled Node.js).
HUMA_SCRIPT_HOST="$BIN_DIR/HumaScriptHost" python3 backend/integrations/noir/package.py "$APP_DIR/Contents/Resources/NoirEngine"
# JavaScriptCore compiles the engine's JavaScript just in time, so its host may use JIT memory (and nothing broader).
for RUNTIME in HumaScriptHost node; do
    if [ -f "$APP_DIR/Contents/Resources/NoirEngine/$RUNTIME" ]; then
        sign --entitlements extra/Resources/NoirNode.entitlements "$APP_DIR/Contents/Resources/NoirEngine/$RUNTIME"
    fi
done
for TOOL in bb capture-input witness; do
    sign "$APP_DIR/Contents/Resources/NoirEngine/$TOOL"
done
python3 backend/integrations/noir/package.py --refresh-manifest "$APP_DIR/Contents/Resources/NoirEngine"
sign "$APP_DIR"
printf 'Built %s\n' "$APP_DIR"
