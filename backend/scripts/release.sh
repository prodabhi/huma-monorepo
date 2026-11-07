#!/bin/bash
# Builds a Developer ID signed, notarized and stapled Huma.dmg that opens on any Mac.
# Needs the Developer ID certificate in the keychain and the `huma-notary` notarytool profile.
set -euo pipefail
cd "$(dirname "$0")/../.."
IDENTITY="${HUMA_SIGN_IDENTITY:-Developer ID Application: Swayam Karle (38V69R9TA5)}"
OUT="$PWD/build/release"
rm -rf "$OUT/Huma.app" "$OUT/dmg" "$OUT/Huma.dmg"
mkdir -p "$OUT"
# The proving points are downloaded once by the app instead of shipped (HumaCore ProvingSetup).
HUMA_EXTERNAL_SETUP=1 HUMA_CONFIG=release HUMA_SIGN_IDENTITY="$IDENTITY" HUMA_APP_DIR="$OUT/Huma.app" ./backend/scripts/build.sh
codesign --verify --deep --strict "$OUT/Huma.app"

mkdir -p "$OUT/dmg"
ditto "$OUT/Huma.app" "$OUT/dmg/Huma.app"
ln -s /Applications "$OUT/dmg/Applications"
# The window layout (Huma left, Applications right, the arrow background between), made once with dmgbuild
# 1.6.7; it refers to the volume by name, so the volume stays "Huma".
cp extra/Resources/dmg/DS_Store "$OUT/dmg/.DS_Store"
cp extra/Resources/dmg/background.tiff "$OUT/dmg/.background.tiff"
# LZMA (ULMO) is about 15% smaller than the default zlib and opens on macOS 10.15 and later.
hdiutil create -volname Huma -srcfolder "$OUT/dmg" -fs HFS+ -format ULMO "$OUT/Huma.dmg" >/dev/null
rm -rf "$OUT/dmg"
codesign --force --timestamp --sign "$IDENTITY" "$OUT/Huma.dmg"

# Apple scans the disk image and everything in it; the ticket is then stapled for offline opens.
xcrun notarytool submit "$OUT/Huma.dmg" --keychain-profile huma-notary --wait
xcrun stapler staple "$OUT/Huma.dmg"
spctl --assess --type open --context context:primary-signature --verbose "$OUT/Huma.dmg"
printf 'Built %s\n' "$OUT/Huma.dmg"
