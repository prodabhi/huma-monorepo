#!/bin/bash
# Writes frontend/pages/appcast.xml (served at huma.social/appcast.xml) for build/release/Huma.dmg, signed with the
# Sparkle key in this Mac's Keychain. Installed copies of Huma read it to find and verify updates.
# Optional: HUMA_RELEASE_NOTES="<li>…</li><li>…</li>"
set -euo pipefail
cd "$(dirname "$0")/.."
DMG=build/release/Huma.dmg
VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" extra/Resources/Info.plist)
BUILD=$(/usr/libexec/PlistBuddy -c "Print CFBundleVersion" extra/Resources/Info.plist)
SIGNATURE=$(.build/artifacts/sparkle/Sparkle/bin/sign_update --account huma "$DMG")
DATE=$(LC_ALL=C date -u "+%a, %d %b %Y %H:%M:%S +0000")
cat > frontend/pages/appcast.xml <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Huma</title>
    <item>
      <title>Huma $VERSION</title>
      <pubDate>$DATE</pubDate>
      <sparkle:version>$BUILD</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>14.0</sparkle:minimumSystemVersion>
      <description><![CDATA[<ul>${HUMA_RELEASE_NOTES:-}</ul>]]></description>
      <enclosure url="https://huma.social/download/Huma.dmg" type="application/octet-stream" $SIGNATURE/>
    </item>
  </channel>
</rss>
XML
printf 'Wrote frontend/pages/appcast.xml for Huma %s (%s)\n' "$VERSION" "$BUILD"
