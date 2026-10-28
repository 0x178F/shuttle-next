#!/bin/zsh
set -euo pipefail
ROOT="${0:A:h:h}"
ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
  arm64|x86_64) ;;
  *) print -u2 "ARCH must be arm64 or x86_64"; exit 1 ;;
esac
VERSION="${APP_VERSION:-$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$ROOT/Resources/Info.plist")}"
BUILD_NUMBER="${BUILD_NUMBER:-$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$ROOT/Resources/Info.plist")}"
if [[ ! "$VERSION" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' || "$BUILD_NUMBER" != <-> ]]; then
  print -u2 "APP_VERSION must be major.minor.patch and BUILD_NUMBER must be numeric."
  exit 1
fi
IDENTITY="${CODE_SIGN_IDENTITY:--}"

swift build --package-path "$ROOT" --configuration release --arch "$ARCH" --force-resolved-versions
BIN="$(swift build --package-path "$ROOT" --configuration release --arch "$ARCH" --show-bin-path)"
APP="$ROOT/dist/ShuttleNext.app"
mkdir -p "$ROOT/dist"
# dist is a generated output owned by this build, not an installed application.
rm -rf -- "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/ShuttleNext" "$APP/Contents/MacOS/ShuttleNext"
cp "$BIN/ShuttleNextHelper" "$APP/Contents/MacOS/ShuttleNextHelper"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP/Contents/Info.plist"
cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp -R "$BIN/ShuttleNext_ShuttleCore.bundle" "$APP/Contents/Resources/"
for localization in "$ROOT"/Resources/*.lproj; do
  [[ -d "$localization" ]] && cp -R "$localization" "$APP/Contents/Resources/"
done

SIGN_OPTIONS=(--force --sign "$IDENTITY" --options runtime)
if [[ "$IDENTITY" == "-" ]]; then
  SIGN_OPTIONS+=(--timestamp=none)
else
  SIGN_OPTIONS+=(--timestamp)
fi
codesign "${SIGN_OPTIONS[@]}" "$APP/Contents/MacOS/ShuttleNextHelper"
codesign "${SIGN_OPTIONS[@]}" --entitlements "$ROOT/Resources/ShuttleNext.entitlements" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
print "Built: $APP ($ARCH)"

STAGING="$(mktemp -d)"
trap 'rm -rf -- "$STAGING"' EXIT
ditto "$APP" "$STAGING/ShuttleNext.app"
ln -s /Applications "$STAGING/Applications"
DMG="$ROOT/dist/ShuttleNext-$ARCH.dmg"
hdiutil create -volname ShuttleNext -srcfolder "$STAGING" -fs HFS+ -format UDZO -ov "$DMG"
hdiutil verify "$DMG"
print "Built: $DMG"
if [[ "$IDENTITY" == "-" ]]; then
  print "Local ad-hoc signature only. Developer ID signing and Apple notarization are required for trusted public distribution."
fi
