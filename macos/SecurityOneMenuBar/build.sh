#!/bin/bash
#
# Build the menu bar console into a runnable .app bundle.
#
# No Xcode project on purpose: this is one Swift file against AppKit, and a
# project file would be more to maintain than the program. All that is needed
# is the Command Line Tools, which anyone with Homebrew already has.
#
#   ./build.sh          build into ./build/SecurityOne.app
#   ./build.sh install  build, then move it to /Applications and launch it
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="SecurityOne"
BUNDLE="$HERE/build/$APP_NAME.app"

if ! command -v swiftc >/dev/null 2>&1; then
    echo "swiftc not found. Install the Command Line Tools first:"
    echo "  xcode-select --install"
    exit 1
fi

echo "==> Compiling"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"

# Optimised because it runs continuously; a menu bar app that costs measurable
# CPU is one people quit, and then it is not a console at all.
swiftc -O \
    -target "$(uname -m)-apple-macos11.0" \
    -framework AppKit \
    -o "$BUNDLE/Contents/MacOS/$APP_NAME" \
    "$HERE/main.swift"

echo "==> Assembling bundle"

# LSUIElement is what keeps it out of the Dock and the app switcher. Without
# it this is a normal application with an invisible window, which is a
# different and much more annoying thing.
cat > "$BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Security One</string>
    <key>CFBundleDisplayName</key><string>Security One</string>
    <key>CFBundleIdentifier</key><string>com.securityone.menubar</string>
    <key>CFBundleVersion</key><string>1.0</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleExecutable</key><string>$APP_NAME</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>LSUIElement</key><true/>
    <key>NSAppleEventsUsageDescription</key>
    <string>Opens Terminal to show the full agent report.</string>
</dict>
</plist>
PLIST

# Ad-hoc signature. Not a distribution signature — it is what lets the binary
# run at all on Apple Silicon, where an unsigned executable is refused.
codesign --force --deep --sign - "$BUNDLE" 2>/dev/null || \
    echo "    (codesign unavailable; the app may need to be allowed in System Settings)"

echo "==> Built $BUNDLE"

if [ "${1:-}" = "install" ]; then
    echo "==> Installing to /Applications"
    rm -rf "/Applications/$APP_NAME.app"
    cp -R "$BUNDLE" /Applications/
    open "/Applications/$APP_NAME.app"
    echo "    Running. Look for the dot in the menu bar."
else
    echo
    echo "    Run it:      open '$BUNDLE'"
    echo "    Install it:  $0 install"
fi
