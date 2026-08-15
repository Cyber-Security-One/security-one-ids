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

# Never as root. The agent lives in a root-owned directory, so reaching for
# sudo is the natural move — and it is the wrong one: a menu bar app launched
# by root belongs to root's GUI session, which means it builds, installs,
# reports success, and never appears in the menu bar. Escalate only for the
# one step that genuinely needs it, further down.
if [ "$(id -u)" = "0" ]; then
    echo "Do not run this with sudo."
    echo "A menu bar app started as root lands in root's session and never appears."
    echo "Run it as yourself; it will ask for a password only if /Applications needs one."
    exit 1
fi

# Build somewhere the invoking user can actually write. Inside the repo is the
# obvious place and the wrong one, for the same reason.
BUILD_DIR="${BUILD_DIR:-$HOME/Library/Caches/SecurityOneMenuBar}"
BUNDLE="$BUILD_DIR/$APP_NAME.app"

if ! command -v swiftc >/dev/null 2>&1; then
    echo "swiftc not found. Install the Command Line Tools first:"
    echo "  xcode-select --install"
    exit 1
fi

echo "==> Compiling"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"

if [ ! -r "$HERE/main.swift" ]; then
    echo "main.swift is not readable at $HERE."
    echo "If the checkout is root-owned, the sources still need to be world-readable."
    exit 1
fi

# Optimised because it runs continuously; a menu bar app that costs measurable
# CPU is one people quit, and then it is not a console at all.
swiftc -O \
    -target "$(uname -m)-apple-macos11.0" \
    -framework AppKit \
    -framework SceneKit \
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

    # sudo only here, and only if it is actually needed — an admin account can
    # usually write /Applications without it. The launch below stays as the
    # invoking user either way, which is the point of not running the whole
    # script as root.
    if [ -w /Applications ]; then
        rm -rf "/Applications/$APP_NAME.app"
        cp -R "$BUNDLE" /Applications/
    else
        echo "    /Applications needs an administrator; you may be asked for your password."
        sudo rm -rf "/Applications/$APP_NAME.app"
        sudo cp -R "$BUNDLE" /Applications/
        sudo chown -R "$(id -u):$(id -g)" "/Applications/$APP_NAME.app"
    fi

    open "/Applications/$APP_NAME.app"
    echo "    Running. Look for the dot in the menu bar."
    echo "    Start it at login: System Settings > General > Login Items > +"
else
    echo
    echo "    Run it:      open '$BUNDLE'"
    echo "    Install it:  $0 install"
fi
