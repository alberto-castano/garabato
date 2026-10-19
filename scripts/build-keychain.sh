#!/bin/sh
# Builds the macOS Keychain helper from native/keychain/main.swift.
# Usage: scripts/build-keychain.sh [output path]
set -eu
if [ "$(uname -s)" != Darwin ]; then
  echo "Keychain helper skipped: it is built on macOS only."
  exit 0
fi
root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:-"$root/native/build/garabato-keychain"}
mkdir -p "$(dirname "$output")"
# macOS 12 is the oldest system that Electron supports and that has
# SecTrustCopyCertificateChain.
swiftc -O -target "$(uname -m)-apple-macos12" \
  "$root/native/keychain/main.swift" -o "$output"
