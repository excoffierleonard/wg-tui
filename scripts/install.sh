#!/bin/sh
set -e

REPO="excoffierleonard/wg-tui"
BINARY="wg-tui"
INSTALL_DIR="/usr/local/bin"

# Get latest version
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
VERSION_NO_V=$(echo "$VERSION" | tr -d 'v')

echo "Installing ${BINARY} ${VERSION}..."

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) TARGET="x86_64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Download
URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}-${VERSION_NO_V}-${TARGET}"
echo "Downloading from ${URL}..."
curl -fsSL "$URL" -o "$BINARY"

# Install
chmod +x "$BINARY"
if [ -w "$INSTALL_DIR" ]; then
    mv "$BINARY" "$INSTALL_DIR/"
else
    sudo mv "$BINARY" "$INSTALL_DIR/"
fi

echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
echo "Run '${BINARY} --version' to verify"