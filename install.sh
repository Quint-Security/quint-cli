#!/bin/sh
set -e

REPO="Quint-Security/cli"
INSTALL_DIR="/usr/local/bin"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin) OS="darwin" ;;
  linux)  OS="linux" ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="x64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

TARGET="${OS}-${ARCH}"
URL="https://github.com/${REPO}/releases/latest/download/quint-${TARGET}.tar.gz"

echo "Downloading quint for ${TARGET}..."
tmpdir=$(mktemp -d)
curl -fsSL "$URL" | tar xz -C "$tmpdir"

echo "Installing to ${INSTALL_DIR}/quint..."
if [ -w "$INSTALL_DIR" ]; then
  mv "$tmpdir/quint" "$INSTALL_DIR/quint"
else
  sudo mv "$tmpdir/quint" "$INSTALL_DIR/quint"
fi

rm -rf "$tmpdir"

echo "quint installed successfully. Run 'quint --help' to get started."
