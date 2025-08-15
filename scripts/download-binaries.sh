#!/bin/bash
set -e

# Download pre-built binaries from GitHub releases
# Usage: ./scripts/download-binaries.sh <version> <target>

VERSION=${1:-latest}
TARGET=${2:-x86_64-unknown-linux-musl}

echo "Downloading binaries for version: $VERSION, target: $TARGET"

# Create binaries directory
mkdir -p binaries

# Function to download binary
download_binary() {
    local binary_name=$1
    local asset_name="${binary_name}-${TARGET}"

    if [ "$VERSION" = "latest" ]; then
        # Get latest release
        LATEST_TAG=$(curl -s https://api.github.com/repos/boundless-xyz/boundless/releases/latest | jq -r '.tag_name')
        DOWNLOAD_URL="https://github.com/boundless-xyz/boundless/releases/download/${LATEST_TAG}/${asset_name}"
    else
        DOWNLOAD_URL="https://github.com/boundless-xyz/boundless/releases/download/${VERSION}/${asset_name}"
    fi

    echo "Downloading $binary_name from: $DOWNLOAD_URL"

    if curl -L -f -o "binaries/${binary_name}" "$DOWNLOAD_URL"; then
        chmod +x "binaries/${binary_name}"
        echo "✅ Downloaded $binary_name successfully"
    else
        echo "❌ Failed to download $binary_name"
        exit 1
    fi
}

# Download required binaries
download_binary "agent"
download_binary "broker"
download_binary "boundless-cli"
download_binary "rest_api"

echo "All binaries downloaded successfully to binaries/ directory"
ls -la binaries/
