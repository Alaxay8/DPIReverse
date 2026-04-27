#!/bin/bash

# DPIReverse Installation Script for Linux and macOS

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting DPIReverse installation...${NC}"

# 0. Handle one-liner installation (cloning if not in repo)
if [ ! -f "go.mod" ]; then
    echo -e "${BLUE}Not in repository. Cloning from GitHub...${NC}"
    TMP_DIR=$(mktemp -d)
    git clone https://github.com/Alaxay8/DPIReverse.git "$TMP_DIR"
    cd "$TMP_DIR"
    # Ensure we are on the dev branch if that's where the latest code is
    git checkout dev &> /dev/null || true
fi

# 1. Check for Go
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed. Please install Go (1.21+) to build the utility.${NC}"
    exit 1
fi

# 2. Build the binary
echo -e "${BLUE}Building the binary...${NC}"
go build -o dpi .

# 3. Determine installation path
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    echo -e "${BLUE}Requesting sudo permissions to install to $INSTALL_DIR...${NC}"
    sudo mv dpi "$INSTALL_DIR/dpi"
    sudo chmod +x "$INSTALL_DIR/dpi"
else
    mv dpi "$INSTALL_DIR/dpi"
    chmod +x "$INSTALL_DIR/dpi"
fi

echo -e "${GREEN}Success! DPIReverse is now installed as 'dpi'.${NC}"
echo -e "You can run it from any directory using: ${BLUE}dpi scan youtube.com${NC}"
