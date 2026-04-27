#!/bin/bash

# DPIReverse Uninstallation Script

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${BLUE}Uninstalling DPIReverse...${NC}"

if [ -f "/usr/local/bin/dpi" ]; then
    sudo rm "/usr/local/bin/dpi"
    echo -e "${GREEN}DPIReverse has been removed successfully.${NC}"
else
    echo "DPIReverse was not found in /usr/local/bin/dpi"
fi
