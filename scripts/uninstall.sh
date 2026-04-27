#!/bin/bash

# DPIReverse Uninstallation Script

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${BLUE}Uninstalling DPIReverse...${NC}"

if [ -f "/usr/local/bin/dpi" ]; then
    sudo rm "/usr/local/bin/dpi"
    echo -e "${GREEN}DPIReverse has been removed from /usr/local/bin/dpi.${NC}"
elif [ -f "/usr/bin/dpi" ]; then
    sudo rm "/usr/bin/dpi"
    echo -e "${GREEN}DPIReverse has been removed from /usr/bin/dpi.${NC}"
else
    echo -e "${RED}DPIReverse was not found in standard paths.${NC}"
fi
