#!/bin/bash
# install-dep.sh — Install build dependencies for NaxDarks Linux agent (x64 + arm64)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || { echo -e "${RED}Not root and sudo not found.${NC}"; exit 1; }
    SUDO="sudo"
fi

echo -e "${YELLOW}Installing NaxDarks build dependencies...${NC}"
echo ""

echo -e "${YELLOW}[1/4] Base toolchain...${NC}"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq build-essential pkg-config > /dev/null 2>&1
echo -e "${GREEN}  ✓${NC} gcc, make, pkg-config"

echo -e "${YELLOW}[2/4] x86_64 libraries...${NC}"
$SUDO apt-get install -y -qq libssl-dev libcurl4-openssl-dev zlib1g-dev > /dev/null 2>&1
echo -e "${GREEN}  ✓${NC} libssl-dev, libcurl4-openssl-dev, zlib1g-dev"

echo -e "${YELLOW}[3/4] ARM64 cross-compiler...${NC}"
$SUDO apt-get install -y -qq gcc-aarch64-linux-gnu > /dev/null 2>&1
echo -e "${GREEN}  ✓${NC} gcc-aarch64-linux-gnu"

echo -e "${YELLOW}[4/4] ARM64 libraries...${NC}"
$SUDO dpkg --add-architecture arm64 > /dev/null 2>&1
$SUDO apt-get update -qq > /dev/null 2>&1
$SUDO apt-get install -y -qq -o Dpkg::Options::="--force-overwrite" \
    libcurl4-openssl-dev:arm64 \
    libssl-dev:arm64 \
    zlib1g-dev:arm64 > /dev/null 2>&1
echo -e "${GREEN}  ✓${NC} libcurl4-openssl-dev:arm64, libssl-dev:arm64, zlib1g-dev:arm64"

echo ""
echo -e "${GREEN}Done.${NC}"
