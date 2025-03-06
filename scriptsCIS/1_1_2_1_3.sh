#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if /tmp is mounted without the nosuid option
if findmnt -kn /tmp | grep -v nosuid >/dev/null; then
    echo -e "${RED}[FAIL] /tmp is mounted without the nosuid option. Remediation needed${NC}"
    exit 1
else
    echo -e "${GREEN}[PASS] /tmp is mounted with the nosuid option${NC}"
    exit 0
fi