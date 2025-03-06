#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "Checking if /var is on a separate partition and verifying mount options..."

# Check if /var is a mount point
if mountpoint -q /var; then
    echo -e "${GREEN}[INFO] /var is mounted on a separate partition${NC}"
    
    # Get mount options for /var
    mount_options=$(mount | grep ' /var ' | awk '{print $6}' | tr -d '()')
    
    # Check for required mount options
    if echo "$mount_options" | grep -q "noexec"; then
        echo -e "${GREEN}[PASS] noexec option is set on /var${NC}"
    else
        echo -e "${RED}[FAIL] noexec option is not set on /var${NC}"
    fi
    
    if echo "$mount_options" | grep -q "nosuid"; then
        echo -e "${GREEN}[PASS] nosuid option is set on /var${NC}"
    else
        echo -e "${RED}[FAIL] nosuid option is not set on /var${NC}"
    fi
    
    if echo "$mount_options" | grep -q "nodev"; then
        echo -e "${GREEN}[PASS] nodev option is set on /var${NC}"
    else
        echo -e "${RED}[FAIL] nodev option is not set on /var${NC}"
    fi
else
    echo -e "${RED}[FAIL] /var is not mounted on a separate partition${NC}"
fi