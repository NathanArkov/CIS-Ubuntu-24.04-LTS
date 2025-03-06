#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# 1.1.2-1.1.3 Ensure separate partition exists for /home and verify its mount options
echo "Checking /home partition and mount options..."

# Check if /home is a mount point
if mountpoint -q /home; then
    echo -e "${GREEN}[CHECK] /home is mounted as a separate partition${NC}"
    
    # Get mount options for /home
    mount_options=$(mount | grep ' /home ' | awk '{print $6}' | tr -d '()')
    
    # Check for required mount options
    if echo "$mount_options" | grep -q "nodev"; then
        echo -e "${GREEN}[PASS] nodev option is set on /home${NC}"
    else
        echo -e "${RED}[FAIL] nodev option is not set on /home${NC}"
    fi
    
    if echo "$mount_options" | grep -q "nosuid"; then
        echo -e "${GREEN}[PASS] nosuid option is set on /home${NC}"
    else
        echo -e "${RED}[FAIL] nosuid option is not set on /home${NC}"
    fi
    
    if echo "$mount_options" | grep -q "noexec"; then
        echo -e "${GREEN}[PASS] noexec option is set on /home${NC}"
    else
        echo -e "${RED}[FAIL] noexec option is not set on /home${NC}"
    fi
else
    echo -e "${RED}[FAIL] /home is not mounted as a separate partition${NC}"
fi