#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if running with root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Backup fstab before modifications
cp /etc/fstab /etc/fstab.backup

# Function to check if nodev is properly set
check_nodev() {
    if mount | grep "on /tmp" | grep -q "nodev"; then
        echo -e "${GREEN}PASS: nodev option is set on /tmp${NC}"
        return 0
    else
        echo -e "${RED}FAIL: nodev option is not set on /tmp${NC}"
        return 1
    fi
}

# Add nodev option to /tmp if it exists in fstab
if grep -q "^[^#].*\s/tmp\s" /etc/fstab; then
    # Add nodev option if it's not already present
    sed -i '/\s\/tmp\s/ s/defaults/defaults,nodev/' /etc/fstab
    sed -i 's/,nodev,nodev/,nodev/' /etc/fstab  # Remove duplicate nodev if any
else
    echo "# /tmp with nodev option" >> /etc/fstab
    echo "tmpfs   /tmp    tmpfs   defaults,nodev   0   0" >> /etc/fstab
fi

# Remount /tmp to apply changes
mount -o remount /tmp

# Check final status
check_nodev