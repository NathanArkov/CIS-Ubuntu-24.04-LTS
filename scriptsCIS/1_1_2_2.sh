#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to check if /dev/shm is mounted as tmpfs
check_shm_mount() {
    if ! mount | grep -E '\s/dev/shm\s' | grep -q 'tmpfs'; then
        echo -e "${RED}FAIL: /dev/shm is not mounted as tmpfs${NC}"
        return 1
    fi
    echo -e "${GREEN}PASS: /dev/shm is properly mounted as tmpfs${NC}"
    return 0
}

# Function to check mount options
check_mount_option() {
    local option=$1
    if ! mount | grep -E '\s/dev/shm\s' | grep -q "$option"; then
        echo -e "${RED}FAIL: $option option is not set on /dev/shm${NC}"
        return 1
    fi
    echo -e "${GREEN}PASS: $option option is set on /dev/shm${NC}"
    return 0
}

# Main execution
echo "=== Checking /dev/shm configuration ==="
check_shm_mount
shm_status=$?

echo "Checking mount options..."
check_mount_option "nodev"
nodev_status=$?

check_mount_option "nosuid"
nosuid_status=$?

check_mount_option "noexec"
noexec_status=$?

# Check fstab entry
echo "Checking /etc/fstab entry..."
if grep -q '/dev/shm' /etc/fstab; then
    echo -e "${GREEN}PASS: /dev/shm entry exists in /etc/fstab${NC}"
else
    echo -e "${RED}FAIL: No /dev/shm entry in /etc/fstab${NC}"
fi

# Final status
if [ $shm_status -eq 0 ] && [ $nodev_status -eq 0 ] && [ $nosuid_status -eq 0 ] && [ $noexec_status -eq 0 ]; then
    echo -e "${GREEN}Overall status: PASS${NC}"
    exit 0
else
    echo -e "${RED}Overall status: FAIL${NC}"
    exit 1
fi