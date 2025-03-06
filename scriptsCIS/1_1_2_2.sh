#!/bin/bash

# Function to check if /dev/shm is mounted as tmpfs
check_shm_mount() {
    if ! mount | grep -E '\s/dev/shm\s' | grep -q 'tmpfs'; then
        echo "FAIL: /dev/shm is not mounted as tmpfs"
        return 1
    fi
    echo "PASS: /dev/shm is properly mounted as tmpfs"
    return 0
}

# Function to check mount options
check_mount_option() {
    local option=$1
    if ! mount | grep -E '\s/dev/shm\s' | grep -q "$option"; then
        echo "FAIL: $option option is not set on /dev/shm"
        return 1
    fi
    echo "PASS: $option option is set on /dev/shm"
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
    echo "PASS: /dev/shm entry exists in /etc/fstab"
else
    echo "FAIL: No /dev/shm entry in /etc/fstab"
fi

# Final status
if [ $shm_status -eq 0 ] && [ $nodev_status -eq 0 ] && [ $nosuid_status -eq 0 ] && [ $noexec_status -eq 0 ]; then
    echo "Overall status: PASS"
    exit 0
else
    echo "Overall status: FAIL"
    exit 1
fi