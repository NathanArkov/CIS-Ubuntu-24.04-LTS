#!/bin/bash

echo "Checking if /var is on a separate partition and verifying mount options..."

# Check if /var is a mount point
if mountpoint -q /var; then
    echo "[INFO] /var is mounted on a separate partition"
    
    # Get mount options for /var
    mount_options=$(mount | grep ' /var ' | awk '{print $6}' | tr -d '()')
    
    # Check for required mount options
    if echo "$mount_options" | grep -q "noexec"; then
        echo "[PASS] noexec option is set on /var"
    else
        echo "[FAIL] noexec option is not set on /var"
    fi
    
    if echo "$mount_options" | grep -q "nosuid"; then
        echo "[PASS] nosuid option is set on /var"
    else
        echo "[FAIL] nosuid option is not set on /var"
    fi
    
    if echo "$mount_options" | grep -q "nodev"; then
        echo "[PASS] nodev option is set on /var"
    else
        echo "[FAIL] nodev option is not set on /var"
    fi
else
    echo "[FAIL] /var is not mounted on a separate partition"
fi