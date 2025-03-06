#!/bin/bash

# 1.1.2-1.1.3 Ensure separate partition exists for /home and verify its mount options
echo "Checking /home partition and mount options..."

# Check if /home is a mount point
if mountpoint -q /home; then
    echo "[CHECK] /home is mounted as a separate partition"
    
    # Get mount options for /home
    mount_options=$(mount | grep ' /home ' | awk '{print $6}' | tr -d '()')
    
    # Check for required mount options
    if echo "$mount_options" | grep -q "nodev"; then
        echo "[PASS] nodev option is set on /home"
    else
        echo "[FAIL] nodev option is not set on /home"
    fi
    
    if echo "$mount_options" | grep -q "nosuid"; then
        echo "[PASS] nosuid option is set on /home"
    else
        echo "[FAIL] nosuid option is not set on /home"
    fi
    
    if echo "$mount_options" | grep -q "noexec"; then
        echo "[PASS] noexec option is set on /home"
    else
        echo "[FAIL] noexec option is not set on /home"
    fi
else
    echo "[FAIL] /home is not mounted as a separate partition"
fi