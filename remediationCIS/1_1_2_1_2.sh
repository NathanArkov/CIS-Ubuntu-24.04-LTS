#!/bin/bash

# Check if running with root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Backup fstab before modifications
cp /etc/fstab /etc/fstab.backup

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

echo "Added nodev option to /tmp and remounted successfully"