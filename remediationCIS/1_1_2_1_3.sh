#!/bin/bash

# Check if running with root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Backup fstab before modifications
cp /etc/fstab /etc/fstab.backup

# Add nosuid option to /tmp if it exists in fstab
if grep -q "^[^#].*\s/tmp\s" /etc/fstab; then
    # Add nosuid option if it's not already present
    sed -i '/\s\/tmp\s/ s/defaults/defaults,nosuid/' /etc/fstab
    sed -i 's/,nosuid,nosuid/,nosuid/' /etc/fstab  # Remove duplicate nosuid if any
else
    echo "# /tmp with nosuid option" >> /etc/fstab
    echo "tmpfs   /tmp    tmpfs   defaults,nosuid   0   0" >> /etc/fstab
fi

# Remount /tmp to apply changes
mount -o remount /tmp

echo "Added nosuid option to /tmp and remounted successfully"