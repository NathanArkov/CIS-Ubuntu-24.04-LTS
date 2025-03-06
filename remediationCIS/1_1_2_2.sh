#!/bin/bash

# Function to backup fstab
backup_fstab() {
    cp /etc/fstab /etc/fstab.$(date +%Y%m%d-%H%M%S).bak
}

# Function to add or update /dev/shm entry in fstab
configure_fstab() {
    if grep -q '^tmpfs[[:space:]]\+/dev/shm' /etc/fstab; then
        # Update existing entry
        sed -i '/^tmpfs[[:space:]]\+\/dev\/shm/c\tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0' /etc/fstab
    else
        # Add new entry
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
    fi
}

# Function to remount /dev/shm with proper options
remount_shm() {
    mount -o remount,noexec,nodev,nosuid /dev/shm
}

echo "=== Remediating /dev/shm configuration ==="

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Backup fstab
echo "Creating backup of /etc/fstab..."
backup_fstab

# Configure fstab
echo "Configuring /dev/shm in /etc/fstab..."
configure_fstab

# Remount /dev/shm
echo "Remounting /dev/shm with proper options..."
remount_shm

echo "Remediation completed. Please verify the changes."
exit 0