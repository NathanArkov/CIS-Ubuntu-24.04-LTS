#!/bin/bash

# 1.1.2-1.1.3 Remediation: Ensure separate partition exists for /home and set proper mount options

echo "Remediating /home partition mount options..."

# Check if /home is a mount point
if ! mountpoint -q /home; then
    echo "ERROR: /home is not mounted as a separate partition."
    echo "Manual intervention required: Create a separate partition for /home first."
    exit 1
fi

# Get current mount options and device for /home
device=$(mount | grep ' /home ' | awk '{print $1}')
current_opts=$(mount | grep ' /home ' | awk '{print $6}' | tr -d '()')

# Create array of required options
required_opts=("nodev" "nosuid" "noexec")
new_opts=""

# Check and add missing options
for opt in "${required_opts[@]}"; do
    if ! echo "$current_opts" | grep -q "$opt"; then
        new_opts="$new_opts,$opt"
    fi
done

# If we have new options to add
if [ ! -z "$new_opts" ]; then
    # Remove leading comma if present
    new_opts=${new_opts#,}
    
    # Combine current and new options
    if [ ! -z "$current_opts" ]; then
        final_opts="$current_opts,$new_opts"
    else
        final_opts="$new_opts"
    fi

    echo "Updating /etc/fstab with new mount options..."
    # Backup fstab
    cp /etc/fstab /etc/fstab.backup
    
    # Update fstab with new options
    sed -i "s|\( /home .*\)|\1,${new_opts}|" /etc/fstab
    
    echo "Remounting /home with new options..."
    mount -o remount /home
    
    echo "Verification after remount:"
    mount | grep ' /home '
else
    echo "All required mount options are already set for /home"
fi

echo "Remediation complete."