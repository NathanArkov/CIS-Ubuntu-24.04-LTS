#!/bin/bash

echo "Checking and remediating /var mount options..."

# Check if script is run with root privileges
if [ "$(id -u)" -ne 0 ]; then
	echo "[ERROR] This script must be run as root"
	exit 1
fi

# Check if /var is a mount point
if mountpoint -q /var; then
	echo "[INFO] /var is mounted on a separate partition"
	
	# Get current mount options and device
	device=$(mount | grep ' /var ' | awk '{print $1}')
	current_options=$(mount | grep ' /var ' | awk '{print $6}' | tr -d '()')
	
	# Initialize new options
	new_options=""
	
	# Add required options if missing
	for option in noexec nosuid nodev; do
		if ! echo "$current_options" | grep -q "$option"; then
			echo "[REMEDIATION] Adding $option option to /var"
			new_options="$new_options,$option"
		fi
	done
	
	# If changes are needed, update fstab and remount
	if [ ! -z "$new_options" ]; then
		# Backup fstab
		cp /etc/fstab /etc/fstab.backup
		
		# Update fstab with new options
		sed -i "s| /var | /var defaults$new_options |" /etc/fstab
		
		# Remount /var
		mount -o remount /var
		echo "[SUCCESS] Updated mount options for /var"
	else
		echo "[PASS] All required mount options are already set"
	fi
else
	echo "[FAIL] /var is not mounted on a separate partition"
	echo "[INFO] Manual intervention required to create separate partition for /var"
fi
