#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display section headers
print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# Function to display success messages
print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# Function to display error messages
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}



# Function to check and remediate kernel modules
check_kernel_module() {
    local module_name=$1
    local module_type=$2

    # Check if the module is loaded
    if lsmod | grep -q "$module_name"; then
        print_error "Kernel module $module_name is loaded."
        # Unload the module
        modprobe -r "$module_name" 2>/dev/null || rmmod "$module_name" 2>/dev/null
        print_success "Kernel module $module_name has been unloaded."
    else
        print_success "Kernel module $module_name is not loaded."
    fi

    # Check if the module is blacklisted
    if ! grep -q "blacklist $module_name" /etc/modprobe.d/*.conf; then
        print_error "Kernel module $module_name is not blacklisted."
        # Blacklist the module
        echo "blacklist $module_name" | tee -a /etc/modprobe.d/disable-unused.conf
        print_success "Kernel module $module_name has been blacklisted."
    else
        print_success "Kernel module $module_name is already blacklisted."
    fi

    # Check if the module is set to not load
    if ! grep -q "install $module_name /bin/false" /etc/modprobe.d/*.conf; then
        print_error "Kernel module $module_name is not set to not load."
        # Set the module to not load
        echo "install $module_name /bin/false" | tee -a /etc/modprobe.d/disable-unused.conf
        print_success "Kernel module $module_name has been set to not load."
    else
        print_success "Kernel module $module_name is already set to not load."
    fi
}

# Function to check and remediate filesystem options
check_filesystem_option() {
    local mount_point=$1
    local option=$2

    # Check if the option is set
    if ! findmnt -kn "$mount_point" | grep -q "$option"; then
        print_error "Option $option is not set on $mount_point."
        # Add the option to /etc/fstab
        local device=$(findmnt -kn "$mount_point" -o SOURCE)
        local fstype=$(findmnt -kn "$mount_point" -o FSTYPE)
        local options=$(findmnt -kn "$mount_point" -o OPTIONS)
        sed -i "/$mount_point/d" /etc/fstab
        echo "$device $mount_point $fstype defaults,$options,$option 0 0" | tee -a /etc/fstab
        mount -o remount "$mount_point"
        print_success "Option $option has been set on $mount_point."
    else
        print_success "Option $option is already set on $mount_point."
    fi
}

# Main execution
main() {
    print_header "Starting Security Benchmark"
    
        # Check and remediate kernel modules
    check_kernel_module "cramfs" "fs"
    check_kernel_module "freevxfs" "fs"
    check_kernel_module "hfs" "fs"
    check_kernel_module "hfsplus" "fs"
    check_kernel_module "jffs2" "fs"
    check_kernel_module "overlayfs" "fs"
    check_kernel_module "squashfs" "fs"
    check_kernel_module "udf" "fs"
    check_kernel_module "usb-storage" "drivers"

    # Check and remediate filesystem options
    check_filesystem_option "/tmp" "nodev"
    check_filesystem_option "/tmp" "nosuid"
    check_filesystem_option "/tmp" "noexec"
    check_filesystem_option "/dev/shm" "nodev"
    check_filesystem_option "/dev/shm" "nosuid"
    check_filesystem_option "/dev/shm" "noexec"
    check_filesystem_option "/home" "nodev"
    check_filesystem_option "/home" "nosuid"
    check_filesystem_option "/var" "nodev"
    check_filesystem_option "/var" "nosuid"
    check_filesystem_option "/var/tmp" "nodev"
    check_filesystem_option "/var/tmp" "nosuid"
    check_filesystem_option "/var/tmp" "noexec"
    check_filesystem_option "/var/log" "nodev"
    check_filesystem_option "/var/log" "nosuid"
    check_filesystem_option "/var/log" "noexec"
    check_filesystem_option "/var/log/audit" "nodev"
    check_filesystem_option "/var/log/audit" "nosuid"
    check_filesystem_option "/var/log/audit" "noexec"

    
    print_header "Benchmark Complete"
}

# Execute main function
main