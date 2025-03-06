#!/usr/bin/env bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Module parameters
MODULE_NAME="hfs"
MODULE_TYPE="fs"

# Function to handle module configuration
configure_module() {
    local module_name="$1"
    local changes_made=false

    # Check if module is loaded
    if lsmod | grep "$module_name" &> /dev/null; then
        echo -e "${RED}Module '$module_name' is loaded - unloading...${NC}"
        modprobe -r "$module_name" 2>/dev/null
        rmmod "$module_name" 2>/dev/null
        changes_made=true
    fi

    # Check and set module to false
    if ! modprobe --showconfig | grep -q "install $module_name /bin/false"; then
        echo "install $module_name /bin/false" >> "/etc/modprobe.d/${module_name}.conf"
        changes_made=true
    fi

    # Check and blacklist module
    if ! modprobe --showconfig | grep -q "blacklist $module_name"; then
        echo "blacklist $module_name" >> "/etc/modprobe.d/${module_name}.conf"
        changes_made=true
    fi

    return $changes_made
}

# Main execution
main() {
    local module_path
    module_path="$(readlink -f /lib/modules/**/kernel/$MODULE_TYPE | sort -u)"
    local module_found=false

    echo "Checking module: $MODULE_NAME"

    for base_dir in $module_path; do
        if [ -d "$base_dir/${MODULE_NAME/-/\/}" ] && [ -n "$(ls -A "$base_dir/${MODULE_NAME/-/\/}")" ]; then
            echo "Module found in: $base_dir"
            module_found=true
            
            if configure_module "$MODULE_NAME"; then
                echo -e "${GREEN}Successfully configured module: $MODULE_NAME${NC}"
            else
                echo -e "${GREEN}No changes needed for module: $MODULE_NAME${NC}"
            fi
        fi
    done

    if ! $module_found; then
        echo -e "${RED}Module '$MODULE_NAME' not found in system${NC}"
        exit 1
    fi
}

# Run main function
main
