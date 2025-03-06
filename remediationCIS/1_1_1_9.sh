#!/usr/bin/env bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

{
    # Initialize variables
    a_output2=()
    a_output3=()
    l_dl=""
    l_mod_name="usb-storage"
    l_mod_type="drivers"
    l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
    
    f_module_fix() {
        l_dl="y"
        a_showconfig=()
        
        # Get module configuration
        while IFS= read -r l_showconfig; do
            a_showconfig+=("$l_showconfig")
        done < <(modprobe --showconfig | grep -P '\b(install|blacklist)\h+'"${l_mod_chk_name//-/_}"'\b')
        
        # Check if module is loaded and unload it
        if lsmod | grep "$l_mod_chk_name" &> /dev/null; then
            a_output2+=(" - unloading kernel module: \"$l_mod_name\"")
            modprobe -r "$l_mod_chk_name" 2>/dev/null
            rmmod "$l_mod_name" 2>/dev/null
        fi
        
        # Set module to false if not already set
        if ! grep -Pq -- '\binstall\h+'"${l_mod_chk_name//-/_}"'\h+(\/usr)?\/bin\/(true|false)\b' <<< "${a_showconfig[*]}"; then
            a_output2+=(" - setting kernel module: \"$l_mod_name\" to \"$(readlink -f /bin/false)\"")
            printf '%s\n' "install $l_mod_chk_name $(readlink -f /bin/false)" >> /etc/modprobe.d/"$l_mod_name".conf
        fi
        
        # Blacklist module if not already blacklisted
        if ! grep -Pq -- '\bblacklist\h+'"${l_mod_chk_name//-/_}"'\b' <<< "${a_showconfig[*]}"; then
            a_output2+=(" - denylisting kernel module: \"$l_mod_name\"")
            printf '%s\n' "blacklist $l_mod_chk_name" >> /etc/modprobe.d/"$l_mod_name".conf
        fi
    }
    
    # Main loop to check module directories
    for l_mod_base_directory in $l_mod_path; do
        if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A "$l_mod_base_directory/${l_mod_name/-/\/}")" ]; then
            a_output3+=(" - \"$l_mod_base_directory\"")
            l_mod_chk_name="$l_mod_name"
}