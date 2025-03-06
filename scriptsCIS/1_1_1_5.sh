#!/usr/bin/env bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to check module configuration
check_module_config() {
    local mod_name="$1"
    local mod_chk_name="${mod_name//-/_}"
    local showconfig
    local output=()
    local failures=()

    # Get module configuration
    mapfile -t showconfig < <(modprobe --showconfig | grep -P -- '\b(install|blacklist)\h+'"${mod_chk_name}"'\b')

    # Check if module is loaded
    if ! lsmod | grep "$mod_chk_name" &>
        else
            a_output2+=(" - kernel module: \"$l_mod_name\" is loaded")
        fi

        if grep -Pq -- '\binstall\h+'"${l_mod_chk_name//-/_}"'\h+(\/usr)?\/bin\/(true|false)\b' <<< "${a_showconfig[*]}"; then
            a_output+=(" - kernel module: \"$l_mod_name\" is not loadable")
        else
            a_output2+=(" - kernel module: \"$l_mod_name\" is loadable")
        fi

        if grep -Pq -- '\bblacklist\h+'"${l_mod_chk_name//-/_}"'\b' <<< "${a_showconfig[*]}"; then
            a_output+=(" - kernel module: \"$l_mod_name\" is deny listed")
        else
            a_output2+=(" - kernel module: \"$l_mod_name\" is not deny listed")
        fi
    }

    for l_mod_base_directory in $l_mod_path; do
        if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A "$l_mod_base_directory/${l_mod_name/-/\/}")" ]; then
            a_output3+=(" - \"$l_mod_base_directory\"")
            l_mod_chk_name="$l_mod_name"
            [[ "$l_mod_name" =~ overlay ]] && l_mod_chk_name="${l_mod_name::-2}"
            [ "$l_dl" != "y" ] && f_module_chk
        else
            a_output+=(" - kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\"")
        fi
    done

    [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "" " -- INFO --" " - module: \"$l_mod_name\" exists in:" "${a_output3[@]}"

    if [ "${#a_output2[@]}" -le 0 ]; then
        printf '\n%s\n' "- Audit Result:"
        printf "${GREEN} ** PASS ** ${NC}\n"
        printf '%s\n' "${a_output[@]}"
    else
        printf '\n%s\n' "- Audit Result:"
        printf "${RED} ** FAIL ** ${NC}\n"
        printf '%s\n' " - Reason(s) for audit failure:" "${a_output2[@]}"
        [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:" "${a_output[@]}"
    fi
}