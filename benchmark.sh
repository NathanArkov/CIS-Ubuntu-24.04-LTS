#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
answer="null"

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
    answer="null"
    local module_name=$1
    local module_type=$2
    # Audit
    if lsmod | grep -q "$module_name"; then
        echo "Kernel module $module_name is loaded."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            modprobe -r "$module_name" 2>/dev/null
            rmmod "$module_name" 2>/dev/null
            echo "Kernel module $module_name has been unloaded."
        fi
    else
        echo "Kernel module $module_name is not loaded."
    fi
    # Check if the module is blacklisted
    if ! grep -q "blacklist $module_name" /etc/modprobe.d/*.conf; then
        echo "Kernel module $module_name is not blacklisted."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "blacklist $module_name" | tee -a /etc/modprobe.d/disable-unused.conf
            echo "Kernel module $module_name has been blacklisted."
        fi
    else
        echo "Kernel module $module_name is already blacklisted."
    fi
    # Check if the module is set to not load
    if ! grep -q "install $module_name /bin/false" /etc/modprobe.d/*.conf; then
        echo "Kernel module $module_name is not set to not load."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "install $module_name /bin/false" | tee -a /etc/modprobe.d/disable-unused.conf
            echo "Kernel module $module_name has been set to not load."
        fi
    else
        echo "Kernel module $module_name is already set to not load."
    fi
}

check_filesystem_option() {
    answer="null"
    local mount_point=$1
    local option=$2
    # Audit
    if ! findmnt -kn "$mount_point" | grep -q "$option"; then
        echo "Option $option is not set on $mount_point."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            local device=$(findmnt -kn "$mount_point" -o SOURCE)
            local fstype=$(findmnt -kn "$mount_point" -o FSTYPE)
            local options=$(findmnt -kn "$mount_point" -o OPTIONS)
            sed -i "/$mount_point/d" /etc/fstab
            echo "$device $mount_point $fstype defaults,$options,$option 0 0" | tee -a /etc/fstab
            mount -o remount "$mount_point"
            echo "Option $option has been set on $mount_point."
        fi
    else
        echo "Option $option is already set on $mount_point."
    fi
}

audit_remediate_var_log_audit_partition() {
    answer="null"
    # Audit
    if findmnt -kn /var/log/audit &>/dev/null; then
        echo "/var/log/audit is mounted on a separate partition."
    else
        echo "/var/log/audit is NOT mounted on a separate partition."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Please manually create a separate partition for /var/log/audit and update /etc/fstab."
        fi
    fi
}

audit_remediate_var_log_partition() {
    answer="null"
    # Audit
    if findmnt -kn /var/log &>/dev/null; then
        echo "/var/log is mounted on a separate partition."
    else
        echo "/var/log is NOT mounted on a separate partition."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Please manually create a separate partition for /var/log and update /etc/fstab."
        fi
    fi
}

audit_remediate_var_tmp_partition() {
    answer="null"
    # Audit
    if findmnt -kn /var/tmp &>/dev/null; then
        echo "/var/tmp is mounted on a separate partition."
    else
        echo "/var/tmp is NOT mounted on a separate partition."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Please manually create a separate partition for /var/tmp and update /etc/fstab."
        fi
    fi
}

audit_remediate_gpg_keys() {
    answer="null"
    # Audit
    if apt-key list &>/dev/null; then
        echo "GPG keys are configured."
    else
        echo "GPG keys are NOT configured."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Please manually configure GPG keys for your package manager."
        fi
    fi
}

audit_remediate_package_repositories() {
    answer="null"
    # Audit
    if apt-cache policy &>/dev/null; then
        echo "Package manager repositories are configured."
    else
        echo "Package manager repositories are NOT configured."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Please manually configure package manager repositories."
        fi
    fi
}

audit_remediate_updates() {
    answer="null"
    # Audit
    if apt update && apt -s upgrade &>/dev/null; then
        echo "System is up to date."
    else
        echo "System is NOT up to date."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            apt update && apt upgrade -y
            echo "System has been updated."
        fi
    fi
}

audit_remediate_apparmor_installed() {
    answer="null"
    # Audit
    if dpkg-query -s apparmor &>/dev/null; then
        echo "AppArmor is installed."
    else
        echo "AppArmor is NOT installed."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            apt install apparmor -y
            echo "AppArmor has been installed."
        fi
    fi
}

audit_remediate_apparmor_bootloader() {
    answer="null"
    # Audit
    if grep -q "apparmor=1" /boot/grub/grub.cfg; then
        echo "AppArmor is enabled in the bootloader configuration."
    else
        echo "AppArmor is NOT enabled in the bootloader configuration."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            sed -i '/GRUB_CMDLINE_LINUX=/s/\"/&apparmor=1 /' /etc/default/grub
            update-grub
            echo "AppArmor has been enabled in the bootloader configuration."
        fi
    fi
}

audit_remediate_apparmor_profiles() {
    answer="null"
    # Audit
    if apparmor_status | grep -q "enforce\\|complain"; then
        echo "All AppArmor profiles are in enforce or complain mode."
    else
        echo "Not all AppArmor profiles are in enforce or complain mode."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            aa-enforce /etc/apparmor.d/*
            echo "AppArmor profiles have been set to enforce mode."
        fi
    fi
}

audit_remediate_apparmor_enforce() {
    answer="null"
    # Audit
    if apparmor_status | grep -q "enforce"; then
        echo "All AppArmor profiles are enforcing."
    else
        echo "Not all AppArmor profiles are enforcing."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            aa-enforce /etc/apparmor.d/*
            echo "AppArmor profiles have been set to enforce mode."
        fi
    fi
}
audit_remediate_bootloader_password() {
    answer="null"
    # Audit
    if grep -q "^set superusers" /boot/grub/grub.cfg; then
        echo "Bootloader password is set."
    else
        echo "Bootloader password is NOT set."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Please manually set a bootloader password."
        fi
    fi
}

audit_remediate_bootloader_config() {
    answer="null"
    # Audit
    if stat -Lc "%a" /boot/grub/grub.cfg | grep -q "600"; then
        echo "Bootloader config access is configured correctly."
    else
        echo "Bootloader config access is NOT configured correctly."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            chown root:root /boot/grub/grub.cfg
            chmod 600 /boot/grub/grub.cfg
            echo "Bootloader config access has been configured."
        fi
    fi
}

audit_remediate_aslr() {
    answer="null"
    # Audit
    if sysctl kernel.randomize_va_space | grep -q "2"; then
        echo "Address space layout randomization (ASLR) is enabled."
    else
        echo "Address space layout randomization (ASLR) is NOT enabled."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
            sysctl -w kernel.randomize_va_space=2
            echo "ASLR has been enabled."
        fi
    fi
}

audit_remediate_ptrace_scope() {
    answer="null"
    # Audit
    if sysctl kernel.yama.ptrace_scope | grep -q "[1-3]"; then
        echo "ptrace_scope is restricted."
    else
        echo "ptrace_scope is NOT restricted."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
            sysctl -w kernel.yama.ptrace_scope=1
            echo "ptrace_scope has been restricted."
        fi
    fi
}

audit_remediate_core_dumps() {
    answer="null"
    # Audit
    if grep -q "hard core 0" /etc/security/limits.conf && sysctl fs.suid_dumpable | grep -q "0"; then
        echo "Core dumps are restricted."
    else
        echo "Core dumps are NOT restricted."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "* hard core 0" >> /etc/security/limits.conf
            echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
            sysctl -w fs.suid_dumpable=0
            echo "Core dumps have been restricted."
        fi
    fi
}

ensure_prelink_not_installed() {
    answer="null"
    # Audit
    if dpkg-query -s prelink &>/dev/null; then
        echo -e "\e[31mprelink is installed\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            prelink -ua
            apt purge prelink -y
            echo -e "\e[31mPrelink has been uninstalled and binaries restored to normal.\e[0m"
        fi
    else
        echo "prelink is not installed"
    fi
}

ensure_motd_configured_properly() {
    answer="null"
    # Audit
    if grep -E -i '(\v|\r|\m|\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/motd; then
        echo -e "\e[31mMessage of the day contains OS information\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > /etc/motd
            echo -e "\e[31mMessage of the day has been configured properly.\e[0m"
        fi
    else
        echo "Message of the day is configured properly"
    fi
}

ensure_remote_login_warning_banner_configured_properly() {
    answer="null"
    # Audit
    if grep -E -i '(\v|\r|\m|\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue.net; then
        echo -e "\e[31mRemote login warning banner contains OS information\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
            echo -e "\e[31mRemote login warning banner has been configured properly.\e[0m"
        fi
    else
        echo "Remote login warning banner is configured properly"
    fi
}

ensure_local_login_warning_banner_configured_properly() {
    answer="null"
    # Audit
    if grep -E -i '(\v|\r|\m|\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue; then
        echo -e "\e[31mLocal login warning banner contains OS information\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
            echo -e "\e[31mLocal login warning banner has been configured properly.\e[0m"
        fi
    else
        echo "Local login warning banner is configured properly"
    fi
}

audit_and_remediate_gdm_automount() {
    answer="null"
    # Audit
    automount=$(gsettings get org.gnome.desktop.media-handling automount)
    automount_open=$(gsettings get org.gnome.desktop.media-handling automount-open)
    if [ "$automount" = "false" ] && [ "$automount_open" = "false" ]; then
        echo "GDM automatic mounting of removable media is already disabled."
    else
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            gsettings set org.gnome.desktop.media-handling automount false
            gsettings set org.gnome.desktop.media-handling automount-open false
            echo -e "\e[31mGDM automatic mounting of removable media has been disabled. Please restart the system for changes to take effect.\e[0m"
        fi
    fi
}

audit_and_remediate_gdm_automount_lock() {
    answer="null"
    # Audit
    if grep -Psrilq "^\h*automount\h*=\h*false\b" /etc/dconf/db/local.d/locks/* && \
       grep -Psrilq "^\h*automount-open\h*=\h*false\b" /etc/dconf/db/local.d/locks/*; then
        echo "GDM automatic mounting of removable media is locked and set to false."
    else
        # Remediation
        read -p "Lock GDM auto mount ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            mkdir -p /etc/dconf/db/local.d/locks
            echo -e "[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false" > /etc/dconf/db/local.d/locks/00-media-automount
            dconf update
            echo -e "\e[31mGDM automatic mounting of removable media has been locked and set to false. Please log out and back in again for changes to take effect.\e[0m"
        fi
    fi
}
audit_and_remediate_gdm_autorun_never() {
    answer="null"
    # Audit
    autorun_never=$(gsettings get org.gnome.desktop.media-handling autorun-never)
    if [ "$autorun_never" = "true" ]; then
        echo "GDM autorun-never is already enabled."
    else
        # Remediation
        read -p "Activate GDM autorun-never ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            gsettings set org.gnome.desktop.media-handling autorun-never true
            echo -e "\e[31mGDM autorun-never has been enabled. Please restart the system for changes to take effect.\e[0m"
        fi
    fi
}

audit_and_remediate_xdmcp() {
    answer="null"
    # Audit
    if grep -Psil -- '^\h*\[xdmcp\]' /etc/{gdm3,gdm}/{custom,daemon}.conf | xargs -I{} awk '/\[xdmcp\]/{f=1;next}/\[/{f=0}f{if(/^\s*Enable\s*=\s*true/)print "The file: \""{}"\" includes: \""$0"\" in the \"[xdmcp]\" block"}' | grep -q 'Enable=true'; then
        # Remediation
        read -p "Disable XDMCP ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            grep -Psil -- '^\h*\[xdmcp\]' /etc/{gdm3,gdm}/{custom,daemon}.conf | xargs -I{} sed -i '/\[xdmcp\]/,/^\[/{s/^\s*Enable\s*=\s*true/#&/}' {}
            echo -e "\e[31mXDMCP has been disabled. Please restart the system for changes to take effect.\e[0m"
        fi
    else
        echo "XDMCP is not enabled."
    fi
}

audit_and_remediate_autofs() {
    answer="null"
    # Audit
    if dpkg-query -s autofs &>/dev/null; then
        echo "autofs is installed."
        if systemctl is-enabled autofs.service 2>/dev/null | grep -q 'enabled'; then
            echo "autofs.service is enabled."
            if systemctl is-active autofs.service 2>/dev/null | grep -q '^active'; then
                echo "autofs.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop autofs.service
                    systemctl mask autofs.service
                    echo -e "\e[31mautofs.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "autofs is not installed."
    fi
}

audit_and_remediate_avahi() {
    answer="null"
    # Audit
    if dpkg-query -s avahi-daemon &>/dev/null; then
        echo "avahi-daemon is installed."
        if systemctl is-enabled avahi-daemon.service 2>/dev/null | grep -q 'enabled'; then
            echo "avahi-daemon.service is enabled."
            if systemctl is-active avahi-daemon.service 2>/dev/null | grep -q '^active'; then
                echo "avahi-daemon.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop avahi-daemon.service
                    systemctl mask avahi-daemon.service
                    echo -e "\e[31mavahi-daemon.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "avahi-daemon is not installed."
    fi
}

audit_and_remediate_dhcp() {
    answer="null"
    # Audit
    if dpkg-query -s isc-dhcp-server &>/dev/null; then
        echo "isc-dhcp-server is installed."
        if systemctl is-enabled isc-dhcp-server.service 2>/dev/null | grep -q 'enabled'; then
            echo "isc-dhcp-server.service is enabled."
            if systemctl is-active isc-dhcp-server.service 2>/dev/null | grep -q '^active'; then
                echo "isc-dhcp-server.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop isc-dhcp-server.service
                    systemctl mask isc-dhcp-server.service
                    echo -e "\e[31misc-dhcp-server.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "isc-dhcp-server is not installed."
    fi
}

audit_and_remediate_dns() {
    answer="null"
    # Audit
    if dpkg-query -s bind9 &>/dev/null; then
        echo "bind9 is installed."
        if systemctl is-enabled named.service 2>/dev/null | grep -q 'enabled'; then
            echo "named.service is enabled."
            if systemctl is-active named.service 2>/dev/null | grep -q '^active'; then
                echo "named.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop named.service
                    systemctl mask named.service
                    echo -e "\e[31mnamed.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "bind9 is not installed."
    fi
}

audit_and_remediate_dnsmasq() {
    answer="null"
    # Audit
    if dpkg-query -s dnsmasq &>/dev/null; then
        echo "dnsmasq is installed."
        if systemctl is-enabled dnsmasq.service 2>/dev/null | grep -q 'enabled'; then
            echo "dnsmasq.service is enabled."
            if systemctl is-active dnsmasq.service 2>/dev/null | grep -q '^active'; then
                echo "dnsmasq.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop dnsmasq.service
                    systemctl mask dnsmasq.service
                    echo -e "\e[31mdnsmasq.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "dnsmasq is not installed."
    fi
}

audit_and_remediate_ftp() {
    answer="null"
    # Audit
    if dpkg-query -s vsftpd &>/dev/null; then
        echo "vsftpd is installed."
        if systemctl is-enabled vsftpd.service 2>/dev/null | grep -q 'enabled'; then
            echo "vsftpd.service is enabled."
            if systemctl is-active vsftpd.service 2>/dev/null | grep -q '^active'; then
                echo "vsftpd.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop vsftpd.service
                    systemctl mask vsftpd.service
                    echo -e "\e[31mvsftpd.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "vsftpd is not installed."
    fi
}

audit_and_remediate_ldap() {
    answer="null"
    # Audit
    if dpkg-query -s slapd &>/dev/null; then
        echo "slapd is installed."
        if systemctl is-enabled slapd.service 2>/dev/null | grep -q 'enabled'; then
            echo "slapd.service is enabled."
            if systemctl is-active slapd.service 2>/dev/null | grep -q '^active'; then
                echo "slapd.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop slapd.service
                    systemctl mask slapd.service
                    echo -e "\e[31mslapd.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "slapd is not installed."
    fi
}
audit_and_remediate_message_access() {
    answer="null"
    # Audit
    if dpkg-query -s dovecot-imapd &>/dev/null; then
        echo "dovecot-imapd is installed."
        if systemctl is-enabled dovecot.service 2>/dev/null | grep -q 'enabled'; then
            echo "dovecot.service is enabled."
            if systemctl is-active dovecot.service 2>/dev/null | grep -q '^active'; then
                echo "dovecot.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop dovecot.service
                    systemctl mask dovecot.service
                    echo -e "\e[31mdovecot.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "dovecot-imapd is not installed."
    fi
}

audit_and_remediate_nfs() {
    answer="null"
    # Audit
    if dpkg-query -s nfs-kernel-server &>/dev/null; then
        echo "nfs-kernel-server is installed."
        if systemctl is-enabled nfs-server.service 2>/dev/null | grep -q 'enabled'; then
            echo "nfs-server.service is enabled."
            if systemctl is-active nfs-server.service 2>/dev/null | grep -q '^active'; then
                echo "nfs-server.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop nfs-server.service
                    systemctl mask nfs-server.service
                    echo -e "\e[31mnfs-server.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "nfs-kernel-server is not installed."
    fi
}

audit_and_remediate_nis() {
    answer="null"
    # Audit
    if dpkg-query -s ypserv &>/dev/null; then
        echo "ypserv is installed."
        if systemctl is-enabled ypserv.service 2>/dev/null | grep -q 'enabled'; then
            echo "ypserv.service is enabled."
            if systemctl is-active ypserv.service 2>/dev/null | grep -q '^active'; then
                echo "ypserv.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop ypserv.service
                    systemctl mask ypserv.service
                    echo -e "\e[31mypserv.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "ypserv is not installed."
    fi
}

audit_and_remediate_print_server() {
    answer="null"
    # Audit
    if dpkg-query -s cups &>/dev/null; then
        echo "cups is installed."
        if systemctl is-enabled cups.service 2>/dev/null | grep -q 'enabled'; then
            echo "cups.service is enabled."
            if systemctl is-active cups.service 2>/dev/null | grep -q '^active'; then
                echo "cups.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop cups.service
                    systemctl mask cups.service
                    echo -e "\e[31mcups.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "cups is not installed."
    fi
}

audit_and_remediate_rpcbind() {
    answer="null"
    # Audit
    if dpkg-query -s rpcbind &>/dev/null; then
        echo "rpcbind is installed."
        if systemctl is-enabled rpcbind.service 2>/dev/null | grep -q 'enabled'; then
            echo "rpcbind.service is enabled."
            if systemctl is-active rpcbind.service 2>/dev/null | grep -q '^active'; then
                echo "rpcbind.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop rpcbind.service
                    systemctl mask rpcbind.service
                    echo -e "\e[31mrpcbind.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "rpcbind is not installed."
    fi
}

audit_and_remediate_samba() {
    answer="null"
    # Audit
    if dpkg-query -s samba &>/dev/null; then
        echo "samba is installed."
        if systemctl is-enabled smbd.service 2>/dev/null | grep -q 'enabled'; then
            echo "smbd.service is enabled."
            if systemctl is-active smbd.service 2>/dev/null | grep -q '^active'; then
                echo "smbd.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop smbd.service
                    systemctl mask smbd.service
                    echo -e "\e[31msmbd.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "samba is not installed."
    fi
}

audit_and_remediate_rsync() {
    answer="null"
    # Audit
    if dpkg-query -s rsync &>/dev/null; then
        echo "rsync is installed."
        if systemctl is-enabled rsync.service 2>/dev/null | grep -q 'enabled'; then
            echo "rsync.service is enabled."
            if systemctl is-active rsync.service 2>/dev/null | grep -q '^active'; then
                echo "rsync.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop rsync.service
                    systemctl mask rsync.service
                    echo -e "\e[31mrsync.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "rsync is not installed."
    fi
}

audit_and_remediate_snmp() {
    answer="null"
    # Audit
    if dpkg-query -s snmpd &>/dev/null; then
        echo "snmpd is installed."
        if systemctl is-enabled snmpd.service 2>/dev/null | grep -q 'enabled'; then
            echo "snmpd.service is enabled."
            if systemctl is-active snmpd.service 2>/dev/null | grep -q '^active'; then
                echo "snmpd.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop snmpd.service
                    systemctl mask snmpd.service
                    echo -e "\e[31msnmpd.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "snmpd is not installed."
    fi
}

audit_and_remediate_tftp() {
    answer="null"
    # Audit
    if dpkg-query -s tftpd-hpa &>/dev/null; then
        echo "tftpd-hpa is installed."
        if systemctl is-enabled tftpd-hpa.service 2>/dev/null | grep -q 'enabled'; then
            echo "tftpd-hpa.service is enabled."
            if systemctl is-active tftpd-hpa.service 2>/dev/null | grep -q '^active'; then
                echo "tftpd-hpa.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop tftpd-hpa.service
                    systemctl mask tftpd-hpa.service
                    echo -e "\e[31mtftpd-hpa.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "tftpd-hpa is not installed."
    fi
}
audit_and_remediate_web_proxy() {
    answer="null"
    # Audit
    if dpkg-query -s squid &>/dev/null; then
        echo "squid is installed."
        if systemctl is-enabled squid.service 2>/dev/null | grep -q 'enabled'; then
            echo "squid.service is enabled."
            if systemctl is-active squid.service 2>/dev/null | grep -q '^active'; then
                echo "squid.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop squid.service
                    systemctl mask squid.service
                    echo -e "\e[31msquid.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "squid is not installed."
    fi
}

audit_and_remediate_web_server() {
    answer="null"
    # Audit
    if dpkg-query -s apache2 &>/dev/null; then
        echo "apache2 is installed."
        if systemctl is-enabled apache2.service 2>/dev/null | grep -q 'enabled'; then
            echo "apache2.service is enabled."
            if systemctl is-active apache2.service 2>/dev/null | grep -q '^active'; then
                echo "apache2.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop apache2.service
                    systemctl mask apache2.service
                    echo -e "\e[31mapache2.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "apache2 is not installed."
    fi
    if dpkg-query -s nginx &>/dev/null; then
        echo "nginx is installed."
        if systemctl is-enabled nginx.service 2>/dev/null | grep -q 'enabled'; then
            echo "nginx.service is enabled."
            if systemctl is-active nginx.service 2>/dev/null | grep -q '^active'; then
                echo "nginx.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop nginx.service
                    systemctl mask nginx.service
                    echo -e "\e[31mnginx.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "nginx is not installed."
    fi
}

audit_and_remediate_xinetd() {
    answer="null"
    # Audit
    if dpkg-query -s xinetd &>/dev/null; then
        echo "xinetd is installed."
        if systemctl is-enabled xinetd.service 2>/dev/null | grep -q 'enabled'; then
            echo "xinetd.service is enabled."
            if systemctl is-active xinetd.service 2>/dev/null | grep -q '^active'; then
                echo "xinetd.service is active."
                # Remediation
                read -p "Remediate to this problem ? (Y/N)" answer
                if [ "$answer" = "Y" ]; then
                    systemctl stop xinetd.service
                    systemctl mask xinetd.service
                    echo -e "\e[31mxinetd.service has been stopped and masked.\e[0m"
                fi
            fi
        fi
    else
        echo "xinetd is not installed."
    fi
}


audit_and_remediate_x_window() {
    answer="null"
    # Audit
    if dpkg-query -s xserver-common &>/dev/null; then
        echo "xserver-common is installed. This is a potential security risk."
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
        apt purge xserver-common -y
        echo -e "\e[31mxserver-common has been removed.\e[0m"
        fi
    else
        echo "xserver-common is not installed."
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

    audit_remediate_var_log_audit_partition
    audit_remediate_var_log_partition
    audit_remediate_var_tmp_partition
    audit_remediate_gpg_keys
    audit_remediate_package_repositories
    audit_remediate_updates
    audit_remediate_apparmor_installed
    audit_remediate_apparmor_bootloader
    audit_remediate_apparmor_profiles
    audit_remediate_apparmor_enforce
    audit_remediate_bootloader_password
    audit_remediate_bootloader_config
    audit_remediate_aslr
    audit_remediate_ptrace_scope
    audit_remediate_core_dumps
    ensure_prelink_not_installed
    ensure_motd_configured_properly
    ensure_remote_login_warning_banner_configured_properly
    ensure_local_login_warning_banner_configured_properly
    audit_and_remediate_gdm_automount
    audit_and_remediate_gdm_automount_lock
    audit_and_remediate_gdm_autorun_never
    audit_and_remediate_xdmcp
    audit_and_remediate_autofs
    audit_and_remediate_avahi
    audit_and_remediate_dhcp
    audit_and_remediate_dns
    audit_and_remediate_dnsmasq
    audit_and_remediate_ftp
    audit_and_remediate_ldap
    audit_and_remediate_message_access
    audit_and_remediate_nfs
    audit_and_remediate_nis
    audit_and_remediate_print_server
    audit_and_remediate_rpcbind
    audit_and_remediate_samba
    audit_and_remediate_rsync
    audit_and_remediate_snmp
    audit_and_remediate_tftp
    audit_and_remediate_web_proxy
    audit_and_remediate_web_server
    audit_and_remediate_xinetd
    audit_and_remediate_x_window

    


    
    print_header "Benchmark Complete"
}

# Execute main function
main