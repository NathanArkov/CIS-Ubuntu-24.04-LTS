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
        echo -e "[RISK] \e[31mKernel module $module_name is loaded.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            modprobe -r "$module_name" 2>/dev/null
            rmmod "$module_name" 2>/dev/null
            print_success "Kernel module $module_name has been unloaded."
        fi
    else
        print_success "Kernel module $module_name is not loaded."
    fi
    # Check if the module is blacklisted
    if ! grep -q "blacklist $module_name" /etc/modprobe.d/*.conf; then
        echo -e "[RISK] \e[31mKernel module $module_name is not blacklisted.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "blacklist $module_name" | tee -a /etc/modprobe.d/disable-unused.conf
            print_success "Kernel module $module_name has been blacklisted."
        fi
    else
        print_success "Kernel module $module_name is already blacklisted."
    fi
    # Check if the module is set to not load
    if ! grep -q "install $module_name /bin/false" /etc/modprobe.d/*.conf; then
        echo -e "[RISK] \e[31mKernel module $module_name is not set to not load.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "install $module_name /bin/false" | tee -a /etc/modprobe.d/disable-unused.conf
            print_success "Kernel module $module_name has been set to not load."
        fi
    else
        print_success "Kernel module $module_name is already set to not load."
    fi
}

check_filesystem_option() {
    answer="null"
    local mount_point=$1
    local option=$2
    # Audit
    if ! findmnt -kn "$mount_point" | grep -q "$option"; then
        echo -e "[RISK] \e[31mOption $option is not set on $mount_point.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            local device=$(findmnt -kn "$mount_point" -o SOURCE)
            local fstype=$(findmnt -kn "$mount_point" -o FSTYPE)
            local options=$(findmnt -kn "$mount_point" -o OPTIONS)
            sed -i "/$mount_point/d" /etc/fstab
            echo "$device $mount_point $fstype defaults,$options,$option 0 0" | tee -a /etc/fstab
            mount -o remount "$mount_point"
            print_success "Option $option has been set on $mount_point."
        fi
    else
        print_success "Option $option is already set on $mount_point."
    fi
}

audit_remediate_var_log_audit_partition() {
    answer="null"
    # Audit
    if findmnt -kn /var/log/audit &>/dev/null; then
        print_success "/var/log/audit is mounted on a separate partition."
    else
        echo -e "[RISK] \e[31m/var/log/audit is NOT mounted on a separate partition.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            print_success "Please manually create a separate partition for /var/log/audit and update /etc/fstab."
        fi
    fi
}

audit_remediate_var_log_partition() {
    answer="null"
    # Audit
    if findmnt -kn /var/log &>/dev/null; then
        print_success "/var/log is mounted on a separate partition."
    else
        echo -e "[RISK] \e[31m/var/log is NOT mounted on a separate partition.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            print_success "Please manually create a separate partition for /var/log and update /etc/fstab."
        fi
    fi
}

audit_remediate_var_tmp_partition() {
    answer="null"
    # Audit
    if findmnt -kn /var/tmp &>/dev/null; then
        print_success "/var/tmp is mounted on a separate partition."
    else
        echo -e "[RISK] \e[31m/var/tmp is NOT mounted on a separate partition.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            print_success "Please manually create a separate partition for /var/tmp and update /etc/fstab."
        fi
    fi
}

audit_remediate_gpg_keys() {
    answer="null"
    # Audit
    if apt-key list &>/dev/null; then
        print_success "GPG keys are configured."
    else
        echo -e "[RISK] \e[31mGPG keys are NOT configured.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            print_success "Please manually configure GPG keys for your package manager."
        fi
    fi
}

audit_remediate_package_repositories() {
    answer="null"
    # Audit
    if apt-cache policy &>/dev/null; then
        print_success "Package manager repositories are configured."
    else
        echo -e "[RISK] \e[31mPackage manager repositories are NOT configured.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            print_success "Please manually configure package manager repositories."
        fi
    fi
}

audit_remediate_updates() {
    answer="null"
    # Audit
    if apt update && apt -s upgrade &>/dev/null; then
        print_success "System is up to date."
    else
        echo -e "[RISK] \e[31mSystem is NOT up to date.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            apt update && apt upgrade -y
            print_success "System has been updated."
        fi
    fi
}

audit_remediate_apparmor_installed() {
    answer="null"
    # Audit
    if dpkg-query -s apparmor &>/dev/null; then
        print_success "AppArmor is installed."
    else
        echo -e "[RISK] \e[31mAppArmor is NOT installed.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            apt install apparmor -y
            print_success "AppArmor has been installed."
        fi
    fi
}

audit_remediate_apparmor_bootloader() {
    answer="null"
    # Audit
    if grep -q "apparmor=1" /boot/grub/grub.cfg; then
        print_success "AppArmor is enabled in the bootloader configuration."
    else
        echo -e "[RISK] \e[31mAppArmor is NOT enabled in the bootloader configuration.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            sed -i '/GRUB_CMDLINE_LINUX=/s/\"/&apparmor=1 /' /etc/default/grub
            update-grub
            print_success "AppArmor has been enabled in the bootloader configuration."
        fi
    fi
}

audit_remediate_apparmor_profiles() {
    answer="null"
    # Audit
    if apparmor_status | grep -q "enforce\\|complain"; then
        print_success "All AppArmor profiles are in enforce or complain mode."
    else
        echo -e "[RISK] \e[31mNot all AppArmor profiles are in enforce or complain mode.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            aa-enforce /etc/apparmor.d/*
            print_success "AppArmor profiles have been set to enforce mode."
        fi
    fi
}

audit_remediate_apparmor_enforce() {
    answer="null"
    # Audit
    if apparmor_status | grep -q "enforce"; then
        print_success "All AppArmor profiles are enforcing."
    else
        echo -e "[RISK] \e[31mNot all AppArmor profiles are enforcing.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            aa-enforce /etc/apparmor.d/*
            print_success "AppArmor profiles have been set to enforce mode."
        fi
    fi
}
audit_remediate_bootloader_password() {
    answer="null"
    # Audit
    if grep -q "^set superusers" /boot/grub/grub.cfg; then
        print_success "Bootloader password is set."
    else
        echo -e "[RISK] \e[31mBootloader password is NOT set.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            print_success "Please manually set a bootloader password."
        fi
    fi
}

audit_remediate_bootloader_config() {
    answer="null"
    # Audit
    if stat -Lc "%a" /boot/grub/grub.cfg | grep -q "600"; then
        print_success "Bootloader config access is configured correctly."
    else
        echo -e "[RISK] \e[31mBootloader config access is NOT configured correctly.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            chown root:root /boot/grub/grub.cfg
            chmod 600 /boot/grub/grub.cfg
            print_success "Bootloader config access has been configured."
        fi
    fi
}

audit_remediate_aslr() {
    answer="null"
    # Audit
    if sysctl kernel.randomize_va_space | grep -q "2"; then
        print_success "Address space layout randomization (ASLR) is enabled."
    else
        echo -e "[RISK] \e[31mAddress space layout randomization (ASLR) is NOT enabled.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
            sysctl -w kernel.randomize_va_space=2
            print_success "ASLR has been enabled."
        fi
    fi
}

audit_remediate_ptrace_scope() {
    answer="null"
    # Audit
    if sysctl kernel.yama.ptrace_scope | grep -q "[1-3]"; then
        print_success "ptrace_scope is restricted."
    else
        echo -e "[RISK] \e[31mptrace_scope is NOT restricted.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
            sysctl -w kernel.yama.ptrace_scope=1
            print_success "ptrace_scope has been restricted."
        fi
    fi
}

audit_remediate_core_dumps() {
    answer="null"
    # Audit
    if grep -q "hard core 0" /etc/security/limits.conf && sysctl fs.suid_dumpable | grep -q "0"; then
        print_success "Core dumps are restricted."
    else
        echo -e "[RISK] \e[31mCore dumps are NOT restricted.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "* hard core 0" >> /etc/security/limits.conf
            echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
            sysctl -w fs.suid_dumpable=0
            print_success "Core dumps have been restricted."
        fi
    fi
}

ensure_prelink_not_installed() {
    answer="null"
    # Audit
    if dpkg-query -s prelink &>/dev/null; then
        echo -e "[RISK] \e[31mprelink is installed\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            prelink -ua
            apt purge prelink -y
            echo -e "\e[31mPrelink has been uninstalled and binaries restored to normal.\e[0m"
        fi
    else
        print_success "prelink is not installed"
    fi
}

ensure_motd_configured_properly() {
    answer="null"
    # Audit
    if grep -E -i '(\v|\r|\m|\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/motd; then
        echo -e "[RISK] \e[31mMessage of the day contains OS information\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > /etc/motd
            echo -e "\e[31mMessage of the day has been configured properly.\e[0m"
        fi
    else
        print_success "Message of the day is configured properly"
    fi
}

ensure_remote_login_warning_banner_configured_properly() {
    answer="null"
    # Audit
    if grep -E -i '(\v|\r|\m|\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue.net; then
        echo -e "[RISK] \e[31mRemote login warning banner contains OS information\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
            echo -e "\e[31mRemote login warning banner has been configured properly.\e[0m"
        fi
    else
        print_success "Remote login warning banner is configured properly"
    fi
}

ensure_local_login_warning_banner_configured_properly() {
    answer="null"
    # Audit
    if grep -E -i '(\v|\r|\m|\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue; then
        echo -e "[RISK] \e[31mLocal login warning banner contains OS information\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
            echo -e "\e[31mLocal login warning banner has been configured properly.\e[0m"
        fi
    else
        print_success "Local login warning banner is configured properly"
    fi
}

audit_and_remediate_gdm_automount() {
    answer="null"
    # Audit
    automount=$(gsettings get org.gnome.desktop.media-handling automount)
    automount_open=$(gsettings get org.gnome.desktop.media-handling automount-open)
    if [ "$automount" = "false" ] && [ "$automount_open" = "false" ]; then
        print_success "GDM automatic mounting of removable media is already disabled."
    else
        echo -e "[RISK] \e[31mGDM automatic mounting of removable media is enabled.\e[0m"
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
        print_success "GDM automatic mounting of removable media is locked and set to false."
    else
        echo -e "[RISK] \e[31mGDM automatic mounting of removable media is not locked.\e[0m"
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
        print_success "GDM autorun-never is already enabled."
    else
        echo -e "[RISK] \e[31mGDM autorun-never is not enabled.\e[0m"
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
        echo -e "[RISK] \e[31mXDMCP is enabled.\e[0m"
        # Remediation
        read -p "Disable XDMCP ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            grep -Psil -- '^\h*\[xdmcp\]' /etc/{gdm3,gdm}/{custom,daemon}.conf | xargs -I{} sed -i '/\[xdmcp\]/,/^\[/{s/^\s*Enable\s*=\s*true/#&/}' {}
            echo -e "\e[31mXDMCP has been disabled. Please restart the system for changes to take effect.\e[0m"
        fi
    else
        print_success "XDMCP is not enabled."
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
                echo -e "[RISK] \e[31mautofs.service is active.\e[0m"
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
        print_success "autofs is not installed."
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
                echo -e "[RISK] \e[31mavahi-daemon.service is active.\e[0m"
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
        print_success "avahi-daemon is not installed."
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
                echo -e "[RISK] \e[31misc-dhcp-server.service is active.\e[0m"
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
        print_success "isc-dhcp-server is not installed."
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
                echo -e "[RISK] \e[31mnamed.service is active.\e[0m"
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
        print_success "bind9 is not installed."
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
                echo -e "[RISK] \e[31mdnsmasq.service is active.\e[0m"
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
        print_success "dnsmasq is not installed."
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
                echo -e "[RISK] \e[31mvsftpd.service is active.\e[0m"
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
        print_success "vsftpd is not installed."
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
                echo -e "[RISK] \e[31mslapd.service is active.\e[0m"
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
        print_success "slapd is not installed."
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
                echo -e "[RISK] \e[31mdovecot.service is active.\e[0m"
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
        print_success "dovecot-imapd is not installed."
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
                echo -e "[RISK] \e[31mnfs-server.service is active.\e[0m"
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
        print_success "nfs-kernel-server is not installed."
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
                echo -e "[RISK] \e[31mypserv.service is active.\e[0m"
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
        print_success "ypserv is not installed."
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
                echo -e "[RISK] \e[31mcups.service is active.\e[0m"
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
        print_success "cups is not installed."
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
                echo -e "[RISK] \e[31mrpcbind.service is active.\e[0m"
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
        print_success "rpcbind is not installed."
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
                echo -e "[RISK] \e[31msmbd.service is active.\e[0m"
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
        print_success "samba is not installed."
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
                echo -e "[RISK] \e[31mrsync.service is active.\e[0m"
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
        print_success "rsync is not installed."
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
                echo -e "[RISK] \e[31msnmpd.service is active.\e[0m"
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
        print_success "snmpd is not installed."
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
                echo -e "[RISK] \e[31mtftpd-hpa.service is active.\e[0m"
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
        print_success "tftpd-hpa is not installed."
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
                echo -e "[RISK] \e[31msquid.service is active.\e[0m"
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
        print_success "squid is not installed."
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
                echo -e "[RISK] \e[31mapache2.service is active.\e[0m"
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
        print_success "apache2 is not installed."
    fi
    if dpkg-query -s nginx &>/dev/null; then
        echo "nginx is installed."
        if systemctl is-enabled nginx.service 2>/dev/null | grep -q 'enabled'; then
            echo "nginx.service is enabled."
            if systemctl is-active nginx.service 2>/dev/null | grep -q '^active'; then
                echo -e "[RISK] \e[31mnginx.service is active.\e[0m"
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
        print_success "nginx is not installed."
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
                echo -e "[RISK] \e[31mxinetd.service is active.\e[0m"
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
        print_success "xinetd is not installed."
    fi
}


audit_and_remediate_x_window() {
    answer="null"
    # Audit
    if dpkg-query -s xserver-common &>/dev/null; then
        echo -e "[RISK] \e[31mxserver-common is installed. This is a potential security risk.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
        apt purge xserver-common -y
        echo -e "\e[31mxserver-common has been removed.\e[0m"
        fi
    else
        print_success "xserver-common is not installed."
    fi
}

audit_and_remediate_ssh() {
    answer="null"  # mettre la variable answer à "null"
    
    # Vérifier si sshd est installé
    if ! command -v sshd &> /dev/null; then
       print_success "sshd is not installed."
        return 1
    fi

    # Audit
    clientaliveinterval=$(sshd -T | grep -Pi 'clientaliveinterval' | awk '{print $2}')
    clientalivecountmax=$(sshd -T | grep -Pi 'clientalivecountmax' | awk '{print $2}')
    
    if [ "$clientaliveinterval" -gt 0 ] && [ "$clientalivecountmax" -gt 0 ]; then
        print_success "ClientAliveInterval and ClientAliveCountMax are correctly configured."  # utiliser la fonction print_success pour afficher un message disant que la vulnérabilité n'est pas présente
    else
        echo -e "[RISK] \e[31mClientAliveInterval and/or ClientAliveCountMax are NOT correctly configured.\e[0m"  # utiliser echo -e "[RISK]" pour afficher un message en ROUGE pour signaler la vulnérabilité à l'utilisateur
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer  # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then  # si l'utilisateur entre "Y", alors
            echo "ClientAliveInterval 15" >> /etc/ssh/sshd_config
            echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config
            print_success "ClientAliveInterval and ClientAliveCountMax have been set in /etc/ssh/sshd_config."  # remédiation
        fi
    fi
}

audit_and_remediate_mta() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    a_output=(); a_output2=(); a_port_list=("25" "465" "587")
    for l_port_number in "${a_port_list[@]}"; do
        if ss -plntu | grep -P -- ':'"$l_port_number"'\b' | grep -Pvq -- '\h+(127\.0\.0\.1|\[?::1\]?):'"$l_port_number"'\b'; then
            a_output2+=(" - Port \"$l_port_number\" is listening on a non-loopback network interface")
        else
            a_output+=(" - Port \"$l_port_number\" is not listening on a non-loopback network interface")
        fi
    done
    if command -v postconf &> /dev/null; then
        l_interfaces="$(postconf -n inet_interfaces)"
    elif command -v exim &> /dev/null; then
        l_interfaces="$(exim -bP local_interfaces)"
    elif command -v sendmail &> /dev/null; then
        l_interfaces="$(grep -i "0 DaemonPortOptions=" /etc/mail/sendmail.cr | grep -oP '(?<=Addr=)[^,+]+')"
    fi
    if [ -n "$l_interfaces" ]; then
        if grep -Pqi '\ball\b' <<< "$l_interfaces"; then
            a_output2+=(" - MTA is bound to all network interfaces")
        elif ! grep -Pqi '(inet_interfaces\h*=\h*)?(0\.0\.0\.0|::1|loopback-only)' <<< "$l_interfaces"; then
            a_output2+=(" - MTA is bound to a network interface \"$l_interfaces\"")
        else
            a_output+=(" - MTA is not bound to a non loopback network interface \"$l_interfaces\"")
        fi
    else
        a_output+=(" - MTA not detected or in use")
    fi
    if [ "${#a_output2[@]}" -le 0 ]; then
        print_success "MTA is not listening on any non-loopback network interface."
    else
        echo -e "[RISK] \e[31mMTA is listening on a non-loopback network interface.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            if command -v postconf &> /dev/null; then
                sed -i '/^inet_interfaces/ s/=.*/= loopback-only/' /etc/postfix/main.cf
                systemctl restart postfix
                print_success "Postfix configuration updated and service restarted."
            else
                echo -e "[RISK] \e[31mManual remediation required for non-Postfix MTA.\e[0m"
            fi
        fi
    fi
}

audit_and_remediate_nis_2() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if dpkg-query -s nis &>/dev/null; then
        echo -e "[RISK] \e[31mnis is installed.\e[0m"  # utiliser echo -e "[RISK]" pour afficher un message en ROUGE pour signaler la vulnérabilité à l'utilisateur
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            apt purge nis -y
            print_success "nis has been uninstalled."   # remédiation
        fi
    else
        print_success "nis is not installed."  # utiliser la fonction print_success pour afficher un message disant que la vulnérabilité n'est pas vulnérable
    fi
}

audit_and_remediate_rsh_client() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if dpkg-query -s rsh-client &>/dev/null; then
        echo -e "[RISK] \e[31mrsh-client is installed.\e[0m"  # utiliser echo -e "[RISK]" pour afficher un message en ROUGE pour signaler la vulnérabilité à l'utilisateur
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            apt purge rsh-client -y
            print_success "rsh-client has been uninstalled."   # remédiation
        fi
    else
        print_success "rsh-client is not installed."  # utiliser la fonction print_success pour afficher un message disant que la vulnérabilité n'est pas vulnérable
    fi
}

audit_and_remediate_talk() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if dpkg-query -s talk &>/dev/null; then
        echo -e "[RISK] \e[31mtalk is installed.\e[0m"  # utiliser echo -e "[RISK]" pour afficher un message en ROUGE pour signaler la vulnérabilité à l'utilisateur
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            apt purge talk -y
            print_success "talk has been uninstalled."   # remédiation
        fi
    else
        print_success "talk is not installed."  # utiliser la fonction print_success pour afficher un message disant que la vulnérabilité n'est pas vulnérable
    fi
}

audit_and_remediate_telnet() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if dpkg-query -l | grep -E 'telnet|inetutils-telnet' &>/dev/null; then
        echo -e "[RISK] \e[31mtelnet or inetutils-telnet is installed.\e[0m"  # utiliser echo -e "[RISK]" pour afficher un message en ROUGE pour signaler la vulnérabilité à l'utilisateur
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            apt purge telnet -y
            apt purge inetutils-telnet -y
            print_success "telnet and inetutils-telnet have been uninstalled."   # remédiation
        fi
    else
        print_success "telnet and inetutils-telnet are not installed."  # utiliser la fonction print_success pour afficher un message disant que la vulnérabilité n'est pas vulnérable
    fi
}

audit_and_remediate_ldap_utils() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if dpkg-query -s ldap-utils &>/dev/null; then
        echo -e "[RISK] \e[31mldap-utils is installed.\e[0m"  # utiliser echo -e "[RISK]" pour afficher un message en ROUGE pour signaler la vulnérabilité à l'utilisateur
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            apt purge ldap-utils -y
            print_success "ldap-utils has been uninstalled."   # remédiation
        fi
    else
        print_success "ldap-utils is not installed."  # utiliser la fonction print_success pour afficher un message disant que la vulnérabilité n'est pas vulnérable
    fi
}

audit_and_remediate_ftp() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if dpkg-query -l | grep -E 'ftp|tnftp' &>/dev/null; then
        echo -e "[RISK] \e[31mftp or tnftp is installed.\e[0m"  # utiliser echo -e "[RISK]" pour afficher un message en ROUGE pour signaler la vulnérabilité à l'utilisateur
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            apt purge ftp -y
            apt purge tnftp -y
            print_success "ftp and tnftp have been uninstalled."   # remédiation
        fi
    else
        print_success "ftp and tnftp are not installed."  # utiliser la fonction print_success pour afficher un message disant que la vulnérabilité n'est pas vulnérable
    fi
}

audit_and_remediate_time_sync() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    l_output="" l_output2=""
    service_not_enabled_chk() {
        l_out2=""
        if systemctl is-enabled "$l_service_name" 2>/dev/null | grep -q 'enabled'; then
            l_out2="$l_out2\n - Daemon: \"$l_service_name\" is enabled on the system"
        fi
        if systemctl is-active "$l_service_name" 2>/dev/null | grep -q '^active'; then
            l_out2="$l_out2\n - Daemon: \"$l_service_name\" is active on the system"
        fi
    }
    l_service_name="systemd-timesyncd.service" # Check systemd-timesyncd daemon
    service_not_enabled_chk
    if [ -n "$l_out2" ]; then
        l_timesyncd="y"
        l_out_tsd="$l_out2"
    else
        l_timesyncd="n"
        l_out_tsd="\n - Daemon: \"$l_service_name\" is not enabled and not active on the system"
    fi
    l_service_name="chrony.service" # Check chrony
    service_not_enabled_chk
    if [ -n "$l_out2" ]; then
        l_chrony="y"
        l_out_chrony="$l_out2"
    else
        l_chrony="n"
        l_out_chrony="\n - Daemon: \"$l_service_name\" is not enabled and not active on the system"
    fi
    l_status="$l_timesyncd$l_chrony"
    case "$l_status" in
        yy)
            l_output2=" - More than one time sync daemon is in use on the system$l_out_tsd$l_out_chrony"
            ;;
        nn)
            l_output2=" - No time sync daemon is in use on the system$l_out_tsd$l_out_chrony"
            ;;
        yn|ny)
            l_output=" - Only one time sync daemon is in use on the system$l_out_tsd$l_out_chrony"
            ;;
        *)
            l_output2=" - Unable to determine time sync daemon(s) status"
            ;;
    esac
    if [ -z "$l_output2" ]; then
        print_success "Only one time sync daemon is in use on the system."
    else
        echo -e "[RISK] \e[31m$l_output2\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            apt purge chrony -y
            apt autoremove chrony -y
            print_success "chrony has been uninstalled. Please configure systemd-timesyncd."
        fi
    fi
}

audit_and_remediate_ntp() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    a_output=(); a_output2=(); a_parlist=("NTP=[^#\n\r]+" "FallbackNTP=[^#\n\r]+")
    l_systemd_config_file="/etc/systemd/timesyncd.conf" # Main systemd configuration file
    f_config_file_parameter_chk() {
        unset A_out; declare -A A_out # Check config file(s) setting
        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_systemd_parameter="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" &&
                    A_out+=(["$l_systemd_parameter"]="$l_file")
                fi
            fi
        done < <("$l_systemdanalyze" cat-config "$l_systemd_config_file" | grep -Pio '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
                l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
                l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}"
                if grep -Piq "\b$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then
                    a_output+=(" - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"")
                else
                    a_output2+=(" - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value matching: \"$l_value_out\"")
                fi
            done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
        else
            a_output2+=(" - \"$l_systemd_parameter_name\" is not set in an included file *** Note: \"$l_systemd_parameter_name\" May be set in a file that's ignored by load procedure ***")
        fi
    }
    l_systemdanalyze="$(readlink -f /bin/systemd-analyze)"
    while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
        l_systemd_parameter_name="${l_systemd_parameter_name// /}"
        l_systemd_parameter_value="${l_systemd_parameter_value// /}"
        l_value_out="${l_systemd_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
        l_value_out="$(tr -d '(){}' <<< "$l_value_out")"
        f_config_file_parameter_chk
    done < <(printf '%s\n' "${a_parlist[@]}")
    if [ "${#a_output2[@]}" -le 0 ]; then
        print_success "NTP and FallbackNTP are correctly set to local site approved authoritative time server(s)."
    else
        echo -e "[RISK] \e[31m${a_output2[@]}\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer
        if [ "$answer" = "Y" ]; then
            a_settings=("NTP=time.nist.gov" "FallbackNTP=time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov")
            [ ! -d /etc/systemd/timesyncd.conf.d/ ] && mkdir /etc/systemd/timesyncd.conf.d/
            if grep -Psq -- '^\h*\[Time\]' /etc/systemd/timesyncd.conf.d/60-timesyncd.conf; then
                printf '%s\n' "" "${a_settings[@]}" >> /etc/systemd/timesyncd.conf.d/60-timesyncd.conf
            else
                printf '%s\n' "" "[Time]" "${a_settings[@]}" >> /etc/systemd/timesyncd.conf.d/60-timesyncd.conf
            fi
            systemctl reload-or-restart systemd-journald
            print_success "NTP and FallbackNTP parameters have been updated to local site approved authoritative time server(s)."
        fi
    fi
}

audit_and_remediate_systemd_timesyncd() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if systemctl is-enabled systemd-timesyncd.service &>/dev/null && systemctl is-active systemd-timesyncd.service &>/dev/null; then
        print_success "systemd-timesyncd.service is enabled and active."
    else
        echo -e "[RISK] \e[31msystemd-timesyncd.service is not enabled or not active.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            systemctl unmask systemd-timesyncd.service
            systemctl --now enable systemd-timesyncd.service
            print_success "systemd-timesyncd.service has been unmasked, enabled, and started."
        fi
    fi
}

audit_and_remediate_cron() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if systemctl list-unit-files | awk '$1~/^crond?\.service/{print $2}' | grep -q 'enabled' && systemctl list-units | awk '$1~/^crond?\.service/{print $3}' | grep -q 'active'; then
        print_success "cron service is enabled and active."
    else
        echo -e "[RISK] \e[31mcron service is not enabled or not active.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            systemctl unmask "$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $1}')"
            systemctl --now enable "$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $1}')"
            print_success "cron service has been unmasked, enabled, and started."
        fi
    fi
}

audit_and_remediate_crontab() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/crontab | grep -q 'Access: (600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)'; then
        print_success "/etc/crontab has correct permissions and ownership."
    else
        echo -e "[RISK] \e[31m/etc/crontab does not have correct permissions or ownership.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            chown root:root /etc/crontab
            chmod og-rwx /etc/crontab
            print_success "/etc/crontab ownership and permissions have been corrected."
        fi
    fi
}

audit_and_remediate_cron_hourly() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.hourly/ | grep -q 'Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'; then
        print_success "/etc/cron.hourly has correct permissions and ownership."
    else
        echo -e "[RISK] \e[31m/etc/cron.hourly does not have correct permissions or ownership.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            chown root:root /etc/cron.hourly/
            chmod og-rwx /etc/cron.hourly/
            print_success "/etc/cron.hourly ownership and permissions have been corrected."
        fi
    fi
}

audit_and_remediate_cron_daily() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.daily/ | grep -q 'Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'; then
        print_success "/etc/cron.daily has correct permissions and ownership."
    else
        echo -e "[RISK] \e[31m/etc/cron.daily does not have correct permissions or ownership.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            chown root:root /etc/cron.daily/
            chmod og-rwx /etc/cron.daily/
            print_success "/etc/cron.daily ownership and permissions have been corrected."
        fi
    fi
}

audit_and_remediate_cron_weekly() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.weekly/ | grep -q 'Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'; then
        print_success "/etc/cron.weekly has correct permissions and ownership."
    else
        echo -e "[RISK] \e[31m/etc/cron.weekly does not have correct permissions or ownership.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            chown root:root /etc/cron.weekly/
            chmod og-rwx /etc/cron.weekly/
            print_success "/etc/cron.weekly ownership and permissions have been corrected."
        fi
    fi
}

audit_and_remediate_cron_monthly() {
    answer="null"  # mettre la variable answer à "null"
    # Audit
    if stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.monthly/ | grep -q 'Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'; then
        print_success "/etc/cron.monthly has correct permissions and ownership."
    else
        echo -e "[RISK] \e[31m/etc/cron.monthly does not have correct permissions or ownership.\e[0m"
        # Remediation
        read -p "Remediate to this problem ? (Y/N)" answer    # on laisse le choix à l'utilisateur de remédier à la vulnérabilité ou non
        if [ "$answer" = "Y" ]; then   # si l'utilisateur entre "Y", alors 
            chown root:root /etc/cron.monthly/
            chmod og-rwx /etc/cron.monthly/
            print_success "/etc/cron.monthly ownership and permissions have been corrected."
        fi
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
    audit_and_remediate_ssh
    audit_and_remediate_mta
    audit_and_remediate_ntp
    audit_and_remediate_time_sync
    audit_and_remediate_systemd_timesyncd
    audit_and_remediate_ldap_utils
    audit_and_remediate_telnet
    audit_and_remediate_talk
    audit_and_remediate_rsh_client
    audit_and_remediate_nis_2
    audit_and_remediate_ntp
    audit_and_remediate_systemd_timesyncd
    audit_and_remediate_cron
    audit_and_remediate_crontab
    audit_and_remediate_cron_hourly
    audit_and_remediate_cron_daily
    audit_and_remediate_cron_weekly
    audit_and_remediate_cron_monthly
        


    
    print_header "Benchmark Complete"
}

# Execute main function
main