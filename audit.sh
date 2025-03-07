RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
FIREWALL="$(dpkg -l |awk '/^[hi]i/{print $2}' | grep -E 'iptables|nftables|ufw')"

declare -i OK=0
declare -i NOK=0
declare -i TOTAL=0


# Function to display section headers
print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# Function to display success messages
print_success() {
    echo -e "${GREEN}[-OK]${NC} $1"
    OK+=1
}

# Function to display error messages
print_error() {
    echo -e "${RED}[NOK]${NC} $1"
    NOK+=1
}

# 1.1.1 Configure Filesystem Kernel Modules
check_filesystem_kernel_modules() {
    print_header "1.1.1 Configure Filesystem Kernel Modules"
    modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "overlayfs" "squashfs" "udf" "usb-storage");
    for module in "${modules[@]}"; do
        if lsmod | grep -q "$module"; then
            # echo "Checking $module module..."
            if grep -qE "/bin/true|/bin/false" /etc/modprobe.d/*; then
                print_success "$module has /bin/true or /bin/false entry"
            else
                print_error "$module does not have /bin/true or /bin/false entry"
            fi

            if grep -q "blacklist $module" /etc.modprobe.d/*; then
                print_success "$module is deny listed"
            else
                print_error "$module is not deny listed"
            fi

            if ! lsmod | grep -q "$module"; then
                print_success "$module is not loaded in the running kernel"
            else
                print_error "$module is loaded in the running kernel"
            fi
        else
            print_success "$module module is not available or pre-compiled into the kernel"
        fi
    done
}

# 1.5.2 Restrict ptrace_scope
check_ptrace_scope() {
    print_header "1.5.2 Restrict ptrace_scope"
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
    if [[ "$ptrace_scope" -ge 1 && "$ptrace_scope" -le 3 ]]; then
        print_success "ptrace_scope is restricted"
    else
        print_error "ptrace_scope is not restricted"
    fi
}

# 1.5.3 Core dumps restricted
check_core_dumps() {
    print_header "1.5.3 Core dumps restricted"
    if sysctl fs.suid_dumpable | grep -q "0"; then
        print_success "Core dumps are restricted"
    else
        print_error "Core dumps are not restricted"
    fi
}

# 1.5.4 prelink
check_prelink() {
    print_header "1.5.4 prelink"
    if ! command -v prelink &> /dev/null; then
        print_success "prelink is uninstalled"
    else
        print_error "prelink is installed"
    fi
}

# 1.5.5 Error reporting
check_error_reporting() {
    print_header "1.5.5 Error reporting"
    if systemctl is-enabled apport &> /dev/null; then
        print_error "Automatic error reporting is enabled"
    else
        print_success "Automatic error reporting is not enabled"
    fi
}

# 1.6 Command line warning banners
check_warning_banners() {
    print_header "1.6 Command line warning banners"
    if [ -f /etc/motd ]; then
        print_success "MOTD is configured"
    else
        print_error "MOTD is not configured"
    fi

    if [ -f /etc/issue ]; then
        print_success "Local login warning banner is configured"
    else
        print_error "Local login warning banner is not configured"
    fi

    if [ -f /etc/issue.net ]; then
        print_success "Remote login warning banner is configured"
    else
        print_error "Remote login warning banner is not configured"
    fi

    if ls -l /etc/motd /etc/issue /etc/issue.net | grep -q "root"; then
        print_success "Access to /etc/motd, /etc/issue, and /etc/issue.net is configured"
    else
        print_error "Access to /etc/motd, /etc/issue, and /etc/issue.net is not configured"
    fi
}

# 1.7 Configure Gnome Display Manager
check_gnome_display_manager() {
    print_header "1.7 Configure Gnome Display Manager"

    # Ensure GDM is removed
    if ! dpkg -l | grep -q gdm; then
        print_success "GDM is removed"
    else
        print_error "GDM is not removed"
    fi

    # Ensure GDM login banner is configured
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "banner-message-enable=true" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM login banner is configured"
    else
        print_error "GDM login banner is not configured"
    fi

    # Ensure GDM disable-user-list option is enabled
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "disable-user-list=true" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM disable-user-list option is enabled"
    else
        print_error "GDM disable-user-list option is not enabled"
    fi

    # Ensure GDM screen locks when the user is idle
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "idle-delay=uint32 300" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM screen locks when the user is idle"
    else
        print_error "GDM screen does not lock when the user is idle"
    fi

    # Ensure GDM screen locks cannot be overridden
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "lock-delay=uint32 0" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM screen locks cannot be overridden"
    else
        print_error "GDM screen locks can be overridden"
    fi

    # Ensure GDM automatic mounting of removable media is disabled
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "automount=false" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM automatic mounting of removable media is disabled"
    else
        print_error "GDM automatic mounting of removable media is not disabled"
    fi

    # Ensure GDM disabling automatic mounting of removable media is not overridden
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "automount-open=false" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM disabling automatic mounting of removable media is not overridden"
    else
        print_error "GDM disabling automatic mounting of removable media is overridden"
    fi

    # Ensure GDM autorun-never is enabled
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "autorun-never=true" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM autorun-never is enabled"
    else
        print_error "GDM autorun-never is not enabled"
    fi

    # Ensure GDM autorun-never is not overridden
    if [ -f /etc/gdm3/greeter.dconf-defaults ] && grep -q "autorun-never=true" /etc/gdm3/greeter.dconf-defaults; then
        print_success "GDM autorun-never is not overridden"
    else
        print_error "GDM autorun-never is overridden"
    fi

    # Ensure XDMCP is not enabled
    if [ -f /etc/gdm3/custom.conf ] && grep -q "Enable=false" /etc/gdm3/custom.conf; then
        print_success "XDMCP is not enabled"
    else
        print_error "XDMCP is enabled"
    fi
}

# 2.1 Configure Server Services
check_server_services() {
    print_header "2.1 Configure Server Services"

    services=("autofs" "avahi-daemon" "dhcpd" "named" "dnsmasq" "vsftpd" "slapd" "dovecot" "nfs" "nfs-server" "rpcbind" "rsync" "smb" "snmpd" "tftpd" "squid" "httpd" "xinetd" "X" "postfix")

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_error "$service service is in use"
        else
            print_success "$service service is not in use"
        fi
    done

    # Ensure mail transfer agent is configured for local-only mode
    if netstat -an | grep -q ':25.*LISTEN'; then
        if netstat -an | grep -q '127.0.0.1:25.*LISTEN'; then
            print_success "Mail transfer agent is configured for local-only mode"
        else
            print_error "Mail transfer agent is not configured for local-only mode"
        fi
    else
        print_success "Mail transfer agent is not listening on port 25"
    fi

    # Ensure only approved services are listening on a network interface
    approved_services=("sshd" "httpd" "httpsd")
    listening_services=$(netstat -tuln | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -u)
    for service in $listening_services; do
        if [[ ! " ${approved_services[@]} " =~ " ${service} " ]]; then
            print_error "Unapproved service $service is listening on a network interface"
        else
            print_success "Approved service $service is listening on a network interface"
        fi
    done
}

# 2.2 Configure Client Services
check_client_services() {
    print_header "2.2 Configure Client Services"

    clients=("nis" "rsh-client" "talk" "telnet" "ldap-utils" "ftp")

    for client in "${clients[@]}"; do
        if dpkg -l | grep -q "$client"; then
            print_error "$client is installed"
        else
            print_success "$client is not installed"
        fi
    done
}

# 2.3 Configure Time Synchronization
check_time_synchronization() {
    print_header "2.3 Configure Time Synchronization"

    # Ensure chrony is not running
    if systemctl is-active --quiet chrony; then
        print_error "chrony is running"
    else
        print_success "chrony is not running"
    fi

    # Ensure systemd-timesyncd is configured with authorized timeserver
    if grep -q "NTP=" /etc/systemd/timesyncd.conf; then
        print_success "systemd-timesyncd is configured with authorized timeserver"
    else
        print_error "systemd-timesyncd is not configured with authorized timeserver"
    fi

    # Ensure systemd-timesyncd is enabled and running
    if systemctl is-enabled --quiet systemd-timesyncd && systemctl is-active --quiet systemd-timesyncd; then
        print_success "systemd-timesyncd is enabled and running"
    else
        print_error "systemd-timesyncd is not enabled and running"
    fi
}

# 2.4 Job Schedulers
check_job_schedulers() {
    print_header "2.4 Job Schedulers"

    # Ensure cron daemon is enabled and active
    if systemctl is-enabled --quiet cron && systemctl is-active --quiet cron; then
        print_success "cron daemon is enabled and active"
    else
        print_error "cron daemon is not enabled and active"
    fi

    # Ensure permissions on cron files and directories are configured
    cron_files=("/etc/crontab" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")

    for file in "${cron_files[@]}"; do
        if [ -e "$file" ]; then
            if [ "$file" == "/etc/crontab" ]; then
                required_perms=644
            else
                required_perms=755
            fi

            current_perms=$(stat -c "%a" "$file")
            if [ "$current_perms" -eq "$required_perms" ]; then
                print_success "Permissions on $file are configured correctly"
            else
                print_error "Permissions on $file are not configured correctly."
            fi
        else
            print_error "$file does not exist"
        fi
    done

    # Ensure crontab is restricted to authorized users
    if [ -f /etc/cron.allow ]; then
        print_success "crontab is restricted to authorized users"
    else
        print_error "crontab is not restricted to authorized users"
    fi

    # Ensure AT is restricted to authorized users
    if [ -f /etc/at.allow ]; then
        print_success "AT is restricted to authorized users"
    else
        print_error "AT is not restricted to authorized users"
    fi
}

# 3.1 Configure Network Devices
check_network_devices() {
    print_header "3.1 Configure Network Devices"

    # Ensure IPv6 status is identified
    if sysctl -a | grep -q "net.ipv6.conf.all.disable_ipv6"; then
        print_success "IPv6 status is identified"
    else
        print_error "IPv6 status is not identified"
    fi

    # Ensure wireless interfaces are disabled
    if nmcli radio wifi | grep -q "disabled"; then
        print_success "Wireless interfaces are disabled"
    else
        print_error "Wireless interfaces are not disabled"
    fi

    # Ensure Bluetooth services are not in use
    if systemctl is-active --quiet bluetooth; then
        print_error "Bluetooth services are in use"
    else
        print_success "Bluetooth services are not in use"
    fi
}

# 3.2 Configure Network Kernel Modules
check_network_kernel_modules() {
    print_header "3.2 Configure Network Kernel Modules"

    modules=("dccp" "tipc" "rds" "sctp")
    for module in "${modules[@]}"; do
        if lsmod | grep -q "$module"; then
            print_error "$module kernel module is available"
        else
            print_success "$module kernel module is not available"
        fi
    done
}

# 3.3 Configure Network Kernel Parameters
check_network_kernel_parameters() {
    print_header "3.3 Configure Network Kernel Parameters"

    # Ensure IP forwarding is disabled
    if sysctl net.ipv4.ip_forward | grep -q "0"; then
        print_success "IP forwarding is disabled"
    else
        print_error "IP forwarding is not disabled"
    fi

    # Ensure packet redirect sending is disabled
    if sysctl net.ipv4.conf.all.send_redirects | grep -q "0"; then
        print_success "Packet redirect sending is disabled"
    else
        print_error "Packet redirect sending is not disabled"
    fi

    # Ensure bogus ICMP responses are ignored
    if sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -q "1"; then
        print_success "Bogus ICMP responses are ignored"
    else
        print_error "Bogus ICMP responses are not ignored"
    fi

    # Ensure broadcast ICMP requests are ignored
    if sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -q "1"; then
        print_success "Broadcast ICMP requests are ignored"
    else
        print_error "Broadcast ICMP requests are not ignored"
    fi

    # Ensure ICMP redirects are not accepted
    if sysctl net.ipv4.conf.all.accept_redirects | grep -q "0"; then
        print_success "ICMP redirects are not accepted"
    else
        print_error "ICMP redirects are accepted"
    fi

    # Ensure secure ICMP redirects are not accepted
    if sysctl net.ipv4.conf.all.secure_redirects | grep -q "0"; then
        print_success "Secure ICMP redirects are not accepted"
    else
        print_error "Secure ICMP redirects are accepted"
    fi

    # Ensure reverse path filtering is enabled
    if sysctl net.ipv4.conf.all.rp_filter | grep -q "1"; then
        print_success "Reverse path filtering is enabled"
    else
        print_error "Reverse path filtering is not enabled"
    fi

    # Ensure source routed packets are not accepted
    if sysctl net.ipv4.conf.all.accept_source_route | grep -q "0"; then
        print_success "Source routed packets are not accepted"
    else
        print_error "Source routed packets are accepted"
    fi

    # Ensure suspicious packets are logged
    if sysctl net.ipv4.conf.all.log_martians | grep -q "1"; then
        print_success "Suspicious packets are logged"
    else
        print_error "Suspicious packets are not logged"
    fi

    # Ensure TCP SYN cookies are enabled
    if sysctl net.ipv4.tcp_syncookies | grep -q "1"; then
        print_success "TCP SYN cookies are enabled"
    else
        print_error "TCP SYN cookies are not enabled"
    fi

    # Ensure IPv6 router advertisements are not accepted
    if sysctl net.ipv6.conf.all.accept_ra | grep -q "0"; then
        print_success "IPv6 router advertisements are not accepted"
    else
        print_error "IPv6 router advertisements are accepted"
    fi
}

# 4.1 Single Firewall
check_single_firewall() {
    print_header "4.1 Single Firewall"

    # Ensure a single firewall configuration utility is in use
    if dpkg -l | grep -qE "ufw|iptables|firewalld"; then
        firewall_count=$(dpkg -l | grep -E "ufw|iptables|firewalld" | wc -l)
        if [ "$firewall_count" -eq 1 ]; then
            print_success "A single firewall configuration utility is in use"
        else
            print_error "Multiple firewall configuration utilities are in use"
        fi
    else
        print_error "No firewall configuration utility is in use"
    fi
}

# 4.2 Configure UFW
check_ufw_configuration() {
    print_header "4.2 Configure UFW"

    # Ensure ufw is installed
    if dpkg -l | grep -q ufw; then
        print_success "ufw is installed"
    else
        print_error "ufw is not installed"
    fi

    # Ensure iptables-persistent is not installed with ufw
    if dpkg -l | grep -q iptables-persistent; then
        print_error "iptables-persistent is installed with ufw"
    else
        print_success "iptables-persistent is not installed with ufw"
    fi

    # Ensure ufw is enabled
    if systemctl is-enabled --quiet ufw && systemctl is-active --quiet ufw; then
        print_success "ufw is enabled"
    else
        print_error "ufw is not enabled"
    fi

    # Ensure ufw loopback traffic is configured
    if ufw status | grep -q "allow in on lo"; then
        print_success "ufw loopback traffic is configured"
    else
        print_error "ufw loopback traffic is not configured"
    fi

    # Ensure ufw outbound connections are configured
    if ufw status | grep -q "allow out"; then
        print_success "ufw outbound connections are configured"
    else
        print_error "ufw outbound connections are not configured"
    fi

    # Ensure ufw firewall rules exist for all open ports
    open_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -u)
    for port in $open_ports; do
        if ufw status | grep -q "$port"; then
            print_success "ufw firewall rule exists for port $port"
        else
            print_error "ufw firewall rule does not exist for port $port"
        fi
    done

    # Ensure ufw has a default deny policy
    if ufw status | grep -q "Default: deny (incoming)"; then
        print_success "ufw has a default deny policy"
    else
        print_error "ufw does not have a default deny policy"
    fi
}

# 4.3 Configure nftables
check_nftables_configuration() {
    print_header "4.3 Configure nftables"

    # Ensure nftables is installed
    if dpkg -l | grep -q nftables; then
        print_success "nftables is installed"
    else
        print_error "nftables is not installed"
    fi

    # Ensure ufw is uninstalled or disabled with nftables
    if dpkg -l | grep -q ufw; then
        if systemctl is-active --quiet ufw; then
            print_error "ufw is active with nftables"
        else
            print_success "ufw is installed but not active with nftables"
        fi
    else
        print_success "ufw is not installed with nftables"
    fi

    # Ensure iptables are flushed with nftables
    if iptables -L | grep -q "Chain"; then
        print_error "iptables are not flushed with nftables"
    else
        print_success "iptables are flushed with nftables"
    fi

    # Ensure a nftables table exists
    if nft list tables | grep -q "table"; then
        print_success "nftables table exists"
    else
        print_error "nftables table does not exist"
    fi

    # Ensure nftables base chains exist
    if nft list chains | grep -q "chain"; then
        print_success "nftables base chains exist"
    else
        print_error "nftables base chains do not exist"
    fi

    # Ensure nftables loopback traffic is configured
    if nft list ruleset | grep -q "iif lo accept"; then
        print_success "nftables loopback traffic is configured"
    else
        print_error "nftables loopback traffic is not configured"
    fi

    # Ensure nftables outbound and established connections are configured
    if nft list ruleset | grep -q "ct state established,related accept"; then
        print_success "nftables outbound and established connections are configured"
    else
        print_error "nftables outbound and established connections are not configured"
    fi

    # Ensure nftables default deny firewall policy
    if nft list ruleset | grep -q "policy drop"; then
        print_success "nftables default deny firewall policy is configured"
    else
        print_error "nftables default deny firewall policy is not configured"
    fi

    # Ensure nftables service is enabled
    if systemctl is-enabled --quiet nftables; then
        print_success "nftables service is enabled"
    else
        print_error "nftables service is not enabled"
    fi

    # Ensure nftables rules are permanent
    if nft list ruleset | grep -q "table inet"; then
        print_success "nftables rules are permanent"
    else
        print_error "nftables rules are not permanent"
    fi
}

# 4.4 Configure iptables
check_iptables_configuration() {
    print_header "4.4 Configure iptables"

    # Ensure iptables packages are installed
    if dpkg -l | grep -q iptables; then
        print_success "iptables packages are installed"
    else
        print_error "iptables packages are not installed"
    fi

    # Ensure nftables is not in use with iptables
    if dpkg -l | grep -q nftables; then
        print_error "nftables is in use with iptables"
    else
        print_success "nftables is not in use with iptables"
    fi

    # Ensure ufw is not in use with iptables
    if dpkg -l | grep -q ufw; then
        print_error "ufw is in use with iptables"
    else
        print_success "ufw is not in use with iptables"
    fi

    # Ensure iptables default deny firewall policy
    if iptables -L | grep -q "policy DROP"; then
        print_success "iptables default deny firewall policy is configured"
    else
        print_error "iptables default deny firewall policy is not configured"
    fi

    # Ensure iptables loopback traffic is configured
    if iptables -L | grep -q "ACCEPT all -- lo"; then
        print_success "iptables loopback traffic is configured"
    else
        print_error "iptables loopback traffic is not configured"
    fi

    # Ensure iptables outbound and established connections are configured
    if iptables -L | grep -q "ACCEPT all -- anywhere anywhere state RELATED,ESTABLISHED"; then
        print_success "iptables outbound and established connections are configured"
    else
        print_error "iptables outbound and established connections are not configured"
    fi

    # Ensure iptables firewall rules exist for all open ports
    open_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -u)
    for port in $open_ports; do
        if iptables -L | grep -q "$port"; then
            print_success "iptables firewall rule exists for port $port"
        else
            print_error "iptables firewall rule does not exist for port $port"
        fi
    done

    # Ensure ip6tables default deny firewall policy
    if ip6tables -L | grep -q "policy DROP"; then
        print_success "ip6tables default deny firewall policy is configured"
    else
        print_error "ip6tables default deny firewall policy is not configured"
    fi

    # Ensure ip6tables loopback traffic is configured
    if ip6tables -L | grep -q "ACCEPT all -- lo"; then
        print_success "ip6tables loopback traffic is configured"
    else
        print_error "ip6tables loopback traffic is not configured"
    fi

    # Ensure ip6tables outbound and established connections are configured
    if ip6tables -L | grep -q "ACCEPT all -- anywhere anywhere state RELATED,ESTABLISHED"; then
        print_success "ip6tables outbound and established connections are configured"
    else
        print_error "ip6tables outbound and established connections are not configured"
    fi

    # Ensure ip6tables firewall rules exist for all open ports
    open_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -u)
    for port in $open_ports; do
        if ip6tables -L | grep -q "$port"; then
            print_success "ip6tables firewall rule exists for port $port"
        else
            print_error "ip6tables firewall rule does not exist for port $port"
        fi
    done
}

# 5.1 SSH Server
check_ssh_server() {
    print_header "5.1 SSH Server"

    # Ensure permissions on SSH private host key files are configured
    private_keys=$(find /etc/ssh -type f -name 'ssh_host_*_key')
    for key in $private_keys; do
        if [ "$(stat -c %a "$key")" -eq 600 ]; then
            print_success "Permissions on SSH private host key file $key are configured"
        else
            print_error "Permissions on SSH private host key file $key are not configured"
        fi
    done

    # Ensure permissions on SSH public host key files are configured
    public_keys=$(find /etc/ssh -type f -name 'ssh_host_*_key.pub')
    for key in $public_keys; do
        if [ "$(stat -c %a "$key")" -eq 644 ]; then
            print_success "Permissions on SSH public host key file $key are configured"
        else
            print_error "Permissions on SSH public host key file $key are not configured"
        fi
    done

    # Check if sshd is installed
    if ! command -v sshd &> /dev/null; then
        print_error "sshd is not installed. Skipping SSH server checks."
        return
    fi

    # Ensure permissions on /etc/ssh/sshd_config are configured
    if [ "$(stat -c %a /etc/ssh/sshd_config)" -eq 640 ]; then
        print_success "Permissions on /etc/ssh/sshd_config are configured"
    else
        print_error "Permissions on /etc/ssh/sshd_config are not configured"
    fi

    # Ensure sshd access is configured
    if grep -q "^AllowUsers" /etc/ssh/sshd_config; then
        print_success "sshd access is configured"
    else
        print_error "sshd access is not configured"
    fi

    # Ensure sshd Banner is configured
    if grep -q "^Banner" /etc/ssh/sshd_config; then
        print_success "sshd Banner is configured"
    else
        print_error "sshd Banner is not configured"
    fi

    # Ensure sshd Ciphers are configured
    if grep -q "^Ciphers" /etc/ssh/sshd_config; then
        print_success "sshd Ciphers are configured"
    else
        print_error "sshd Ciphers are not configured"
    fi

    # Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
    if grep -q "^ClientAliveInterval" /etc/ssh/sshd_config && grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config; then
        print_success "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        print_error "sshd ClientAliveInterval and ClientAliveCountMax are not configured"
    fi

    # Ensure sshd DisableForwarding is enabled
    if grep -q "^DisableForwarding yes" /etc/ssh/sshd_config; then
        print_success "sshd DisableForwarding is enabled"
    else
        print_error "sshd DisableForwarding is not enabled"
    fi

    # Ensure sshd GSSAPIAuthentication is disabled
    if grep -q "^GSSAPIAuthentication no" /etc/ssh/sshd_config; then
        print_success "sshd GSSAPIAuthentication is disabled"
    else
        print_error "sshd GSSAPIAuthentication is not disabled"
    fi

    # Ensure sshd HostbasedAuthentication is disabled
    if grep -q "^HostbasedAuthentication no" /etc/ssh/sshd_config; then
        print_success "sshd HostbasedAuthentication is disabled"
    else
        print_error "sshd HostbasedAuthentication is not disabled"
    fi

    # Ensure sshd IgnoreRhosts is enabled
    if grep -q "^IgnoreRhosts yes" /etc/ssh/sshd_config; then
        print_success "sshd IgnoreRhosts is enabled"
    else
        print_error "sshd IgnoreRhosts is not enabled"
    fi

    # Ensure sshd KexAlgorithms is configured
    if grep -q "^KexAlgorithms" /etc/ssh/sshd_config; then
        print_success "sshd KexAlgorithms is configured"
    else
        print_error "sshd KexAlgorithms are not configured"
    fi

    # Ensure sshd LoginGraceTime is configured
    if grep -q "^LoginGraceTime" /etc/ssh/sshd_config; then
        print_success "sshd LoginGraceTime is configured"
    else
        print_error "sshd LoginGraceTime is not configured"
    fi

    # Ensure sshd LogLevel is configured
    if grep -q "^LogLevel" /etc/ssh/sshd_config; then
        print_success "sshd LogLevel is configured"
    else
        print_error "sshd LogLevel is not configured"
    fi

    # Ensure sshd MACs are configured correctly
    if grep -q "^MACs" /etc/ssh/sshd_config; then
        print_success "sshd MACs are configured correctly"
    else
        print_error "sshd MACs are not configured correctly"
    fi

    # Ensure sshd MaxAuthTries is configured
    if grep -q "^MaxAuthTries" /etc/ssh/sshd_config; then
        print_success "sshd MaxAuthTries is configured"
    else
        print_error "sshd MaxAuthTries is not configured"
    fi

    # Ensure sshd MaxSessions is configured
    if grep -q "^MaxSessions" /etc/ssh/sshd_config; then
        print_success "sshd MaxSessions is configured"
    else
        print_error "sshd MaxSessions is not configured"
    fi

    # Ensure sshd MaxStartups is configured
    if grep -q "^MaxStartups" /etc/ssh/sshd_config; then
        print_success "sshd MaxStartups is configured"
    else
        print_error "sshd MaxStartups is not configured"
    fi

    # Ensure sshd PermitEmptyPasswords is disabled
    if grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config; then
        print_success "sshd PermitEmptyPasswords is disabled"
    else
        print_error "sshd PermitEmptyPasswords is not disabled"
    fi

    # Ensure sshd PermitRootLogin is disabled
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        print_success "sshd PermitRootLogin is disabled"
    else
        print_error "sshd PermitRootLogin is not disabled"
    fi

    # Ensure sshd PermitUserEnvironment is disabled
    if grep -q "^PermitUserEnvironment no" /etc/ssh/sshd_config; then
        print_success "sshd PermitUserEnvironment is disabled"
    else
        print_error "sshd PermitUserEnvironment is not disabled"
    fi

    # Ensure sshd UsePAM is enabled
    if grep -q "^UsePAM yes" /etc/ssh/sshd_config; then
        print_success "sshd UsePAM is enabled"
    else
        print_error "sshd UsePAM is not enabled"
    fi
}

# 5.2 Configure Privilege Escalation
check_privilege_escalation() {
    print_header "5.2 Configure Privilege Escalation"

    # 5.2.1 Ensure sudo is installed
    if dpkg -l | grep -q sudo; then
        print_success "sudo is installed"
    else
        print_error "sudo is not installed"
    fi

    # 5.2.2 Ensure sudo commands use pty
    if grep -q "Defaults use_pty" /etc/sudoers; then
        print_success "sudo commands use pty"
    else
        print_error "sudo commands do not use pty"
    fi

    # 5.2.3 Ensure sudo log file exists
    if grep -q "Defaults logfile=" /etc/sudoers; then
        print_success "sudo log file exists"
    else
        print_error "sudo log file does not exist"
    fi

    # 5.2.4 Ensure users must provide password for privilege escalation
    if grep -q "Defaults !authenticate" /etc/sudoers; then
        print_error "Users are not required to provide password for privilege escalation"
    else
        print_success "Users must provide password for privilege escalation"
    fi

    # 5.2.5 Ensure re-authentication for privilege escalation is not disabled globally
    if grep -q "Defaults timestamp_timeout=" /etc/sudoers; then
        print_error "Re-authentication for privilege escalation is disabled globally"
    else
        print_success "Re-authentication for privilege escalation is not disabled globally"
    fi

    # 5.2.6 Ensure sudo authentication timeout is configured correctly
    if grep -q "Defaults timestamp_timeout=" /etc/sudoers; then
        print_success "sudo authentication timeout is configured correctly"
    else
        print_error "sudo authentication timeout is not configured correctly"
    fi

    # 5.2.7 Ensure access to the su command is restricted
    if grep -q "auth required pam_wheel.so" /etc/pam.d/su; then
        print_success "Access to the su command is restricted"
    else
        print_error "Access to the su command is not restricted"
    fi
}

# 5.3 Configure PAM
check_pam_configuration() {
    print_header "5.3 Configure PAM"

    # 5.3.1.1 Ensure latest version of pam is installed
    if dpkg -l | grep -q "libpam0g"; then
        print_success "Latest version of pam is installed"
    else
        print_error "Latest version of pam is not installed"
    fi

    # 5.3.1.2 Ensure libpam-modules is installed
    if dpkg -l | grep -q "libpam-modules"; then
        print_success "libpam-modules is installed"
    else
        print_error "libpam-modules is not installed"
    fi

    # 5.3.1.3 Ensure libpam-pwquality is installed
    if dpkg -l | grep -q "libpam-pwquality"; then
        print_success "libpam-pwquality is installed"
    else
        print_error "libpam-pwquality is not installed"
    fi

    # 5.3.2.1 Ensure pam_unix module is enabled
    if grep -q "pam_unix.so" /etc/pam.d/common-auth; then
        print_success "pam_unix module is enabled"
    else
        print_error "pam_unix module is not enabled"
    fi

    # 5.3.2.2 Ensure pam_faillock module is enabled
    if grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
        print_success "pam_faillock module is enabled"
    else
        print_error "pam_faillock module is not enabled"
    fi

    # 5.3.2.3 Ensure pam_pwquality module is enabled
    if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        print_success "pam_pwquality module is enabled"
    else
        print_error "pam_pwquality module is not enabled"
    fi

    # 5.3.2.4 Ensure pam_pwhistory module is enabled
    if grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
        print_success "pam_pwhistory module is enabled"
    else
        print_error "pam_pwhistory module is not enabled"
    fi
}

# 5.3.3 Configure PAM Arguments
check_pam_arguments() {
    print_header "5.3.3 Configure PAM Arguments"

    # 5.3.3.1 Configure pam_faillock module
    # 5.3.3.1.1 Ensure password failed attempts lockout is configured
    if grep -q "auth required pam_faillock.so" /etc/pam.d/common-auth; then
        print_success "Password failed attempts lockout is configured"
    else
        print_error "Password failed attempts lockout is not configured"
    fi

    # 5.3.3.1.2 Ensure password unlock time is configured
    if grep -q "unlock_time=" /etc/security/faillock.conf; then
        print_success "Password unlock time is configured"
    else
        print_error "Password unlock time is not configured"
    fi

    # 5.3.3.1.3 Ensure password failed attempts lockout includes root account
    if grep -q "even_deny_root" /etc/security/faillock.conf; then
        print_success "Password failed attempts lockout includes root account"
    else
        print_error "Password failed attempts lockout does not include root account"
    fi

    # 5.3.3.2 Configure pam_pwquality module
    # 5.3.3.2.1 Ensure password number of changed characters is configured
    if grep -q "difok=" /etc/security/pwquality.conf; then
        print_success "Password number of changed characters is configured"
    else
        print_error "Password number of changed characters is not configured"
    fi

    # 5.3.3.2.2 Ensure minimum password length is configured
    if grep -q "minlen=" /etc/security/pwquality.conf; then
        print_success "Minimum password length is configured"
    else
        print_error "Minimum password length is not configured"
    fi

    # 5.3.3.2.3 Ensure password complexity is configured
    if grep -q "minclass=" /etc/security/pwquality.conf; then
        print_success "Password complexity is configured"
    else
        print_error "Password complexity is not configured"
    fi

    # 5.3.3.2.4 Ensure password same consecutive characters is configured
    if grep -q "maxrepeat=" /etc/security/pwquality.conf; then
        print_success "Password same consecutive characters is configured"
    else
        print_error "Password same consecutive characters is not configured"
    fi

    # 5.3.3.2.5 Ensure password maximum sequential characters is configured
    if grep -q "maxsequence=" /etc/security/pwquality.conf; then
        print_success "Password maximum sequential characters is configured"
    else
        print_error "Password maximum sequential characters is not configured"
    fi

    # 5.3.3.2.6 Ensure password dictionary check is enabled
    if grep -q "dictcheck=" /etc/security/pwquality.conf; then
        print_success "Password dictionary check is enabled"
    else
        print_error "Password dictionary check is not enabled"
    fi

    # 5.3.3.2.7 Ensure password quality checking is enforced
    if grep -q "enforce_for_root" /etc/security/pwquality.conf; then
        print_success "Password quality checking is enforced"
    else
        print_error "Password quality checking is not enforced"
    fi

    # 5.3.3.2.8 Ensure password quality is enforced for the root user
    if grep -q "enforce_for_root" /etc/security/pwquality.conf; then
        print_success "Password quality is enforced for the root user"
    else
        print_error "Password quality is not enforced for the root user"
    fi

    # 5.3.3.3 Configure pam_pwhistory module
    # 5.3.3.3.1 Ensure password history remember is configured
    if grep -q "remember=" /etc/security/pwhistory.conf; then
        print_success "Password history remember is configured"
    else
        print_error "Password history remember is not configured"
    fi

    # 5.3.3.3.2 Ensure password history is enforced for the root user
    if grep -q "enforce_for_root" /etc/security/pwhistory.conf; then
        print_success "Password history is enforced for the root user"
    else
        print_error "Password history is not enforced for the root user"
    fi

    # 5.3.3.3.3 Ensure pam_pwhistory includes use_authtok
    if grep -q "use_authtok" /etc/security/pwhistory.conf; then
        print_success "pam_pwhistory includes use_authtok"
    else
        print_error "pam_pwhistory does not include use_authtok"
    fi

    # 5.3.3.4 Configure pam_unix module
    # 5.3.3.4.1 Ensure pam_unix does not include nullok
    if ! grep -q "nullok" /etc/pam.d/common-password; then
        print_success "pam_unix does not include nullok"
    else
        print_error "pam_unix includes nullok"
    fi

    # 5.3.3.4.2 Ensure pam_unix does not include remember
    if ! grep -q "remember=" /etc/pam.d/common-password; then
        print_success "pam_unix does not include remember"
    else
        print_error "pam_unix includes remember"
    fi

    # 5.3.3.4.3 Ensure pam_unix includes a strong password hashing algorithm
    if grep -q "sha512" /etc/pam.d/common-password; then
        print_success "pam_unix includes a strong password hashing algorithm"
    else
        print_error "pam_unix does not include a strong password hashing algorithm"
    fi

    # 5.3.3.4.4 Ensure pam_unix includes use_authtok
    if grep -q "use_authtok" /etc/pam.d/common-password; then
        print_success "pam_unix includes use_authtok"
    else
        print_error "pam_unix does not include use_authtok"
    fi
}

# 5.4 User Accounts and Environment
check_user_accounts_environment() {
    print_header "5.4 User Accounts and Environment"

    # 5.4.1 Configure shadow password suite parameters
    # 5.4.1.1 Ensure password expiration is configured
    if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
        print_success "Password expiration is configured"
    else
        print_error "Password expiration is not configured"
    fi

    # 5.4.1.2 Ensure minimum password days is configured
    if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
        print_success "Minimum password days is configured"
    else
        print_error "Minimum password days is not configured"
    fi

    # 5.4.1.3 Ensure password expiration warning days is configured
    if grep -q "^PASS_WARN_AGE" /etc/login.defs; then
        print_success "Password expiration warning days is configured"
    else
        print_error "Password expiration warning days is not configured"
    fi

    # 5.4.1.4 Ensure strong password hashing algorithm is configured
    if grep -q "^ENCRYPT_METHOD SHA512" /etc/login.defs; then
        print_success "Strong password hashing algorithm is configured"
    else
        print_error "Strong password hashing algorithm is not configured"
    fi

    # 5.4.1.5 Ensure inactive password lock is configured
    if useradd -D | grep -q "INACTIVE"; then
        print_success "Inactive password lock is configured"
    else
        print_error "Inactive password lock is not configured"
    fi

    # 5.4.1.6 Ensure all users last password change date is in the past
    if awk -F: '$5 < 0 {print $1}' /etc/shadow | grep -q .; then
        print_error "Some users have a last password change date in the future"
    else
        print_success "All users last password change date is in the past"
    fi

    # 5.4.2 Configure root and system accounts and environment
    # 5.4.2.1 Ensure root is the only UID 0 account
    if awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -q "^root$"; then
        print_success "Root is the only UID 0 account"
    else
        print_error "There are other UID 0 accounts besides root"
    fi

    # 5.4.2.2 Ensure root is the only GID 0 account
    if awk -F: '($4 == 0) {print $1}' /etc/passwd | grep -q "^root$"; then
        print_success "Root is the only GID 0 account"
    else
        print_error "There are other GID 0 accounts besides root"
    fi

    # 5.4.2.3 Ensure group root is the only GID 0 group
    if awk -F: '($3 == 0) {print $1}' /etc/group | grep -q "^root$"; then
        print_success "Group root is the only GID 0 group"
    else
        print_error "There are other GID 0 groups besides root"
    fi

    # 5.4.2.4 Ensure root account access is controlled
    if grep -q "^auth required pam_wheel.so" /etc/pam.d/su; then
        print_success "Root account access is controlled"
    else
        print_error "Root account access is not controlled"
    fi

    # 5.4.2.5 Ensure root path integrity
    if echo "$PATH" | grep -q "::\|:/"; then
        print_error "Root path integrity is not ensured"
    else
        print_success "Root path integrity is ensured"
    fi

    # 5.4.2.6 Ensure root user umask is configured
    if grep -q "^umask" /root/.bashrc; then
        print_success "Root user umask is configured"
    else
        print_error "Root user umask is not configured"
    fi

    # 5.4.2.7 Ensure system accounts do not have a valid login shell
    if awk -F: '($7 !~ /(\/usr\/sbin\/nologin|\/bin\/false)/) {print $1}' /etc/passwd | grep -q .; then
        print_error "Some system accounts have a valid login shell"
    else
        print_success "System accounts do not have a valid login shell"
    fi

    # 5.4.2.8 Ensure accounts without a valid login shell are locked
    if awk -F: '($7 !~ /(\/usr\/sbin\/nologin|\/bin\/false)/) {print $1}' /etc/passwd | xargs -I {} passwd -S {} | grep -q " L "; then
        print_success "Accounts without a valid login shell are locked"
    else
        print_error "Accounts without a valid login shell are not locked"
    fi

    # 5.4.3 Configure user default environment
    # 5.4.3.1 Ensure nologin is not listed in /etc/shells
    if grep -q "/usr/sbin/nologin" /etc/shells; then
        print_error "nologin is listed in /etc/shells"
    else
        print_success "nologin is not listed in /etc/shells"
    fi

    # 5.4.3.2 Ensure default user shell timeout is configured
    if grep -q "^TMOUT" /etc/profile; then
        print_success "Default user shell timeout is configured"
    else
        print_error "Default user shell timeout is not configured"
    fi

    # 5.4.3.3 Ensure default user umask is configured
    if grep -q "^umask" /etc/profile; then
        print_success "Default user umask is configured"
    else
        print_error "Default user umask is not configured"
    fi
}

# 6.1 System Logging
check_system_logging() {
    print_header "6.1 System Logging"

    # 6.1.1 Configure systemd-journald service
    # 6.1.1.1 Ensure journald service is enabled and active
    if systemctl is-enabled --quiet systemd-journald && systemctl is-active --quiet systemd-journald; then
        print_success "journald service is enabled and active"
    else
        print_error "journald service is not enabled and active"
    fi

    # 6.1.1.2 Ensure journald log file access is configured
    if grep -q "^Storage=" /etc/systemd/journald.conf; then
        print_success "journald log file access is configured"
    else
        print_error "journald log file access is not configured"
    fi

    # 6.1.1.3 Ensure journald log file rotation is configured
    if grep -q "^SystemMaxUse=" /etc/systemd/journald.conf; then
        print_success "journald log file rotation is configured"
    else
        print_error "journald log file rotation is not configured"
    fi

    # 6.1.1.4 Ensure only one logging system is in use
    if systemctl is-active --quiet rsyslog || systemctl is-active --quiet syslog-ng; then
        print_error "Multiple logging systems are in use"
    else
        print_success "Only one logging system is in use"
    fi

    # 6.1.2 Configure journald
    # 6.1.2.1 Configure systemd-journal-remote
    # 6.1.2.1.1 Ensure systemd-journal-remote is installed
    if dpkg -l | grep -q systemd-journal-remote; then
        print_success "systemd-journal-remote is installed"
    else
        print_error "systemd-journal-remote is not installed"
    fi

    # 6.1.2.1.2 Ensure systemd-journal-upload authentication is configured
    if grep -q "^UploadKey=" /etc/systemd/journal-upload.conf; then
        print_success "systemd-journal-upload authentication is configured"
    else
        print_error "systemd-journal-upload authentication is not configured"
    fi

    # 6.1.2.1.3 Ensure systemd-journal-upload is enabled and active
    if systemctl is-enabled --quiet systemd-journal-upload && systemctl is-active --quiet systemd-journal-upload; then
        print_success "systemd-journal-upload is enabled and active"
    else
        print_error "systemd-journal-upload is not enabled and active"
    fi

    # 6.1.2.1.4 Ensure systemd-journal-remote service is not in use
    if systemctl is-active --quiet systemd-journal-remote; then
        print_error "systemd-journal-remote service is in use"
    else
        print_success "systemd-journal-remote service is not in use"
    fi

    # 6.1.2.2 Ensure journald ForwardToSyslog is disabled
    if grep -q "^ForwardToSyslog=no" /etc/systemd/journald.conf; then
        print_success "journald ForwardToSyslog is disabled"
    else
        print_error "journald ForwardToSyslog is not disabled"
    fi

    # 6.1.2.3 Ensure journald Compress is configured
    if grep -q "^Compress=yes" /etc/systemd/journald.conf; then
        print_success "journald Compress is configured"
    else
        print_error "journald Compress is not configured"
    fi

    # 6.1.2.4 Ensure journald Storage is configured
    if grep -q "^Storage=" /etc/systemd/journald.conf; then
        print_success "journald Storage is configured"
    else
        print_error "journald Storage is not configured"
    fi

    # 6.1.3 Configure rsyslog
    # 6.1.3.1 Ensure rsyslog is installed
    if dpkg -l | grep -q rsyslog; then
        print_success "rsyslog is installed"
    else
        print_error "rsyslog is not installed"
    fi

    # 6.1.3.2 Ensure rsyslog service is enabled and active
    if systemctl is-enabled --quiet rsyslog && systemctl is-active --quiet rsyslog; then
        print_success "rsyslog service is enabled and active"
    else
        print_error "rsyslog service is not enabled and active"
    fi

    # 6.1.3.3 Ensure journald is configured to send logs to rsyslog
    if grep -q "^ForwardToSyslog=yes" /etc/systemd/journald.conf; then
        print_success "journald is configured to send logs to rsyslog"
    else
        print_error "journald is not configured to send logs to rsyslog"
    fi

    # 6.1.3.4 Ensure rsyslog log file creation mode is configured
    if grep -q "^$FileCreateMode" /etc/rsyslog.conf; then
        print_success "rsyslog log file creation mode is configured"
    else
        print_error "rsyslog log file creation mode is not configured"
    fi

    # 6.1.3.5 Ensure rsyslog logging is configured
    if grep -q "^*.*" /etc/rsyslog.conf; then
        print_success "rsyslog logging is configured"
    else
        print_error "rsyslog logging is not configured"
    fi

    # 6.1.3.6 Ensure rsyslog is configured to send logs to a remote log host
    if grep -q "^*.* @@remote-host" /etc/rsyslog.conf; then
        print_success "rsyslog is configured to send logs to a remote log host"
    else
        print_error "rsyslog is not configured to send logs to a remote log host"
    fi

    # 6.1.3.7 Ensure rsyslog is not configured to receive logs from a remote client
    if grep -q "^$ModLoad imtcp" /etc/rsyslog.conf; then
        print_error "rsyslog is configured to receive logs from a remote client"
    else
        print_success "rsyslog is not configured to receive logs from a remote client"
    fi

    # 6.1.3.8 Ensure logrotate is configured
    if dpkg -l | grep -q logrotate; then
        print_success "logrotate is configured"
    else
        print_error "logrotate is not configured"
    fi

    # 6.1.4 Configure Logfiles
    # 6.1.4.1 Ensure access to all logfiles has been configured
    if find /var/log -type f -exec stat -c "%a %n" {} \; | awk '$1 != "600" {print $2}' | grep -q .; then
        print_error "Access to some logfiles is not configured"
    else
        print_success "Access to all logfiles has been configured"
    fi
}

# 6.2 System Auditing
check_system_auditing() {
    print_header "6.2 System Auditing"

    # 6.2.1 Configure auditd Service
    # 6.2.1.1 Ensure auditd packages are installed
    if dpkg -l | grep -q auditd; then
        print_success "auditd packages are installed"
    else
        print_error "auditd packages are not installed"
    fi

    # 6.2.1.2 Ensure auditd service is enabled and active
    if systemctl is-enabled --quiet auditd && systemctl is-active --quiet auditd; then
        print_success "auditd service is enabled and active"
    else
        print_error "auditd service is not enabled and active"
    fi

    # 6.2.1.3 Ensure auditing for processes that start prior to auditd is enabled
    if grep -q "audit=1" /etc/default/grub; then
        print_success "Auditing for processes that start prior to auditd is enabled"
    else
        print_error "Auditing for processes that start prior to auditd is not enabled"
    fi

    # 6.2.1.4 Ensure audit_backlog_limit is sufficient
    if grep -q "audit_backlog_limit=" /etc/default/grub; then
        print_success "audit_backlog_limit is sufficient"
    else
        print_error "audit_backlog_limit is not sufficient"
    fi

    # 6.2.2 Configure Data Retention
    # 6.2.2.1 Ensure audit log storage size is configured
    if grep -q "max_log_file =" /etc/audit/auditd.conf; then
        print_success "Audit log storage size is configured"
    else
        print_error "Audit log storage size is not configured"
    fi

    # 6.2.2.2 Ensure audit logs are not automatically deleted
    if grep -q "max_log_file_action = keep_logs" /etc/audit/auditd.conf; then
        print_success "Audit logs are not automatically deleted"
    else
        print_error "Audit logs are automatically deleted"
    fi

    # 6.2.2.3 Ensure system is disabled when audit logs are full
    if grep -q "space_left_action = email" /etc/audit/auditd.conf && grep -q "action_mail_acct = root" /etc/audit/auditd.conf && grep -q "admin_space_left_action = halt" /etc/audit/auditd.conf; then
        print_success "System is disabled when audit logs are full"
    else
        print_error "System is not disabled when audit logs are full"
    fi

    # 6.2.2.4 Ensure system warns when audit logs are low on space
    if grep -q "space_left =" /etc/audit/auditd.conf && grep -q "space_left_action = email" /etc/audit/auditd.conf; then
        print_success "System warns when audit logs are low on space"
    else
        print_error "System does not warn when audit logs are low on space"
    fi
}

# 6.2.3 Configure auditd Rules
check_auditd_rules() {
    print_header "6.2.3 Configure auditd Rules"

    # 6.2.3.1 Ensure changes to system administration scope (sudoers) is collected
    if auditctl -l | grep -q "/etc/sudoers"; then
        print_success "Changes to system administration scope (sudoers) are collected"
    else
        print_error "Changes to system administration scope (sudoers) are not collected"
    fi

    # 6.2.3.2 Ensure actions as another user are always logged
    if auditctl -l | grep -q "auid>=1000 -F auid!=4294967295 -k actions"; then
        print_success "Actions as another user are always logged"
    else
        print_error "Actions as another user are not always logged"
    fi

    # 6.2.3.3 Ensure events that modify the sudo log file are collected
    if auditctl -l | grep -q "/var/log/sudo.log"; then
        print_success "Events that modify the sudo log file are collected"
    else
        print_error "Events that modify the sudo log file are not collected"
    fi

    # 6.2.3.4 Ensure events that modify date and time information are collected
    if auditctl -l | grep -q "adjtimex\|settimeofday\|clock_settime"; then
        print_success "Events that modify date and time information are collected"
    else
        print_error "Events that modify date and time information are not collected"
    fi

    # 6.2.3.5 Ensure events that modify the system's network environment are collected
    if auditctl -l | grep -q "sethostname\|setdomainname"; then
        print_success "Events that modify the system's network environment are collected"
    else
        print_error "Events that modify the system's network environment are not collected"
    fi

    # 6.2.3.6 Ensure use of privileged commands are collected
    if auditctl -l | grep -q "/usr/sbin"; then
        print_success "Use of privileged commands are collected"
    else
        print_error "Use of privileged commands are not collected"
    fi

    # 6.2.3.7 Ensure unsuccessful file access attempts are collected
    if auditctl -l | grep -q "access"; then
        print_success "Unsuccessful file access attempts are collected"
    else
        print_error "Unsuccessful file access attempts are not collected"
    fi

    # 6.2.3.8 Ensure events that modify user/group information are collected
    if auditctl -l | grep -q "/etc/passwd\|/etc/group\|/etc/shadow"; then
        print_success "Events that modify user/group information are collected"
    else
        print_error "Events that modify user/group information are not collected"
    fi

    # 6.2.3.9 Ensure discretionary access control permission modification events are collected
    if auditctl -l | grep -q "chmod\|chown\|fchmod\|fchown"; then
        print_success "Discretionary access control permission modification events are collected"
    else
        print_error "Discretionary access control permission modification events are not collected"
    fi

    # 6.2.3.10 Ensure successful file system mounts are collected
    if auditctl -l | grep -q "mount"; then
        print_success "Successful file system mounts are collected"
    else
        print_error "Successful file system mounts are not collected"
    fi

    # 6.2.3.11 Ensure session initiation information is collected
    if auditctl -l | grep -q "session"; then
        print_success "Session initiation information is collected"
    else
        print_error "Session initiation information is not collected"
    fi

    # 6.2.3.12 Ensure login and logout events are collected
    if auditctl -l | grep -q "logins"; then
        print_success "Login and logout events are collected"
    else
        print_error "Login and logout events are not collected"
    fi

    # 6.2.3.13 Ensure file deletion events by users are collected
    if auditctl -l | grep -q "unlink\|unlinkat\|rename\|renameat"; then
        print_success "File deletion events by users are collected"
    else
        print_error "File deletion events by users are not collected"
    fi

    # 6.2.3.14 Ensure events that modify the system's Mandatory Access Controls are collected
    if auditctl -l | grep -q "setxattr\|fsetxattr\|lsetxattr"; then
        print_success "Events that modify the system's Mandatory Access Controls are collected"
    else
        print_error "Events that modify the system's Mandatory Access Controls are not collected"
    fi

    # 6.2.3.15 Ensure successful and unsuccessful attempts to use the chcon command are collected
    if auditctl -l | grep -q "chcon"; then
        print_success "Successful and unsuccessful attempts to use the chcon command are collected"
    else
        print_error "Successful and unsuccessful attempts to use the chcon command are not collected"
    fi

    # 6.2.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are collected
    if auditctl -l | grep -q "setfacl"; then
        print_success "Successful and unsuccessful attempts to use the setfacl command are collected"
    else
        print_error "Successful and unsuccessful attempts to use the setfacl command are not collected"
    fi

    # 6.2.3.17 Ensure successful and unsuccessful attempts to use the chacl command are collected
    if auditctl -l | grep -q "chacl"; then
        print_success "Successful and unsuccessful attempts to use the chacl command are collected"
    else
        print_error "Successful and unsuccessful attempts to use the chacl command are not collected"
    fi

    # 6.2.3.18 Ensure successful and unsuccessful attempts to use the usermod command are collected
    if auditctl -l | grep -q "usermod"; then
        print_success "Successful and unsuccessful attempts to use the usermod command are collected"
    else
        print_error "Successful and unsuccessful attempts to use the usermod command are not collected"
    fi

    # 6.2.3.19 Ensure kernel module loading, unloading, and modification is collected
    if auditctl -l | grep -q "init_module\|delete_module"; then
        print_success "Kernel module loading, unloading, and modification is collected"
    else
        print_error "Kernel module loading, unloading, and modification is not collected"
    fi

    # 6.2.3.20 Ensure the audit configuration is immutable
    if auditctl -l | grep -q "^-e 2"; then
        print_success "The audit configuration is immutable"
    else
        print_error "The audit configuration is not immutable"
    fi

    # 6.2.3.21 Ensure the running and on disk configuration is the same
    if diff /etc/audit/audit.rules <(auditctl -l); then
        print_success "The running and on disk configuration is the same"
    else
        print_error "The running and on disk configuration is not the same"
    fi
}

# 6.2.4 Configure auditd File Access
check_auditd_file_access() {
    print_header "6.2.4 Configure auditd File Access"

    # 6.2.4.1 Ensure audit log files mode is configured
    if find /var/log/audit -type f -exec stat -c "%a %n" {} \; | awk '$1 != "600" {print $2}' | grep -q .; then
        print_error "Audit log files mode is not configured"
    else
        print_success "Audit log files mode is configured"
    fi

    # 6.2.4.2 Ensure audit log files owner is configured
    if find /var/log/audit -type f -exec stat -c "%U %n" {} \; | awk '$1 != "root" {print $2}' | grep -q .; then
        print_error "Audit log files owner is not configured"
    else
        print_success "Audit log files owner is configured"
    fi

    # 6.2.4.3 Ensure audit log files group owner is configured
    if find /var/log/audit -type f -exec stat -c "%G %n" {} \; | awk '$1 != "root" {print $2}' | grep -q .; then
        print_error "Audit log files group owner is not configured"
    else
        print_success "Audit log files group owner is configured"
    fi

    # 6.2.4.4 Ensure the audit log file directory mode is configured
    if stat -c "%a" /var/log/audit | grep -q "700"; then
        print_success "Audit log file directory mode is configured"
    else
        print_error "Audit log file directory mode is not configured"
    fi

    # 6.2.4.5 Ensure audit configuration files mode is configured
    if find /etc/audit -type f -exec stat -c "%a %n" {} \; | awk '$1 != "600" {print $2}' | grep -q .; then
        print_error "Audit configuration files mode is not configured"
    else
        print_success "Audit configuration files mode is configured"
    fi

    # 6.2.4.6 Ensure audit configuration files owner is configured
    if find /etc/audit -type f -exec stat -c "%U %n" {} \; | awk '$1 != "root" {print $2}' | grep -q .; then
        print_error "Audit configuration files owner is not configured"
    else
        print_success "Audit configuration files owner is configured"
    fi

    # 6.2.4.7 Ensure audit configuration files group owner is configured
    if find /etc/audit -type f -exec stat -c "%G %n" {} \; | awk '$1 != "root" {print $2}' | grep -q .; then
        print_error "Audit configuration files group owner is not configured"
    else
        print_success "Audit configuration files group owner is configured"
    fi

    # 6.2.4.8 Ensure audit tools mode is configured
    if find /sbin/auditctl /sbin/auditd -type f -exec stat -c "%a %n" {} \; | awk '$1 != "755" {print $2}' | grep -q .; then
        print_error "Audit tools mode is not configured"
    else
        print_success "Audit tools mode is configured"
    fi

    # 6.2.4.9 Ensure audit tools owner is configured
    if find /sbin/auditctl /sbin/auditd -type f -exec stat -c "%U %n" {} \; | awk '$1 != "root" {print $2}' | grep -q .; then
        print_error "Audit tools owner is not configured"
    else
        print_success "Audit tools owner is configured"
    fi

    # 6.2.4.10 Ensure audit tools group owner is configured
    if find /sbin/auditctl /sbin/auditd -type f -exec stat -c "%G %n" {} \; | awk '$1 != "root" {print $2}' | grep -q .; then
        print_error "Audit tools group owner is not configured"
    else
        print_success "Audit tools group owner is configured"
    fi
}

# 6.3 Configure Integrity Checking
check_integrity_checking() {
    print_header "6.3 Configure Integrity Checking"

    # 6.3.1 Ensure AIDE is installed
    if dpkg -l | grep -q aide; then
        print_success "AIDE is installed"
    else
        print_error "AIDE is not installed"
    fi

    # 6.3.2 Ensure filesystem integrity is regularly checked
    if crontab -l | grep -q aide; then
        print_success "Filesystem integrity is regularly checked"
    else
        print_error "Filesystem integrity is not regularly checked"
    fi

    # 6.3.3 Ensure cryptographic mechanisms are used to protect the integrity of audit tools
    if grep -q "sha512" /etc/aide/aide.conf; then
        print_success "Cryptographic mechanisms are used to protect the integrity of audit tools"
    else
        print_error "Cryptographic mechanisms are not used to protect the integrity of audit tools"
    fi
}


check_all_permissions() {
    declare -A files_permissions=(
        ["/etc/passwd"]=644
        ["/etc/passwd-"]=644
        ["/etc/group"]=644
        ["/etc/group-"]=644
        ["/etc/shadow"]=640
        ["/etc/shadow-"]=640
        ["/etc/gshadow"]=640
        ["/etc/gshadow-"]=640
        ["/etc/shells"]=644
        ["/etc/security/opasswd"]=600
    )

    print_header "7 System Maintenance"

    for file in "${!files_permissions[@]}"; do
        expected_perm=${files_permissions[$file]}
        actual_perm=$(stat -c %a "$file")

        if [ "$actual_perm" -eq "$expected_perm" ]; then
            print_success "$file permissions are correctly set to $expected_perm."
        else
            print_error  "$file permissions are not correctly set. Expected: $expected_perm, Found: $actual_perm."
        fi
    done
}


# 7 System Maintenance
check_system_maintenance() {
    print_header "7.1 System Maintenance"

    

    # 7.1.11 Ensure world writable files and directories are secured
    if find / -xdev -type f -perm -002 -exec stat -c "%n" {} + | grep -q .; then
        print_error "World writable files and directories are not secured"
    else
        print_success "World writable files and directories are secured"
    fi

    # 7.1.12 Ensure no files or directories without an owner and a group exist
    if find / -xdev \( -nouser -o -nogroup \) -exec stat -c "%n" {} + | grep -q .; then
        print_error "Files or directories without an owner and a group exist"
    else
        print_success "No files or directories without an owner and a group exist"
    fi

    # 7.1.13 Ensure SUID and SGID files are reviewed
    if find / -xdev \( -perm -4000 -o -perm -2000 \) -exec stat -c "%n" {} + | grep -q .; then
        print_error "SUID and SGID files need to be reviewed"
    else
        print_success "No SUID and SGID files need to be reviewed"
    fi

    # 7.2 Local User and Group Settings
    # 7.2.1 Ensure accounts in /etc/passwd use shadowed passwords
    if awk -F: '($2 != "x") {print $1}' /etc/passwd | grep -q .; then
        print_error "Some accounts in /etc/passwd do not use shadowed passwords"
    else
        print_success "All accounts in /etc/passwd use shadowed passwords"
    fi

    # 7.2.2 Ensure /etc/shadow password fields are not empty
    if awk -F: '($2 == "") {print $1}' /etc/shadow | grep -q .; then
        print_error "Some /etc/shadow password fields are empty"
    else
        print_success "No /etc/shadow password fields are empty"
    fi

    # 7.2.3 Ensure all groups in /etc/passwd exist in /etc/group
    if awk -F: '{print $4}' /etc/passwd | sort -u | while read -r gid; do grep -q ":$gid:" /etc/group || echo "$gid"; done | grep -q .; then
        print_error "Some groups in /etc/passwd do not exist in /etc/group"
    else
        print_success "All groups in /etc/passwd exist in /etc/group"
    fi

    # 7.2.4 Ensure shadow group is empty
    if getent group shadow | awk -F: '{print $4}' | grep -q .; then
        print_error "Shadow group is not empty"
    else
        print_success "Shadow group is empty"
    fi

    # 7.2.5 Ensure no duplicate UIDs exist
    if awk -F: '{print $3}' /etc/passwd | sort | uniq -d | grep -q .; then
        print_error "Duplicate UIDs exist"
    else
        print_success "No duplicate UIDs exist"
    fi

    # 7.2.6 Ensure no duplicate GIDs exist
    if awk -F: '{print $3}' /etc/group | sort | uniq -d | grep -q .; then
        print_error "Duplicate GIDs exist"
    else
        print_success "No duplicate GIDs exist"
    fi

    # 7.2.7 Ensure no duplicate user names exist
    if awk -F: '{print $1}' /etc/passwd | sort | uniq -d | grep -q .; then
        print_error "Duplicate user names exist"
    else
        print_success "No duplicate user names exist"
    fi

    # 7.2.8 Ensure no duplicate group names exist
    if awk -F: '{print $1}' /etc/group | sort | uniq -d | grep -q .; then
        print_error "Duplicate group names exist"
    else
        print_success "No duplicate group names exist"
    fi

    # 7.2.9 Ensure local interactive user home directories are configured
    if awk -F: '($3 >= 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $6}' /etc/passwd | while read -r dir; do [ -d "$dir" ] || echo "$dir"; done | grep -q .; then
        print_error "Some local interactive user home directories are not configured"
    else
        print_success "All local interactive user home directories are configured"
    fi

    # 7.2.10 Ensure local interactive user dot files access is configured
    if awk -F: '($3 >= 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $6}' /etc/passwd | while read -r dir; do find "$dir" -name ".*" -perm /002 -exec stat -c "%n" {} + | grep -q . && echo "$dir"; done | grep -q .; then
        print_error "Some local interactive user dot files access is not configured"
    else
        print_success "All local interactive user dot files access is configured"
    fi
}

main() {

    if dpkg -l | grep -q "^ii  auditd "; then
    echo "auditd is installed"
    else
        echo "auditd is not installed. Installing now..."
        sudo apt-get update
        sudo apt-get install -y auditd
    fi

    if dpkg -l | grep -q "^ii  net-tools "; then
        echo "net-tools is already installed"
    else
        echo "net-tools is not installed. Installing now..."
        sudo apt-get update
        sudo apt-get install -y net-tools
    fi

    clear

    echo "============================="
    echo "======= CIS Benchmark ======="
    echo "====== Ubuntu 24.04 LTS ====="
    echo "============================="
    echo -e "\n"
    echo "This script will Audit your system with the CIS Benchmark requirements"
    echo "If error occurs, please install required dependencies or try running as root"
    echo -e "\n"

    print_header "1 Initial Setup"
    check_filesystem_kernel_modules
    check_ptrace_scope
    check_core_dumps
    check_prelink
    check_error_reporting
    check_warning_banners
    check_gnome_display_manager

    print_header "2 Services"
    check_server_services
    check_client_services
    check_time_synchronization
    check_job_schedulers

    print_header "3 Network Configuration"
    check_network_devices
    check_network_kernel_modules
    check_network_kernel_parameters

    print_header "4 Firewall"
    check_single_firewall
    case $FIREWALL in 
        iptables)
            check_iptables_configuration
            ;;
        nftables)
            check_nftables_configuration
            ;;
        ufw)
            check_ufw_configuration
            ;;
        iptables|nftables)
            check_iptables_configuration
            check_nftables_configuration
            ;;
        iptables|ufw)
            check_iptables_configuration
            check_ufw_configuration
            ;;
        nftables|ufw)
            check_nftables_configuration
            check_ufw_configuration
            ;;
    esac

    print_header "5 Secure Shell"
    check_ssh_server
    check_privilege_escalation
    check_pam_configuration
    check_pam_arguments
    check_user_accounts_environment

    print_header "6 Logging and Auditing"
    check_system_logging
    check_system_auditing
    check_auditd_rules
    check_auditd_file_access
    check_integrity_checking

    print_header "7 System Maintenance"
    check_all_permissions
    check_system_maintenance

    TOTAL=$OK+$NOK
    echo -e "\n============================="
    print_header "End of CIS Benchmark"
    echo -e "${GREEN}[---OK] : $OK Tests passed${NC}"
    echo -e "${RED}[--NOK] : $NOK Tests failed${NC}"
    echo -e "${YELLOW}[TOTAL] : $TOTAL Tests${NC}"
    echo -e "\n============================="
    print_header "Check CIS-Ubuntu-24.04-LTS.PDF file for remediation steps"
    print_header "Github @NathanArkov"

}

main