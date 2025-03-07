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
    echo -e "${GREEN}[-OK]${NC} $1"
}

# Function to display error messages
print_error() {
    echo -e "${RED}[NOK]${NC} $1"
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
            if stat -c "%a" "$file" | grep -qE "^[0-7]00$"; then
                print_success "Permissions on $file are configured"
            else
                print_error "Permissions on $file are not configured"
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
    if [ "$(stat -c %a /etc/ssh/sshd_config)" -eq 600 ]; then
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

main() {
    echo "============================="
    echo "======= CIS Benchmark ======="
    echo "====== Ubuntu 24.04 LTS ====="
    echo "============================="

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
    check_ufw_configuration
    # check_nftables_configuration
    # check_iptables_configuration

    print_header "5 Secure Shell"
    check_ssh_server


}

main