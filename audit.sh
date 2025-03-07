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


# 1.1.1 Configure Filesystem Kernel Modules
check_filesystem_kernel_modules() {
    print_header "1.1.1 Configure Filesystem Kernel Modules"
    modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "overlayfs" "squashfs" "udf" "usb-storage")
    for module in "${modules[@]}"; do
        if lsmod | grep -q "$module"; then
            # echo "Checking $module module..."
            if grep -qE "/bin/true|/bin/false" /etc/modprobe.d/*; then
                print_success "$module has /bin/true or /bin/false entry"
            else
                print_error "$module does not have /bin/true or /bin/false entry"
            fi

            if grep -q "blacklist $module" /etc/modprobe.d/*; then
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

main() {
    echo "============================="
    echo "======= CIS Benchmark ======="
    echo "====== Ubuntu 24.04 LTS ====="
    echo "============================="

    check_filesystem_kernel_modules
    check_ptrace_scope
    check_core_dumps
    check_prelink
    check_error_reporting
    check_warning_banners
    check_gnome_display_manager

}

main