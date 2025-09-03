#!/bin/bash

# Fake Wi-Fi Driver Test Script
# This script provides comprehensive testing for the fake wifi driver

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to wait for user input
wait_for_user() {
    read -p "Press Enter to continue..."
}

# Function to show kernel messages
show_driver_messages() {
    print_status "Recent fake_wifi kernel messages:"
    echo "----------------------------------------"
    dmesg | grep -i fake_wifi | tail -10 || echo "No messages found"
    echo "----------------------------------------"
}

# Function to test driver loading
test_driver_loading() {
    print_status "Testing driver loading..."
    
    # Check if module is already loaded
    if lsmod | grep -q fake_wifi; then
        print_warning "Driver already loaded, unloading first..."
        rmmod fake_wifi || true
        sleep 1
    fi
    
    # Load the driver
    print_status "Loading fake_wifi driver..."
    if insmod fake_wifi.ko; then
        print_success "Driver loaded successfully"
    else
        print_error "Failed to load driver"
        return 1
    fi
    
    sleep 2
    show_driver_messages
}

# Function to test interface creation
test_interface_creation() {
    print_status "Testing interface creation..."
    
    # Look for wireless interfaces
    print_status "Available network interfaces:"
    ip link show | grep -E "(wlan|wl)" || print_warning "No wireless interfaces found"
    
    # Check for our fake interface
    if ip link show | grep -q wlan; then
        INTERFACE=$(ip link show | grep wlan | head -1 | cut -d: -f2 | tr -d ' ')
        print_success "Found wireless interface: $INTERFACE"
        
        # Bring interface up
        print_status "Bringing interface $INTERFACE up..."
        if ip link set $INTERFACE up; then
            print_success "Interface brought up successfully"
        else
            print_error "Failed to bring interface up"
            return 1
        fi
        
        sleep 1
        ip link show $INTERFACE
        return 0
    else
        print_error "No wireless interface found"
        return 1
    fi
}

# Function to test probe request/response
test_probe_handling() {
    print_status "Testing probe request/response handling..."
    
    # Find wireless interface
    INTERFACE=$(ip link show | grep wlan | head -1 | cut -d: -f2 | tr -d ' ' 2>/dev/null || echo "")
    
    if [ -z "$INTERFACE" ]; then
        print_error "No wireless interface found for testing"
        return 1
    fi
    
    print_status "Using interface: $INTERFACE"
    
    # Clear previous messages
    dmesg -c > /dev/null
    
    print_status "Triggering scan to generate probe request..."
    if iw dev $INTERFACE scan trigger; then
        print_success "Scan trigger sent successfully"
    else
        print_warning "Scan trigger may have failed, but this is normal for fake hardware"
    fi
    
    sleep 2
    
    print_status "Checking for probe request/response activity..."
    show_driver_messages
    
    # Check for specific probe messages
    if dmesg | grep -q "PROBE REQUEST.*INTERCEPTED"; then
        print_success "Probe request intercepted successfully!"
    else
        print_warning "No probe request interception detected"
    fi
    
    if dmesg | grep -q "Sent fake probe response"; then
        print_success "Probe response sent successfully!"
    else
        print_warning "No probe response detected"
    fi
}

# Function to test scan results
test_scan_results() {
    print_status "Testing scan results..."
    
    INTERFACE=$(ip link show | grep wlan | head -1 | cut -d: -f2 | tr -d ' ' 2>/dev/null || echo "")
    
    if [ -z "$INTERFACE" ]; then
        print_error "No wireless interface found"
        return 1
    fi
    
    print_status "Attempting to view scan results..."
    if iw dev $INTERFACE scan dump 2>/dev/null | grep -A 10 -B 5 "TestAP"; then
        print_success "Found TestAP in scan results!"
    else
        print_warning "TestAP not found in scan results (this may be normal for fake hardware)"
        print_status "Full scan dump:"
        iw dev $INTERFACE scan dump 2>/dev/null | head -20 || echo "No scan results available"
    fi
}

# Function to show driver statistics
show_statistics() {
    print_status "Driver statistics and status:"
    echo "----------------------------------------"
    
    # Module info
    if lsmod | grep -q fake_wifi; then
        print_success "Module loaded: fake_wifi"
        lsmod | grep fake_wifi
    else
        print_warning "Module not loaded"
    fi
    
    # Interface status
    echo ""
    print_status "Interface status:"
    ip link show | grep -A 1 -B 1 wlan || echo "No wireless interfaces"
    
    # Wireless info
    echo ""
    print_status "Wireless statistics:"
    cat /proc/net/wireless 2>/dev/null || echo "No wireless statistics available"
    
    echo "----------------------------------------"
}

# Function to cleanup
cleanup() {
    print_status "Cleaning up..."
    
    # Bring interface down
    INTERFACE=$(ip link show | grep wlan | head -1 | cut -d: -f2 | tr -d ' ' 2>/dev/null || echo "")
    if [ -n "$INTERFACE" ]; then
        print_status "Bringing interface $INTERFACE down..."
        ip link set $INTERFACE down || true
    fi
    
    # Unload module
    if lsmod | grep -q fake_wifi; then
        print_status "Unloading fake_wifi module..."
        rmmod fake_wifi || true
        print_success "Module unloaded"
    fi
    
    show_driver_messages
}

# Main test function
run_full_test() {
    print_status "Starting comprehensive fake Wi-Fi driver test..."
    echo ""
    
    # Test 1: Driver loading
    print_status "=== Test 1: Driver Loading ==="
    test_driver_loading
    wait_for_user
    
    # Test 2: Interface creation
    print_status "=== Test 2: Interface Creation ==="
    test_interface_creation
    wait_for_user
    
    # Test 3: Probe handling
    print_status "=== Test 3: Probe Request/Response ==="
    test_probe_handling
    wait_for_user
    
    # Test 4: Scan results
    print_status "=== Test 4: Scan Results ==="
    test_scan_results
    wait_for_user
    
    # Show final statistics
    print_status "=== Final Statistics ==="
    show_statistics
    
    print_success "All tests completed!"
}

# Function to show usage
usage() {
    echo "Fake Wi-Fi Driver Test Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  test        Run full test suite"
    echo "  load        Load driver only"
    echo "  probe       Test probe handling only"
    echo "  scan        Test scanning only"
    echo "  status      Show driver status"
    echo "  cleanup     Cleanup and unload driver"
    echo "  monitor     Monitor driver messages in real-time"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 test     # Run complete test suite"
    echo "  sudo $0 load     # Just load the driver"
    echo "  sudo $0 monitor  # Watch driver messages"
}

# Function to monitor driver messages
monitor_messages() {
    print_status "Monitoring fake_wifi driver messages (Ctrl+C to stop)..."
    echo "Watching for kernel messages..."
    echo "----------------------------------------"
    
    # Clear existing messages
    dmesg -c > /dev/null
    
    # Monitor in real-time
    dmesg -w | grep --line-buffered fake_wifi
}

# Main script logic
case "${1:-}" in
    "test")
        check_root
        run_full_test
        ;;
    "load")
        check_root
        test_driver_loading
        ;;
    "probe")
        check_root
        test_probe_handling
        ;;
    "scan")
        check_root
        test_scan_results
        ;;
    "status")
        show_statistics
        show_driver_messages
        ;;
    "cleanup")
        check_root
        cleanup
        ;;
    "monitor")
        monitor_messages
        ;;
    "help"|"--help"|"-h")
        usage
        ;;
    "")
        usage
        ;;
    *)
        print_error "Unknown option: $1"
        usage
        exit 1
        ;;
esac
