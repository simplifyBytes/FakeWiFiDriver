#!/bin/bash

# Example usage script for the Fake Wi-Fi Driver
# This demonstrates a typical workflow for testing the driver

echo "=== Fake Wi-Fi Driver Example Usage ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "Step 1: Building the driver..."
make all

echo
echo "Step 2: Loading the driver..."
make load

echo
echo "Step 3: Checking if driver loaded successfully..."
if lsmod | grep -q fake_wifi; then
    echo "✓ Driver loaded successfully"
else
    echo "✗ Driver failed to load"
    exit 1
fi

echo
echo "Step 4: Viewing initial driver messages..."
dmesg | grep fake_wifi | tail -5

echo
echo "Step 5: Finding wireless interface..."
INTERFACE=$(ip link show | grep wlan | head -1 | cut -d: -f2 | tr -d ' ' 2>/dev/null)
if [ -n "$INTERFACE" ]; then
    echo "✓ Found interface: $INTERFACE"
else
    echo "✗ No wireless interface found"
    echo "This might be normal - mac80211 may not create interface immediately"
fi

echo
echo "Step 6: Bringing interface up (if it exists)..."
if [ -n "$INTERFACE" ]; then
    ip link set $INTERFACE up
    echo "✓ Interface $INTERFACE brought up"
    ip link show $INTERFACE
else
    echo "Skipping - no interface available"
fi

echo
echo "Step 7: Triggering probe request..."
if [ -n "$INTERFACE" ]; then
    echo "Sending scan trigger to generate probe request..."
    iw dev $INTERFACE scan trigger 2>/dev/null || echo "Scan trigger sent (errors are normal for fake hardware)"
else
    echo "Cannot trigger scan without interface"
fi

echo
echo "Step 8: Checking for probe request/response activity..."
sleep 2
echo "Recent driver messages:"
dmesg | grep fake_wifi | tail -10

echo
echo "Step 9: Testing complete!"
echo
echo "To continue testing manually:"
echo "- Monitor messages: make dmesg"
echo "- Trigger more scans: sudo iw dev $INTERFACE scan trigger"
echo "- View scan results: sudo iw dev $INTERFACE scan dump"
echo "- Unload driver: make unload"

echo
echo "For more comprehensive testing, use: sudo ./test_driver.sh test"
