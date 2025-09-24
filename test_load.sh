#!/bin/bash

# Safe module loading test script
# This script tries to load the module and monitor dmesg for any issues

echo "=== Fake WiFi Driver Load Test ==="
echo "Clearing dmesg buffer..."
sudo dmesg -C

echo "Removing any existing module..."
sudo rmmod fake_wifi 2>/dev/null || true

echo "Loading the module..."
timeout 10s sudo insmod fake_wifi.ko

if [ $? -eq 0 ]; then
    echo "Module loaded successfully!"
    echo "Checking dmesg for any warnings/errors..."
    sudo dmesg | tail -20
    
    echo ""
    echo "Module info:"
    lsmod | grep fake_wifi
    
    echo ""
    echo "Network interfaces:"
    ip link show | grep -A2 -B2 wlan || echo "No wlan interface found"
    
    echo ""
    echo "Waiting 5 seconds..."
    sleep 5
    
    echo "Removing module..."
    sudo rmmod fake_wifi
    
    echo "Final dmesg check:"
    sudo dmesg | tail -10
    
else
    echo "Module load failed or timed out!"
    echo "Checking dmesg for errors..."
    sudo dmesg | tail -20
fi

echo "=== Test Complete ==="
