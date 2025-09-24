#!/bin/bash

# Safe module testing script
set -e

echo "Testing fake_wifi module safely..."

# Remove module if loaded
sudo rmmod fake_wifi 2>/dev/null || true

# Clear dmesg buffer
sudo dmesg -C

echo "Loading module with timeout protection..."

# Use timeout to prevent system freeze
timeout 10s sudo insmod fake_wifi.ko || {
    echo "Module load timed out or failed"
    sudo dmesg | tail -20
    exit 1
}

echo "Module loaded successfully, checking dmesg..."
sudo dmesg

echo "Checking if interface was created..."
ip link show | grep wlan || echo "No wlan interface found"

echo "Removing module..."
sudo rmmod fake_wifi

echo "Test completed"
