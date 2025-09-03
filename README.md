# Fake Wi-Fi Driver

A Linux kernel Wi-Fi driver that simulates a SoftMAC wireless device for testing purposes. This driver demonstrates how to interact with the mac80211 subsystem without requiring real wireless hardware.

## Overview

This driver creates a fake wireless interface that:
- Registers with mac80211 as a SoftMAC driver
- Intercepts probe requests from userspace tools
- Generates fake probe responses with a test AP ("TestAP")
- Provides extensive debug logging for educational purposes

## Architecture

The driver follows the standard Linux wireless driver architecture:

```
Userspace (iw, hostapd, etc.)
           ↓
       mac80211 
           ↓
    fake_wifi driver
           ↓
    (No real hardware)
```

### Key Components

1. **ieee80211_ops Structure**: Interface between driver and mac80211
2. **Probe Request Handling**: Intercepts frames in TX path
3. **Probe Response Generation**: Creates fake responses and injects them
4. **Work Queue**: Handles response generation in process context
5. **Debug Logging**: Extensive pr_info() statements for monitoring

## Files

- `fake_wifi.c` - Main driver implementation
- `Makefile` - Build system for the kernel module
- `README.md` - This documentation

## Building

### Prerequisites

- Linux kernel headers for your running kernel
- Build tools (make, gcc)
- Root access for loading modules

### Build Commands

```bash
# Build the module
make all

# Install module files (optional)
make install

# Clean build artifacts
make clean
```

## Usage

### 1. Load the Driver

```bash
# Load the kernel module
sudo make load

# Or manually:
sudo insmod fake_wifi.ko
```

### 2. Check Driver Status

```bash
# View driver messages
make dmesg

# Or manually:
dmesg | grep fake_wifi
```

Expected output:
```
fake_wifi: Loading Fake Wi-Fi Driver v1.0
fake_wifi: Initializing fake hardware capabilities
fake_wifi: Hardware registered successfully with mac80211
fake_wifi: Fake AP ready - SSID: TestAP, BSSID: 02:00:00:00:00:01
```

### 3. Bring Up Interface

```bash
# Find the interface name (usually wlan0)
ip link show

# Bring interface up
sudo ip link set wlan0 up
```

### 4. Test Probe Request/Response

```bash
# Trigger a scan to generate probe requests
sudo iw dev wlan0 scan trigger

# Check for probe request/response activity
make dmesg
```

Expected output:
```
fake_wifi: *** STARTING FAKE HARDWARE ***
fake_wifi: *** PROBE REQUEST #1 INTERCEPTED ***
fake_wifi: From: aa:bb:cc:dd:ee:ff, To: ff:ff:ff:ff:ff:ff
fake_wifi: Created probe response for aa:bb:cc:dd:ee:ff, SSID: TestAP
fake_wifi: Sent fake probe response #1 to aa:bb:cc:dd:ee:ff
```

### 5. View Scan Results

```bash
# View scan results (should show our fake AP)
sudo iw dev wlan0 scan dump | grep -A 10 -B 5 TestAP
```

### 6. Unload the Driver

```bash
# Unload the module
sudo make unload

# Or manually:
sudo rmmod fake_wifi
```

## Understanding the Code

### Driver Registration

```c
/* Allocate hardware structure with mac80211 */
hw = ieee80211_alloc_hw(sizeof(struct fake_wifi_priv), &fake_wifi_ops);

/* Set capabilities and register */
ieee80211_register_hw(hw);
```

### Probe Request Interception

The driver intercepts frames in the `fake_wifi_tx()` function:

```c
static void fake_wifi_tx(struct ieee80211_hw *hw,
                         struct ieee80211_tx_control *control,
                         struct sk_buff *skb)
{
    /* Check if this is a probe request */
    fake_wifi_handle_probe_request(priv, skb);
    
    /* Simulate successful transmission */
    ieee80211_tx_status(hw, skb);
}
```

### Probe Response Generation

Responses are generated in a work queue to avoid atomic context issues:

```c
/* Create fake probe response frame */
probe_resp = fake_wifi_create_probe_response(priv, mgmt->sa);

/* Inject response back into mac80211 */
ieee80211_rx(priv->hw, probe_resp);
```

## Key mac80211 APIs Used

- `ieee80211_alloc_hw()` - Allocate hardware structure
- `ieee80211_register_hw()` - Register with mac80211
- `ieee80211_tx_status()` - Report TX completion
- `ieee80211_rx()` - Inject received frames
- `ieee80211_unregister_hw()` - Unregister from mac80211
- `ieee80211_free_hw()` - Free hardware structure

## Debugging

### Enable Debug Messages

```bash
# Enable all debug messages
echo 8 > /proc/sys/kernel/printk

# Or add debug parameter to module
sudo insmod fake_wifi.ko debug=1
```

### Common Issues

1. **Module won't load**: Check kernel version compatibility
2. **No interface created**: Check dmesg for registration errors  
3. **No probe requests**: Ensure interface is up and scanning
4. **Permission denied**: Most operations require root privileges

### Monitoring

```bash
# Watch real-time kernel messages
sudo dmesg -w | grep fake_wifi

# Monitor interface status
watch -n 1 'ip link show; echo; iw dev'

# Check module status
lsmod | grep fake_wifi
```

## Educational Value

This driver demonstrates:

1. **SoftMAC Architecture**: How drivers interact with mac80211
2. **Frame Handling**: TX/RX frame processing in the kernel
3. **Work Queues**: Deferring work to process context
4. **IEEE 802.11**: Basic frame formats and management frames
5. **Kernel Module Development**: Module lifecycle and error handling

## Testing Scenarios

### Basic Functionality
```bash
# 1. Load driver and verify
sudo make load
make dmesg

# 2. Test interface creation
ip link show | grep wlan

# 3. Test probe handling
sudo iw dev wlan0 scan trigger
make dmesg
```

### Advanced Testing
```bash
# Monitor with tcpdump (if supported)
sudo tcpdump -i wlan0 -s 0 -w capture.pcap

# Test with different scan types
sudo iw dev wlan0 scan trigger freq 2437
sudo iw dev wlan0 scan trigger ssid TestAP

# Check statistics
cat /proc/net/wireless
```

## Limitations

- Single channel support (2437 MHz)
- No encryption support
- Simplified frame handling
- No real RF transmission
- Basic error handling

## Extending the Driver

To add more functionality:

1. **Multiple Channels**: Expand supported_band structure
2. **Encryption**: Implement crypto operations
3. **Multiple APs**: Handle multiple BSSID responses
4. **Association**: Implement auth/assoc frame handling
5. **Data Frames**: Add data packet simulation

## License

GPL v2 - Compatible with Linux kernel licensing requirements.

## References

- [Linux Wireless Documentation](https://wireless.wiki.kernel.org/)
- [mac80211 API Reference](https://www.kernel.org/doc/html/latest/driver-api/80211/mac80211.html)
- [ath9k Driver Source](https://github.com/torvalds/linux/tree/master/drivers/net/wireless/ath/ath9k)
- [IEEE 802.11 Standard](https://standards.ieee.org/standard/802_11-2020.html)
# FakeWiFiDriver
# FakeWiFiDriver
