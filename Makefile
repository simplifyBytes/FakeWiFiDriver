# Makefile for Fake Wi-Fi Driver
# This builds a Linux kernel module

# Module name
obj-m := fake_wifi.o

# Add debug flags for better crash analysis
ccflags-y += -g -O1 -DDEBUG

# Kernel source directory (adjust as needed for your system)
KERNEL_SRC := /lib/modules/$(shell uname -r)/build

# Default target
all:
	make -C $(KERNEL_SRC) M=$(PWD) modules

# Clean target
clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean

# Install target (requires root)
install: all
	sudo make -C $(KERNEL_SRC) M=$(PWD) modules_install

# Debug targets for crash analysis
debug: ccflags-y += -g -O1 -DDEBUG
debug: all

symbols:
	nm fake_wifi.ko | grep -E "(fake_wifi|init|exit)"

disasm:
	objdump -d fake_wifi.ko > fake_wifi.disasm

addr2line:
	@echo "Usage: make addr2line ADDR=0x1234 FUNC=function_name"
	@echo "Example: make addr2line ADDR=0x1a8 FUNC=fake_wifi_init_hw"

addr2line:
ifdef ADDR
ifdef FUNC
	@echo "Resolving $(FUNC)+$(ADDR):"
	@objdump -t fake_wifi.ko | grep $(FUNC) | awk '{print $$1}' | while read func_addr; do \
		actual_addr=$$(printf "0x%x" $$((0x$$func_addr + $(ADDR)))); \
		echo "Function address: 0x$$func_addr, Offset: $(ADDR), Actual: $$actual_addr"; \
		addr2line -e fake_wifi.ko -f -C $$actual_addr; \
	done
else
	@echo "Error: Please specify FUNC=function_name"
endif
else
	@echo "Error: Please specify ADDR=0x1234"
endif
	sudo depmod -a

# Load the module (requires root)
load: all
	sudo insmod fake_wifi.ko

# Unload the module (requires root)
unload:
	sudo rmmod fake_wifi

# Show module information
info:
	modinfo fake_wifi.ko

# Show kernel messages related to our driver
dmesg:
	dmesg | grep -i fake_wifi | tail -20

# Test the driver by triggering a scan
test:
	@echo "Testing fake Wi-Fi driver..."
	@echo "1. Bringing interface up..."
	sudo ip link set wlan0 up || echo "Interface might not exist yet"
	@echo "2. Triggering scan..."
	sudo iw dev wlan0 scan trigger || echo "Scan trigger failed - this is expected if interface doesn't exist"
	@echo "3. Check dmesg for fake_wifi messages:"
	dmesg | grep -i fake_wifi | tail -10

# Help target
help:
	@echo "Fake Wi-Fi Driver Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all      - Build the kernel module"
	@echo "  clean    - Clean build files"
	@echo "  install  - Install the module (requires root)"
	@echo "  load     - Load the module (requires root)"
	@echo "  unload   - Unload the module (requires root)"
	@echo "  info     - Show module information"
	@echo "  dmesg    - Show recent kernel messages from our driver"
	@echo "  test     - Test the driver with a scan trigger"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make all          # Build the module"
	@echo "  make load         # Load the module into kernel"
	@echo "  make test         # Test probe request/response"
	@echo "  make dmesg        # Check driver messages"
	@echo "  make unload       # Remove module from kernel"

.PHONY: all clean install load unload info dmesg test help
