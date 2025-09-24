#!/bin/bash

# ==============================================================================
# Quick Crash Address Resolver for Raspberry Pi 3B
# This script helps quickly resolve crash addresses to source code lines
# ==============================================================================

# Configuration
MODULE_NAME="fake_wifi"
PI_HOST="192.168.1.19"
PI_USER="pi"
PI_PASS="123"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Quick Crash Address Resolver ===${NC}"

# Function to resolve a single address
resolve_single_address() {
    local function_name="$1"
    local offset="$2"
    
    echo -e "${YELLOW}Resolving: ${function_name}+${offset}${NC}"
    
    if [ ! -f "${MODULE_NAME}.ko" ]; then
        echo -e "${RED}Error: ${MODULE_NAME}.ko not found. Please build the module first.${NC}"
        return 1
    fi
    
    # Get function address from symbol table
    func_addr=$(nm "${MODULE_NAME}.ko" | grep " ${function_name}$" | awk '{print $1}')
    
    if [ -z "$func_addr" ]; then
        echo -e "${RED}Function ${function_name} not found in symbol table${NC}"
        echo "Available functions:"
        nm "${MODULE_NAME}.ko" | grep " fake_wifi" | head -10
        return 1
    fi
    
    # Convert offset to decimal if it's hex
    if [[ $offset == 0x* ]]; then
        offset_dec=$((offset))
    else
        offset_dec=$((0x$offset))
    fi
    
    # Calculate actual address
    func_addr_dec=$((0x$func_addr))
    actual_addr=$((func_addr_dec + offset_dec))
    
    printf "${GREEN}Function base address: 0x%x${NC}\n" $func_addr_dec
    printf "${GREEN}Offset: 0x%x (%d)${NC}\n" $offset_dec $offset_dec
    printf "${GREEN}Actual address: 0x%x${NC}\n" $actual_addr
    
    # Use addr2line to get source location
    if command -v addr2line &> /dev/null; then
        echo -e "${BLUE}Source location:${NC}"
        addr2line -e "${MODULE_NAME}.ko" -f -C -s $actual_addr
        echo ""
        
        # Get the source file and line number
        source_info=$(addr2line -e "${MODULE_NAME}.ko" -s $actual_addr)
        if [[ $source_info != "??:0" ]] && [[ $source_info != "??:?" ]]; then
            file=$(echo $source_info | cut -d: -f1)
            line=$(echo $source_info | cut -d: -f2)
            
            if [ -f "$file" ] && [ "$line" != "0" ] && [ "$line" != "?" ]; then
                echo -e "${BLUE}Source code around line ${line}:${NC}"
                echo "----------------------------------------"
                
                # Show source code around the crash line
                start_line=$((line - 5))
                end_line=$((line + 5))
                if [ $start_line -lt 1 ]; then start_line=1; fi
                
                sed -n "${start_line},${end_line}p" "$file" | nl -ba -v$start_line | \
                while IFS= read -r source_line; do
                    line_num=$(echo "$source_line" | awk '{print $1}')
                    if [ "$line_num" = "$line" ]; then
                        echo -e "${RED}>>> $source_line <<<${NC}"
                    else
                        echo "    $source_line"
                    fi
                done
                echo "----------------------------------------"
            fi
        fi
    else
        echo -e "${RED}addr2line not available. Install it with: sudo apt install binutils${NC}"
    fi
    
    # Show disassembly around the address
    echo -e "${BLUE}Disassembly around crash:${NC}"
    objdump -d "${MODULE_NAME}.ko" --start-address=$((actual_addr - 32)) --stop-address=$((actual_addr + 32)) | \
    while IFS= read -r line; do
        if echo "$line" | grep -q "$(printf "%x" $actual_addr)"; then
            echo -e "${RED}>>> $line <<<${NC}"
        else
            echo "    $line"
        fi
    done
}

# Function to parse crash log and extract addresses
parse_crash_log() {
    local log_file="$1"
    
    if [ ! -f "$log_file" ]; then
        echo -e "${RED}Error: Log file '$log_file' not found${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Parsing crash log: $log_file${NC}"
    echo "========================================"
    
    # Extract crash information for ARM64 (Raspberry Pi)
    grep -E "(pc :|Call trace:|fake_wifi)" "$log_file" | while IFS= read -r line; do
        echo -e "${YELLOW}$line${NC}"
        
        # ARM64 format: pc : function_name+0x1a8/0x1f0 [module_name]
        if echo "$line" | grep -qE "pc :.*fake_wifi.*\+0x"; then
            func=$(echo "$line" | sed -n 's/.*pc : \([^+]*\)+.*/\1/p' | tr -d ' ')
            offset=$(echo "$line" | sed -n 's/.*+\(0x[0-9a-f]*\).*/\1/p')
            
            if [ ! -z "$func" ] && [ ! -z "$offset" ]; then
                echo ""
                resolve_single_address "$func" "$offset"
                echo ""
            fi
        fi
        
        # Also check for direct addresses in call trace
        if echo "$line" | grep -qE "\[<[0-9a-f]+>\].*fake_wifi"; then
            addr=$(echo "$line" | sed -n 's/.*\[<\([0-9a-f]*\)>\].*/\1/p')
            if [ ! -z "$addr" ]; then
                echo "Direct address found: 0x$addr"
                # This would need module load address calculation
            fi
        fi
    done
}

# Function to get latest crash from Pi
get_latest_crash() {
    echo -e "${BLUE}Fetching latest crash from Raspberry Pi...${NC}"
    
    # Get recent dmesg and look for crashes
    crash_file="latest_crash_$(date +%Y%m%d_%H%M%S).log"
    
    sshpass -p "$PI_PASS" ssh -o StrictHostKeyChecking=no ${PI_USER}@${PI_HOST} \
        "sudo dmesg | grep -A 50 -B 10 -E '(BUG:|Oops|Call trace|pc :).*fake_wifi'" > "$crash_file" 2>/dev/null
    
    if [ -s "$crash_file" ]; then
        echo -e "${GREEN}Crash log saved as: $crash_file${NC}"
        parse_crash_log "$crash_file"
    else
        echo -e "${YELLOW}No recent crashes found involving fake_wifi module${NC}"
        rm -f "$crash_file"
        
        # Try to get general kernel messages
        sshpass -p "$PI_PASS" ssh -o StrictHostKeyChecking=no ${PI_USER}@${PI_HOST} \
            "sudo dmesg | tail -30" > "recent_dmesg.log"
        echo -e "${BLUE}Recent dmesg saved as: recent_dmesg.log${NC}"
    fi
}

# Show help
show_help() {
    echo "Quick Crash Address Resolver"
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  resolve <function> <offset>   - Resolve specific function+offset"
    echo "    Example: $0 resolve fake_wifi_init_hw 0x1a8"
    echo ""
    echo "  parse <log_file>             - Parse crash from log file"
    echo "    Example: $0 parse crash.log"
    echo ""
    echo "  fetch                        - Get latest crash from Pi"
    echo ""
    echo "  help                         - Show this help"
}

# Main logic
case "$1" in
    "resolve")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo -e "${RED}Error: Please specify function and offset${NC}"
            echo "Usage: $0 resolve <function> <offset>"
            echo "Example: $0 resolve fake_wifi_init_hw 0x1a8"
            exit 1
        fi
        resolve_single_address "$2" "$3"
        ;;
    "parse")
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Please specify log file${NC}"
            echo "Usage: $0 parse <log_file>"
            exit 1
        fi
        parse_crash_log "$2"
        ;;
    "fetch")
        get_latest_crash
        ;;
    "help"|"-h"|"--help"|"")
        show_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac