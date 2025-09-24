#!/bin/bash

# ==============================================================================
# Enhanced Pi Local Crash Analyzer with Address-to-Line Resolution
# Run this script directly on the Raspberry Pi to analyze kernel crashes
# ==============================================================================

MODULE_NAME="fake_wifi"
CRASH_LOG_DIR="/tmp/crash_logs"
SOURCE_FILE="fake_wifi.c"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Enhanced Pi Local Kernel Crash Analyzer ===${NC}"
echo "Module: $MODULE_NAME"
echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -r)"
echo ""

# Create crash log directory
mkdir -p "$CRASH_LOG_DIR"

# Function to install required debugging tools
install_debug_tools() {
    echo -e "${YELLOW}Installing debugging tools...${NC}"
    
    # Check if tools are already installed
    local need_install=false
    
    if ! command -v addr2line &> /dev/null; then
        echo "addr2line not found"
        need_install=true
    fi
    
    if ! command -v objdump &> /dev/null; then
        echo "objdump not found"
        need_install=true
    fi
    
    if ! command -v nm &> /dev/null; then
        echo "nm not found"
        need_install=true
    fi
    
    if [ "$need_install" = true ]; then
        echo "Installing binutils package..."
        sudo apt-get update -qq && sudo apt-get install -y binutils
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Debug tools installed successfully${NC}"
        else
            echo -e "${RED}❌ Failed to install debug tools${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}✅ All debug tools already available${NC}"
    fi
}

# Function to resolve address to source line with enhanced output
resolve_address_to_line() {
    local function_name="$1"
    local offset="$2"
    local show_asm="${3:-true}"
    
    echo -e "${MAGENTA}🔍 RESOLVING CRASH ADDRESS${NC}"
    echo -e "${CYAN}Function: ${function_name}${NC}"
    echo -e "${CYAN}Offset: ${offset}${NC}"
    echo ""
    
    if [ ! -f "${MODULE_NAME}.ko" ]; then
        echo -e "${RED}❌ Error: ${MODULE_NAME}.ko not found in current directory${NC}"
        echo "Please ensure you're running this script from the module build directory"
        return 1
    fi
    
    # Install tools if needed
    install_debug_tools
    
    # Get function address from symbol table
    echo -e "${BLUE}📍 Looking up function in symbol table...${NC}"
    local func_addr=$(nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] ${function_name}$" | awk '{print $1}')
    
    # Handle inlined functions - if not found, look for likely parent functions
    if [ -z "$func_addr" ]; then
        echo -e "${YELLOW}⚠️ Function '${function_name}' not found in symbol table (likely inlined)${NC}"
        
        # Common inlined function mappings for fake_wifi
        case "$function_name" in
            "fake_wifi_init_hw")
                echo -e "${BLUE}🔍 Checking for inlined function in fake_wifi_init...${NC}"
                func_addr=$(nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] fake_wifi_init$" | awk '{print $1}')
                if [ ! -z "$func_addr" ]; then
                    echo -e "${GREEN}✅ Found parent function fake_wifi_init${NC}"
                    function_name="fake_wifi_init"
                fi
                ;;
            "fake_wifi_setup_bands")
                echo -e "${BLUE}🔍 Checking for inlined function in fake_wifi_start...${NC}"
                func_addr=$(nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] fake_wifi_start$" | awk '{print $1}')
                if [ ! -z "$func_addr" ]; then
                    echo -e "${GREEN}✅ Found parent function fake_wifi_start${NC}"
                    function_name="fake_wifi_start"
                fi
                ;;
        esac
        
        if [ -z "$func_addr" ]; then
            echo -e "${RED}❌ Cannot find function or parent function in symbol table${NC}"
            echo -e "${YELLOW}Available functions matching pattern:${NC}"
            nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt].*$(echo $function_name | cut -d_ -f1-2)" | head -10
            echo ""
            echo -e "${YELLOW}All fake_wifi functions:${NC}"
            nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] fake_wifi" | head -10
            return 1
        fi
    fi
    
    # Convert offset to decimal
    local offset_dec
    if [[ $offset == 0x* ]]; then
        offset_dec=$((offset))
    elif [[ $offset =~ ^[0-9]+$ ]]; then
        offset_dec=$offset
    else
        offset_dec=$((0x$offset))
    fi
    
    # Calculate actual address
    local func_addr_dec=$((0x$func_addr))
    local actual_addr=$((func_addr_dec + offset_dec))
    
    echo -e "${GREEN}✅ Function '${function_name}' located${NC}"
    printf "${GREEN}   Base address: 0x%08x${NC}\n" $func_addr_dec
    printf "${GREEN}   Offset: +0x%x (%d bytes)${NC}\n" $offset_dec $offset_dec
    printf "${GREEN}   Crash address: 0x%08x${NC}\n" $actual_addr
    echo ""
    
    # Use addr2line to resolve to source - try multiple formats
    echo -e "${CYAN}📄 Resolving to source code...${NC}"
    
    # Method 1: Direct address resolution
    local source_info=$(addr2line -e "${MODULE_NAME}.ko" -f -C -s $actual_addr 2>/dev/null)
    local source_result=$?
    
    echo "addr2line command: addr2line -e ${MODULE_NAME}.ko -f -C -s 0x$(printf '%x' $actual_addr)"
    echo "addr2line result: $source_info"
    echo ""
    
    if [ $source_result -eq 0 ] && [[ $source_info != *"??:0"* ]] && [[ $source_info != *"??:?"* ]] && [[ $source_info != "??" ]]; then
        echo -e "${GREEN}✅ Source location resolved:${NC}"
        echo "$source_info" | while IFS= read -r line; do
            echo -e "${CYAN}   $line${NC}"
        done
        echo ""
        
        # Extract file and line number from addr2line output
        local line_info=$(addr2line -e "${MODULE_NAME}.ko" -s $actual_addr 2>/dev/null)
        if [[ $line_info == *":"* ]]; then
            local file=$(echo $line_info | cut -d: -f1)
            local line=$(echo $line_info | cut -d: -f2)
            
            echo -e "${BLUE}📍 Exact crash location: ${file}:${line}${NC}"
            echo ""
            
            # Show source code context
            show_source_context "$file" "$line"
        fi
    else
        echo -e "${YELLOW}⚠️ Could not resolve to source line with addr2line${NC}"
        echo "This could mean:"
        echo "- Module was not compiled with debug symbols (-g)"
        echo "- DWARF debug information is not available"
        echo "- Address is outside the compiled code"
        echo ""
        
        # Try alternative approach - use objdump to find nearby symbols
        echo -e "${BLUE}🔍 Trying alternative analysis...${NC}"
        find_nearest_source_location "$function_name" $offset_dec
    fi
    
    # Show disassembly context if requested
    if [ "$show_asm" = "true" ]; then
        show_disassembly_context "$function_name" $actual_addr $offset_dec
    fi
    
    # Additional analysis
    show_additional_analysis "$function_name" $actual_addr
}

# Function to find nearest source location using objdump
find_nearest_source_location() {
    local function_name="$1"
    local offset_dec="$2"
    
    echo -e "${CYAN}🔧 Analyzing with objdump...${NC}"
    
    # Get function disassembly with line numbers
    local disasm_output=$(objdump -d -l "${MODULE_NAME}.ko" 2>/dev/null | \
                         awk "/^[0-9a-f]+ <${function_name}>:/,/^$|^[0-9a-f]+ <[^>]+>:/" | \
                         head -50)
    
    if [ ! -z "$disasm_output" ]; then
        echo "Function disassembly (first 50 lines):"
        echo "$disasm_output" | while IFS= read -r line; do
            # Highlight lines that might contain source info
            if [[ $line == *".c:"* ]]; then
                echo -e "${GREEN}   $line${NC}"
            elif [[ $line == *"${function_name}+0x"* ]]; then
                echo -e "${YELLOW}   $line${NC}"
            else
                echo "   $line"
            fi
        done
        echo ""
    fi
}

# Function to show source code context with enhanced formatting
show_source_context() {
    local file="$1"
    local crash_line="$2"
    
    # Try to find the source file
    local source_path=""
    if [ -f "$file" ]; then
        source_path="$file"
    elif [ -f "$SOURCE_FILE" ] && [ "$crash_line" != "0" ] && [ "$crash_line" != "?" ]; then
        source_path="$SOURCE_FILE"
        echo -e "${YELLOW}Note: Using $SOURCE_FILE instead of $file${NC}"
    else
        echo -e "${RED}❌ Source file not found: $file${NC}"
        return 1
    fi
    
    if [ "$crash_line" = "0" ] || [ "$crash_line" = "?" ]; then
        echo -e "${YELLOW}⚠️ Invalid line number: $crash_line${NC}"
        return 1
    fi
    
    echo -e "${BLUE}📖 SOURCE CODE CONTEXT (Line ${crash_line}):${NC}"
    echo "File: $source_path"
    echo "=================================================="
    
    local start_line=$((crash_line - 10))
    local end_line=$((crash_line + 10))
    if [ $start_line -lt 1 ]; then start_line=1; fi
    
    # Show source with line numbers and highlight crash line
    sed -n "${start_line},${end_line}p" "$source_path" 2>/dev/null | \
    nl -ba -v$start_line -w4 -s': ' | \
    while IFS= read -r source_line; do
        local line_num=$(echo "$source_line" | sed 's/:.*$//' | tr -d ' ')
        if [ "$line_num" = "$crash_line" ]; then
            echo -e "${RED}${YELLOW}>>> $source_line <<<  💥 CRASH HERE${NC}"
        elif [ $((line_num)) -eq $((crash_line - 1)) ] || [ $((line_num)) -eq $((crash_line + 1)) ]; then
            echo -e "${YELLOW}    $source_line${NC}"
        else
            echo -e "${CYAN}    $source_line${NC}"
        fi
    done
    echo "=================================================="
    echo ""
}

# Function to show disassembly context with enhanced analysis
show_disassembly_context() {
    local function_name="$1"
    local crash_addr="$2"
    local offset_dec="$3"
    
    echo -e "${CYAN}🔧 ASSEMBLY ANALYSIS:${NC}"
    echo "============================================="
    
    # Show function disassembly with addresses
    local asm_output=$(objdump -d "${MODULE_NAME}.ko" 2>/dev/null | \
                      awk "/^[0-9a-f]+ <${function_name}>:/,/^$|^[0-9a-f]+ <[^>]+>:/")
    
    if [ ! -z "$asm_output" ]; then
        echo "$asm_output" | head -30 | while IFS= read -r asm_line; do
            # Extract address from assembly line
            local line_addr=$(echo "$asm_line" | grep -o '^[0-9a-f]\+' | head -1)
            
            if [ ! -z "$line_addr" ]; then
                local line_addr_dec=$((0x$line_addr))
                local line_offset=$((line_addr_dec - $(nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] ${function_name}$" | awk '{print "0x" $1}')))
                
                # Highlight the crash offset area
                if [ $line_offset -eq $offset_dec ]; then
                    echo -e "${RED}${YELLOW}>>> $asm_line <<<  💥 CRASH POINT${NC}"
                elif [ $line_offset -ge $((offset_dec - 8)) ] && [ $line_offset -le $((offset_dec + 8)) ]; then
                    echo -e "${YELLOW}    $asm_line  (±$(($line_offset - offset_dec)) bytes)${NC}"
                else
                    echo "    $asm_line"
                fi
            else
                echo "    $asm_line"
            fi
        done
    else
        echo -e "${YELLOW}No disassembly found for function $function_name${NC}"
    fi
    
    echo "============================================="
    echo ""
}

# Function to show additional crash analysis
show_additional_analysis() {
    local function_name="$1"
    local crash_addr="$2"
    
    echo -e "${MAGENTA}📊 ADDITIONAL ANALYSIS:${NC}"
    echo "============================================="
    
    # Show function size and crash position using objdump instead of nm for better accuracy
    echo -e "${BLUE}Function Size Analysis:${NC}"
    local func_info=$(objdump -t "${MODULE_NAME}.ko" 2>/dev/null | grep -E " ${function_name}$")
    
    if [ ! -z "$func_info" ]; then
        local func_start=$(echo "$func_info" | awk '{print "0x" $1}')
        local func_size=$(echo "$func_info" | awk '{print "0x" $5}')
        
        if [ ! -z "$func_start" ] && [ ! -z "$func_size" ] && [ "$func_size" != "0x" ]; then
            local func_start_dec=$((func_start))
            local func_size_dec=$((func_size))
            local crash_position=$(( crash_addr - func_start_dec ))
            
            if [ $func_size_dec -gt 0 ]; then
                local percentage=$(( (crash_position * 100) / func_size_dec ))
                printf "  Function start: 0x%08x\n" $func_start_dec
                printf "  Function size:  %d bytes (0x%x)\n" $func_size_dec $func_size_dec
                printf "  Crash offset:   %d bytes (%.1f%% into function)\n" $crash_position $percentage
            else
                printf "  Function start: 0x%08x\n" $func_start_dec
                printf "  Crash offset:   %d bytes\n" $crash_position
            fi
        else
            echo "  Size information not available from objdump"
        fi
    else
        # Fallback: estimate size using next function
        echo -e "${YELLOW}Using nm-based size estimation:${NC}"
        local func_start_nm=$(nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] ${function_name}$" | awk '{print "0x" $1}')
        if [ ! -z "$func_start_nm" ]; then
            local func_start_dec=$((func_start_nm))
            local crash_position=$(( crash_addr - func_start_dec ))
            printf "  Function start: 0x%08x\n" $func_start_dec
            printf "  Crash offset:   %d bytes\n" $crash_position
            
            # Try to find next function for size estimation
            local next_func_addr=$(nm "${MODULE_NAME}.ko" 2>/dev/null | \
                                   grep -E " [Tt] " | \
                                   awk -v start="$func_start_nm" '$1 > start {print "0x" $1; exit}')
            if [ ! -z "$next_func_addr" ]; then
                local estimated_size=$(( next_func_addr - func_start_dec ))
                if [ $estimated_size -gt 0 ] && [ $estimated_size -lt 10000 ]; then
                    local percentage=$(( (crash_position * 100) / estimated_size ))
                    printf "  Estimated size: %d bytes (0x%x)\n" $estimated_size $estimated_size
                    printf "  Position:       %.1f%% into function\n" $percentage
                fi
            fi
        fi
    fi
    echo ""
    
    # Show nearby functions with correct sorting
    echo -e "${BLUE}Nearby Functions:${NC}"
    nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] " | \
    sort -k1,1 | \
    awk -v target="$function_name" '
    {
        addr[NR] = $1; type[NR] = $2; func[NR] = $3
        if ($3 == target) target_idx = NR
    }
    END {
        start = (target_idx > 3) ? target_idx - 3 : 1
        end = (target_idx < NR - 3) ? target_idx + 3 : NR
        for (i = start; i <= end; i++) {
            if (func[i] == target)
                printf "  -> %s %s %s (CRASHED)\n", addr[i], type[i], func[i]
            else
                printf "     %s %s %s\n", addr[i], type[i], func[i]
        }
    }'
    
    echo "============================================="
    echo ""
}

# Function to analyze recent crashes with enhanced detection
analyze_recent_crashes() {
    echo -e "${BLUE}🔍 ANALYZING RECENT KERNEL CRASHES${NC}"
    echo "============================================="
    
    # Get recent dmesg output
    local crash_log="${CRASH_LOG_DIR}/recent_crash_$(date +%Y%m%d_%H%M%S).log"
    sudo dmesg > "$crash_log"
    
    echo -e "${GREEN}Crash log saved: $crash_log${NC}"
    echo ""
    
    # Look for fake_wifi related crashes with multiple patterns
    local found_crash=false
    
    echo -e "${CYAN}Searching for crash patterns...${NC}"
    
    # Pattern 1: ARM64 crash pattern (Raspberry Pi) - Enhanced detection
    echo -e "${CYAN}Checking for ARM64 crash patterns...${NC}"
    while IFS= read -r line; do
        # Multiple ARM64 crash patterns
        if echo "$line" | grep -qE "(pc :|PC is at).*${MODULE_NAME}.*\+0x"; then
            found_crash=true
            echo -e "${RED}🚨 ARM64 CRASH DETECTED:${NC}"
            echo "$line"
            echo ""
            
            # Extract function and offset - handle different formats
            local func=""
            local offset=""
            
            # Pattern: pc : fake_wifi_function+0x123/0x456
            if echo "$line" | grep -qE "pc :.*\+0x.*\/0x"; then
                func=$(echo "$line" | sed -n 's/.*pc : \([^+]*\)+.*/\1/p' | tr -d ' ')
                offset=$(echo "$line" | sed -n 's/.*+\(0x[0-9a-f]*\)\/.*/\1/p')
            # Pattern: PC is at fake_wifi_function+0x123
            elif echo "$line" | grep -qE "PC is at.*\+0x"; then
                func=$(echo "$line" | sed -n 's/.*PC is at \([^+]*\)+.*/\1/p' | tr -d ' ')
                offset=$(echo "$line" | sed -n 's/.*+\(0x[0-9a-f]*\).*/\1/p')
            # Pattern: pc : fake_wifi_function+0x123
            else
                func=$(echo "$line" | sed -n 's/.*pc : \([^+]*\)+.*/\1/p' | tr -d ' ')
                offset=$(echo "$line" | sed -n 's/.*+\(0x[0-9a-f]*\).*/\1/p')
            fi
            
            if [ ! -z "$func" ] && [ ! -z "$offset" ]; then
                echo -e "${YELLOW}Extracted: Function='$func', Offset='$offset'${NC}"
                echo ""
                resolve_address_to_line "$func" "$offset"
                echo ""
                echo "================================="
                echo ""
            else
                echo -e "${YELLOW}Could not extract function/offset from: $line${NC}"
            fi
        fi
    done < <(dmesg | grep -E -i "(pc :|PC is at|Call trace|${MODULE_NAME})")
    
    # Also check for BUG/Oops that might not have clear pc: lines
    echo -e "${CYAN}Checking for general kernel oops/bugs...${NC}"
    while IFS= read -r line; do
        if echo "$line" | grep -qE -i "(kernel bug|oops|unable to handle|bad page state)"; then
            found_crash=true
            echo -e "${RED}🚨 KERNEL ISSUE DETECTED:${NC}"
            echo "$line"
            
            # Get surrounding context
            echo -e "${BLUE}Context around the issue:${NC}"
            dmesg | grep -A10 -B5 "$line" | tail -15
            echo ""
        fi
    done < <(dmesg | grep -E -i "(kernel bug|oops|unable to handle|bad page state)" | grep -v "Call Trace")
    
    # Pattern 2: x86_64 crash pattern
    while IFS= read -r line; do
        if echo "$line" | grep -qE "RIP:.*${MODULE_NAME}.*\+0x"; then
            found_crash=true
            echo -e "${RED}🚨 x86_64 CRASH DETECTED:${NC}"
            echo "$line"
            echo ""
            
            # Extract function and offset
            local func=$(echo "$line" | sed -n 's/.*RIP: [^:]*:\([^+]*\)+.*/\1/p' | tr -d ' ')
            local offset=$(echo "$line" | sed -n 's/.*+\(0x[0-9a-f]*\).*/\1/p')
            
            if [ ! -z "$func" ] && [ ! -z "$offset" ]; then
                resolve_address_to_line "$func" "$offset"
                echo ""
                echo "================================="
                echo ""
            fi
        fi
    done < <(grep -E "(RIP:|Call Trace|${MODULE_NAME})" "$crash_log")
    
    # Pattern 3: General oops/bug patterns
    local oops_lines=$(grep -n -E "BUG:|Oops:|kernel BUG" "$crash_log")
    if [ ! -z "$oops_lines" ]; then
        found_crash=true
        echo -e "${RED}🚨 KERNEL BUG/OOPS DETECTED:${NC}"
        echo "$oops_lines"
        echo ""
        
        # Look for related module traces
        grep -A20 -B5 -E "BUG:|Oops:|kernel BUG" "$crash_log" | grep "$MODULE_NAME"
    fi
    
    if [ "$found_crash" = false ]; then
        echo -e "${YELLOW}⚠️ No obvious crashes found in recent dmesg${NC}"
        echo -e "${BLUE}Recent ${MODULE_NAME} related messages:${NC}"
        grep "$MODULE_NAME" "$crash_log" | tail -10 || echo "No ${MODULE_NAME} messages found"
        echo ""
        echo -e "${BLUE}Recent kernel warnings/errors:${NC}"
        grep -E -i "warning|error|fail" "$crash_log" | tail -5
    fi
    
    echo "============================================="
}

# Function for manual address resolution
manual_resolve() {
    local function_name="$1"
    local offset="$2"
    
    if [ -z "$function_name" ] || [ -z "$offset" ]; then
        echo -e "${RED}Usage: $0 resolve <function_name> <offset>${NC}"
        echo ""
        echo "Examples:"
        echo "  $0 resolve fake_wifi_init_hw 0x1a8"
        echo "  $0 resolve fake_wifi_init_hw 424"
        echo "  $0 resolve fake_wifi_setup_bands 0x50"
        echo ""
        show_functions
        return 1
    fi
    
    resolve_address_to_line "$function_name" "$offset"
}

# Function to show available functions with enhanced info
show_functions() {
    echo -e "${BLUE}📋 Available functions in ${MODULE_NAME}.ko:${NC}"
    echo "=================================================="
    
    if [ -f "${MODULE_NAME}.ko" ]; then
        echo -e "${CYAN}Text (code) functions:${NC}"
        nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [Tt] " | grep fake_wifi | \
        while read addr type func; do
            printf "  %-30s at 0x%s (%s)\n" "$func" "$addr" "$type"
        done
        
        echo ""
        echo -e "${CYAN}Data symbols:${NC}"
        nm "${MODULE_NAME}.ko" 2>/dev/null | grep -E " [DdBbRr] " | grep fake_wifi | head -5 | \
        while read addr type symbol; do
            printf "  %-30s at 0x%s (%s)\n" "$symbol" "$addr" "$type"
        done
        
        echo ""
        echo -e "${CYAN}Total symbols: $(nm "${MODULE_NAME}.ko" 2>/dev/null | wc -l)${NC}"
    else
        echo -e "${RED}❌ ${MODULE_NAME}.ko not found${NC}"
        echo "Please build the module first with: make"
    fi
    echo "=================================================="
}

# Function to get comprehensive system info
show_system_info() {
    echo -e "${BLUE}💻 SYSTEM INFORMATION${NC}"
    echo "=================================================="
    echo "Hostname: $(hostname)"
    echo "Architecture: $(uname -m)"
    echo "Kernel: $(uname -r)"
    echo "Distribution: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo 'Unknown')"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo ""
    
    echo -e "${BLUE}🔧 Debug Tools Status:${NC}"
    command -v addr2line >/dev/null 2>&1 && echo "✅ addr2line available" || echo "❌ addr2line missing"
    command -v objdump >/dev/null 2>&1 && echo "✅ objdump available" || echo "❌ objdump missing"
    command -v nm >/dev/null 2>&1 && echo "✅ nm available" || echo "❌ nm missing"
    command -v gdb >/dev/null 2>&1 && echo "✅ gdb available" || echo "❌ gdb missing"
    echo ""
    
    echo -e "${BLUE}📦 Module Status:${NC}"
    if lsmod | grep -q "$MODULE_NAME"; then
        echo -e "${GREEN}✅ $MODULE_NAME is loaded${NC}"
        lsmod | grep "$MODULE_NAME"
        echo ""
        echo "Module parameters:"
        ls /sys/module/$MODULE_NAME/parameters/ 2>/dev/null | head -5 || echo "No parameters found"
    else
        echo -e "${YELLOW}⚠️ $MODULE_NAME is not loaded${NC}"
    fi
    echo ""
    
    echo -e "${BLUE}📁 Working Directory:${NC}"
    echo "Current: $(pwd)"
    echo "Contents:"
    ls -la *.ko *.c *.h Makefile 2>/dev/null || echo "No relevant files found"
    echo "=================================================="
    echo ""
}

# Function to show help with examples
show_help() {
    echo -e "${BLUE}Enhanced Pi Local Crash Analyzer - Help${NC}"
    echo "=================================================="
    echo ""
    echo -e "${YELLOW}Usage: $0 [command] [options]${NC}"
    echo ""
    echo -e "${CYAN}Commands:${NC}"
    echo "  analyze              - Analyze recent crashes (default)"
    echo "  test                 - Safely test module loading with crash monitoring"
    echo "  resolve <func> <offset> - Manually resolve function+offset"
    echo "  functions            - Show available functions in module"
    echo "  cleanup              - Remove module and clean up"
    echo "  info                 - Show comprehensive system info"
    echo "  install-tools        - Install required debugging tools"
    echo "  help                 - Show this help"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0                                          # Analyze recent crashes"
    echo "  $0 test                                     # Safely load module with monitoring"
    echo "  $0 resolve fake_wifi_init_hw 0x1a8         # Resolve specific address"
    echo "  $0 resolve fake_wifi_init 0xff8            # Resolve inlined function"
    echo "  $0 functions                                # List all functions"
    echo "  $0 cleanup                                  # Remove module and clean logs"
    echo ""
    echo -e "${CYAN}Typical Workflow:${NC}"
    echo "  1. Build module: make clean && make debug"
    echo "  2. Test safely: $0 test"
    echo "  3. If crash occurs: $0 analyze (after reboot if needed)"
    echo "  4. Clean up: $0 cleanup"
    echo ""
    echo -e "${CYAN}Tips:${NC}"
    echo "  • The 'test' command is the safest way to load the module"
    echo "  • It provides countdown and crash monitoring"
    echo "  • Logs are saved in $CRASH_LOG_DIR for later analysis"
    echo "  • Use 'analyze' after any system crashes or reboots"
    echo "  • Debug symbols are required for line-by-line analysis"
    echo "=================================================="
}

# Function to safely test module loading with crash monitoring
safe_module_test() {
    echo -e "${YELLOW}=== SAFE MODULE TESTING ===${NC}"
    echo -e "${YELLOW}This will attempt to load the module and monitor for crashes${NC}"
    echo ""
    
    # Check if module is already loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        echo -e "${YELLOW}⚠️ Module $MODULE_NAME is already loaded${NC}"
        echo "Current status:"
        lsmod | grep "$MODULE_NAME"
        echo ""
        read -p "Remove existing module first? (y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Removing existing module...${NC}"
            sudo rmmod "$MODULE_NAME" 2>/dev/null || echo "Failed to remove module"
            sleep 2
        else
            echo -e "${YELLOW}Keeping existing module loaded${NC}"
            return 0
        fi
    fi
    
    # Capture pre-crash state
    echo -e "${BLUE}� Capturing pre-test system state...${NC}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local pre_state_file="$CRASH_LOG_DIR/pre_test_state_$timestamp.log"
    
    {
        echo "=== Pre-test System State - $(date) ==="
        echo "Architecture: $(uname -m)"
        echo "Kernel: $(uname -r)"
        echo ""
        echo "=== Memory Info ==="
        free -h
        echo ""
        echo "=== Loaded Modules (wireless related) ==="
        lsmod | grep -E "(cfg80211|mac80211|wifi)" || echo "No wireless modules found"
        echo ""
        echo "=== Recent dmesg (last 20 lines) ==="
        dmesg | tail -20
    } > "$pre_state_file"
    
    echo -e "${GREEN}Pre-test state saved: $pre_state_file${NC}"
    
    # Clear dmesg buffer for clean crash analysis
    echo -e "${BLUE}🧹 Clearing kernel message buffer...${NC}"
    sudo dmesg -C
    
    # Load required dependencies first
    echo -e "${BLUE}📦 Loading dependencies...${NC}"
    
    # Check and load cfg80211
    if ! lsmod | grep -q cfg80211; then
        echo "Loading cfg80211..."
        sudo modprobe cfg80211
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Failed to load cfg80211${NC}"
            return 1
        fi
    else
        echo "✅ cfg80211 already loaded"
    fi
    
    # Check and load mac80211
    if ! lsmod | grep -q mac80211; then
        echo "Loading mac80211..."
        sudo modprobe mac80211
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Failed to load mac80211${NC}"
            return 1
        fi
    else
        echo "✅ mac80211 already loaded"
    fi
    
    echo -e "${GREEN}✅ Dependencies loaded successfully${NC}"
    
    # Verify module file exists
    if [ ! -f "${MODULE_NAME}.ko" ]; then
        echo -e "${RED}❌ Module file ${MODULE_NAME}.ko not found${NC}"
        echo "Please build the module first with: make clean && make debug"
        return 1
    fi
    
    # Show current kernel messages
    echo -e "${BLUE}� Current kernel messages:${NC}"
    dmesg | tail -5 || echo "No recent messages"
    
    echo ""
    echo -e "${YELLOW}⚠️  ABOUT TO LOAD MODULE ⚠️${NC}"
    echo -e "${YELLOW}Module: ${MODULE_NAME}.ko${NC}"
    echo -e "${YELLOW}Press Ctrl+C within 10 seconds to abort${NC}"
    echo ""
    
    # Give user chance to abort with countdown
    for i in {10..1}; do
        echo -ne "\rLoading in $i seconds... "
        sleep 1
    done
    echo ""
    
    # Record the exact time of loading
    local load_time=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}🚀 Loading module at: $load_time${NC}"
    
    # Attempt to load the module
    echo -e "${CYAN}Executing: sudo insmod ${MODULE_NAME}.ko${NC}"
    sudo insmod "${MODULE_NAME}.ko"
    
    local load_result=$?
    
    # Give system a moment to process
    sleep 3
    
    # Check results
    if [ $load_result -eq 0 ]; then
        echo -e "${GREEN}✅ Module insertion command completed successfully${NC}"
        
        # Check if it's actually loaded
        if lsmod | grep -q "$MODULE_NAME"; then
            echo -e "${GREEN}✅ Module is loaded and running in kernel${NC}"
            echo "Module details:"
            lsmod | grep "$MODULE_NAME"
            
            # Check for any immediate error messages
            sleep 2
            local recent_errors=$(dmesg | tail -10 | grep -E -i "(error|fail|bug|oops)")
            if [ ! -z "$recent_errors" ]; then
                echo -e "${YELLOW}⚠️ Recent error messages detected:${NC}"
                echo "$recent_errors"
            else
                echo -e "${GREEN}✅ No immediate error messages${NC}"
            fi
            
        else
            echo -e "${YELLOW}⚠️ Module insertion returned success but module not in lsmod${NC}"
            echo "This could indicate the module loaded and then immediately unloaded due to an error"
        fi
    else
        echo -e "${RED}❌ Module insertion failed with exit code: $load_result${NC}"
    fi
    
    # Show recent kernel messages after loading attempt
    echo ""
    echo -e "${BLUE}📋 Kernel messages after module load attempt:${NC}"
    dmesg | tail -20
    
    # Capture post-load state and analyze any crashes
    capture_post_test_state "$load_time" "$load_result"
    
    return $load_result
}

# Function to capture post-test state and analyze crashes
capture_post_test_state() {
    local load_time="$1"
    local load_result="$2"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local post_test_file="$CRASH_LOG_DIR/post_test_analysis_$timestamp.log"
    
    echo ""
    echo -e "${BLUE}📊 Capturing post-test state and analyzing results...${NC}"
    
    {
        echo "=== Post-test Analysis - $(date) ==="
        echo "Load attempted at: $load_time"
        echo "Load result code: $load_result"
        echo ""
        
        echo "=== Module Status ==="
        lsmod | grep "$MODULE_NAME" || echo "$MODULE_NAME not found in lsmod"
        echo ""
        
        echo "=== Complete dmesg output after load attempt ==="
        dmesg
        echo ""
        
        echo "=== Searching for crash/error indicators ==="
        dmesg | grep -E -i "(bug|oops|panic|call trace|segfault|$MODULE_NAME|error|fail)" | tail -50
        
    } > "$post_test_file"
    
    echo -e "${GREEN}✅ Post-test analysis saved: $post_test_file${NC}"
    
    # Check for crashes and analyze them automatically
    local crash_indicators=$(dmesg | grep -E -i "(bug|oops|panic|call trace|kernel bug)")
    if [ ! -z "$crash_indicators" ]; then
        echo -e "${RED}🚨 CRASH/ERROR DETECTED! Analyzing...${NC}"
        echo "$crash_indicators"
        echo ""
        
        # Run automatic crash analysis
        analyze_recent_crashes
    else
        echo -e "${GREEN}✅ No obvious crashes or kernel bugs detected${NC}"
        
        # Still check for module-specific issues
        local module_issues=$(dmesg | grep -E -i "$MODULE_NAME.*(error|fail|warn)")
        if [ ! -z "$module_issues" ]; then
            echo -e "${YELLOW}⚠️ Module-specific warnings/errors found:${NC}"
            echo "$module_issues"
        fi
    fi
    
    echo ""
    echo -e "${BLUE}💡 Next steps:${NC}"
    if lsmod | grep -q "$MODULE_NAME"; then
        echo "✅ Module is loaded successfully"
        echo "  - Monitor with: dmesg -w"
        echo "  - Unload with: sudo rmmod $MODULE_NAME"
    else
        echo "❌ Module failed to load or crashed"
        echo "  - Analyze crashes: ./pi_local_crash_analyzer.sh analyze"
        echo "  - Check logs in: $CRASH_LOG_DIR"
    fi
}

# Function to clean up and remove module
cleanup_module() {
    echo -e "${BLUE}🧹 Cleaning up module...${NC}"
    
    # Try to remove the module
    if lsmod | grep -q "$MODULE_NAME"; then
        echo "Removing $MODULE_NAME module..."
        sudo rmmod "$MODULE_NAME"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Module removed successfully${NC}"
        else
            echo -e "${RED}❌ Failed to remove module - system may need reboot${NC}"
            echo "You can try: sudo rmmod -f $MODULE_NAME"
        fi
    else
        echo -e "${YELLOW}ℹ️  Module not currently loaded${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}🗂️  Crash analysis logs location: $CRASH_LOG_DIR${NC}"
    if [ -d "$CRASH_LOG_DIR" ]; then
        echo "Available analysis files:"
        ls -la "$CRASH_LOG_DIR"/*.log 2>/dev/null | tail -5
    fi
}

# Function to parse crash from file
parse_crash_file() {
    local crash_file="$1"
    
    if [ ! -f "$crash_file" ]; then
        echo -e "${RED}❌ Crash file not found: $crash_file${NC}"
        return 1
    fi
    
    echo -e "${BLUE}🔍 Parsing crash file: $crash_file${NC}"
    echo ""
    
    local found_crash=false
    
    # Look for crash patterns in the file
    while IFS= read -r line; do
        if echo "$line" | grep -qE "(pc :|RIP:).*${MODULE_NAME}.*\+0x"; then
            found_crash=true
            echo -e "${RED}🚨 CRASH FOUND IN FILE:${NC}"
            echo "$line"
            echo ""
            
            # Extract and resolve
            if echo "$line" | grep -qE "pc :"; then
                # ARM64 format
                local func=$(echo "$line" | sed -n "s/.*pc : \([^+]*\)+.*/\1/p" | tr -d ' ')
                local offset=$(echo "$line" | sed -n 's/.*+\(0x[0-9a-f]*\).*/\1/p')
            else
                # x86_64 format
                local func=$(echo "$line" | sed -n 's/.*RIP: [^:]*:\([^+]*\)+.*/\1/p' | tr -d ' ')
                local offset=$(echo "$line" | sed -n 's/.*+\(0x[0-9a-f]*\).*/\1/p')
            fi
            
            if [ ! -z "$func" ] && [ ! -z "$offset" ]; then
                resolve_address_to_line "$func" "$offset"
            fi
        fi
    done < "$crash_file"
    
    if [ "$found_crash" = false ]; then
        echo -e "${YELLOW}No crash patterns found in file${NC}"
    fi
}

# Main logic with enhanced command handling
case "$1" in
    "test")
        safe_module_test
        ;;
    "resolve")
        manual_resolve "$2" "$3"
        ;;
    "functions")
        show_functions
        ;;
    "cleanup")
        cleanup_module
        ;;
    "info")
        show_system_info
        ;;
    "install-tools")
        install_debug_tools
        ;;
    "parse")
        parse_crash_file "$2"
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    "analyze"|"")
        show_system_info
        analyze_recent_crashes
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac

echo -e "${GREEN}🔚 Analysis complete!${NC}"