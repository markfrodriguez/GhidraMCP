# QEMU + Ghidra Workflow Examples

## Overview

This document provides concrete, step-by-step examples of real-world reverse engineering scenarios using the QEMU + Ghidra MCP integration. Each example includes the problem scenario, analysis steps, and resolution actions.

---

## Example 1: Exception in Interrupt Handler

### Scenario
QEMU reports an exception during firmware execution:
```
QEMU Exception: HardFault at PC=0x0000196C, SP=0x20001F80, LR=0x00001285
```

### Analysis Workflow

#### Step 1: Understand Exception Context
```python
# Decompile code at exception address
exception_code = decompile_function_by_address("0x0000196C")
print("Code at exception:")
print(exception_code)
```

**Expected Output**:
```c
// Decompiled function at 0x0000196C
void eic_handler(void) {
    uint32_t status = *(uint32_t*)0x40001818;  // EIC.INTFLAG
    if (status & 0x8000) {
        // Handle EXTINT15
        process_external_interrupt();
        *(uint32_t*)0x40001818 = 0x8000;  // Clear flag
    }
}
```

#### Step 2: Identify Interrupt Context
```python
# Check if this is a known interrupt handler
interrupts = list_interrupts()
handler_info = None
for irq in interrupts["results"]:
    if irq["handler_address"] == "0x0000196C":
        handler_info = irq
        break

print(f"Exception in: {handler_info['name']} (IRQ {handler_info['irq_number']})")
```

**Output**: `Exception in: EIC_INTREQ_15 (IRQ 27)`

#### Step 3: Analyze Peripheral Configuration
```python
# Get EIC peripheral configuration
eic_config = list_comments(peripheral="EIC")
for comment in eic_config["results"]:
    if "INTFLAG" in comment["register"]:
        print(f"INTFLAG register: {comment}")
```

**Expected Finding**: EIC.INTFLAG register at 0x40001818 shows read-only status

#### Step 4: Root Cause Analysis
```python
# Check what code accesses the problematic register
intflag_refs = xrefs_to(address="0x40001818")
print("Code accessing EIC.INTFLAG:")
for ref in intflag_refs:
    print(f"  {ref}")
```

**Root Cause**: Handler trying to write to read-only status register

### Resolution
```python
# QEMU Action: Configure EIC peripheral to have writable INTFLAG
# or modify handler to use correct clear register
qemu_action = {
    "action": "configure_peripheral",
    "peripheral": "EIC", 
    "register": "INTFLAG",
    "mode": "writable"  # Make status register writable for simulation
}
```

---

## Example 2: Code Stuck in Polling Loop

### Scenario
QEMU execution appears stuck, not making progress:
```
QEMU Status: Stuck at PC=0x00001A2C for 1000+ cycles
Current instruction: LDR R0, [R1, #0x14]
R1 = 0x40002000 (UART base address)
```

### Analysis Workflow

#### Step 1: Analyze Stuck Code
```python
# Understand what the polling loop is doing
stuck_code = decompile_function_by_address("0x00001A2C")
print("Stuck code analysis:")
print(stuck_code)
```

**Expected Output**:
```c
// Function polling UART status
void uart_wait_ready(void) {
    while (1) {
        uint32_t status = *(uint32_t*)0x40002014;  // UART.STATUS
        if (status & 0x1) {  // TX_READY bit
            break;
        }
    }
}
```

#### Step 2: Identify Polled Register
```python
# Find what register is being polled
polled_reg = list_comments(filter="0x40002014")
if polled_reg["results"]:
    reg_info = polled_reg["results"][0]
    print(f"Polling: {reg_info['peripheral']}.{reg_info['register']}")
    print(f"Fields: {reg_info['fields']}")
```

**Output**: 
```
Polling: UART.STATUS
Fields: [{"name": "TX_READY", "offset": "0", "width": "1", "description": "Transmit Ready"}]
```

#### Step 3: Understand UART Configuration
```python
# Get full UART peripheral configuration
uart_config = list_comments(peripheral="UART")
print("UART Configuration:")
for comment in uart_config["results"]:
    if comment["operation"].startswith("WRITE:"):
        print(f"  {comment['register']}: {comment['operation']}")
```

**Expected Output**:
```
UART Configuration:
  CTRLA: WRITE:0x01     # UART enabled
  BAUD: WRITE:0x1A0B    # Baud rate configured  
  CTRLB: WRITE:0x03     # TX/RX enabled
```

#### Step 4: Check Expected Interrupts
```python
# See if UART should generate interrupts instead of polling
uart_interrupts = list_interrupts()
uart_irqs = [irq for irq in uart_interrupts["results"] 
            if irq["peripheral"] == "UART"]
print("UART Interrupts:", uart_irqs)
```

### Resolution
```python
# QEMU Action: Set UART status register to indicate ready state
qemu_action = {
    "action": "set_register",
    "address": "0x40002014",
    "value": "0x00000001",  # Set TX_READY bit
    "description": "Set UART TX_READY to advance execution"
}
```

---

## Example 3: Missing Interrupt Trigger

### Scenario
Code appears to be waiting for an interrupt that never arrives:
```
QEMU Status: Execution idle at PC=0x00001500
Last instruction: WFI (Wait For Interrupt)
NVIC shows no pending interrupts
```

### Analysis Workflow

#### Step 1: Identify Expected Interrupts
```python
# Find what interrupts are configured
interrupts = list_interrupts()
enabled_irqs = [irq for irq in interrupts["results"] if irq["enabled"]]
print("Enabled Interrupts:")
for irq in enabled_irqs:
    print(f"  IRQ {irq['irq_number']}: {irq['name']} ({irq['peripheral']})")
```

**Expected Output**:
```
Enabled Interrupts:
  IRQ 27: EIC_INTREQ_15 (EIC)
  IRQ 31: DMAC_INTREQ_0 (DMAC)
  IRQ 45: RTC_INTREQ_0 (RTC)
```

#### Step 2: Analyze Recent Code Execution
```python
# Look at code before WFI to understand what was being set up
main_function = get_main_function()
if main_function["found"]:
    main_code = decompile_function_by_address(main_function["instruction_address"])
    print("Main function setup:")
    print(main_code)
```

#### Step 3: Check Peripheral Trigger Conditions
```python
# Analyze RTC configuration (common source of periodic interrupts)
rtc_config = list_comments(peripheral="RTC")
for comment in rtc_config["results"]:
    if "INTENSET" in comment["register"]:
        print(f"RTC Interrupt Enable: {comment}")
        print(f"Fields: {comment['fields']}")
```

**Expected Finding**:
```
RTC Interrupt Enable: RTC.INTENSET
Fields: [{"name": "CMP0", "offset": "0", "width": "1", "value": "0x1", 
         "description": "Compare 0 Interrupt Enable"}]
```

#### Step 4: Check Timer/Counter Setup
```python
# Find RTC timer configuration
rtc_setup = list_comments(peripheral="RTC", filter="WRITE")
for comment in rtc_setup["results"]:
    if "COMP" in comment["register"] or "COUNT" in comment["register"]:
        print(f"Timer setup: {comment['register']} = {comment['operation']}")
```

### Resolution
```python
# QEMU Action: Trigger the expected RTC interrupt
qemu_action = {
    "action": "trigger_interrupt", 
    "irq_number": 45,
    "description": "Trigger RTC_INTREQ_0 to advance execution"
}

# Alternative: Set RTC counter to reach compare value
alternative_action = {
    "action": "set_register",
    "address": "0x40002400",  # RTC.COUNT register
    "value": "0x00001000",    # Value that matches COMP0 setting
    "description": "Set RTC counter to trigger compare interrupt"
}
```

---

## Example 4: Memory Initialization Issue

### Scenario
QEMU reports invalid memory access during startup:
```
QEMU Error: Invalid memory access at 0x20005000 (write)
PC=0x00000F10, attempting to write 0x12345678
```

### Analysis Workflow

#### Step 1: Check Memory Layout
```python
# Verify if this is a valid memory region
segments = list_segments()
print("Memory segments:")
for segment in segments:
    print(f"  {segment}")
    
# Look for segment containing 0x20005000
target_found = any("0x20005000" in seg for seg in segments)
print(f"Address 0x20005000 in valid memory: {target_found}")
```

#### Step 2: Analyze Code Making Access
```python
# Understand what code is trying to access this memory
access_code = decompile_function_by_address("0x00000F10")
print("Code making memory access:")
print(access_code)
```

**Expected Output**:
```c
// Memory initialization routine
void init_data_structures(void) {
    struct_ptr = (struct my_data*)0x20005000;
    struct_ptr->magic = 0x12345678;
    struct_ptr->version = 1;
    // ... more initialization
}
```

#### Step 3: Find References to This Memory
```python
# See what other code uses this memory region
memory_refs = xrefs_to(address="0x20005000")
print("Other references to 0x20005000:")
for ref in memory_refs:
    print(f"  {ref}")
```

#### Step 4: Check for Memory Setup Code
```python
# Look for any memory controller or region setup
memory_setup = list_comments(filter="0x20005000")
if not memory_setup["results"]:
    # Check for general memory setup
    memory_setup = list_comments(filter="MEMORY")
    
print("Memory setup configuration:")
for comment in memory_setup["results"]:
    print(f"  {comment}")
```

### Resolution
```python
# QEMU Action: Map the missing memory region
qemu_action = {
    "action": "map_memory",
    "start_address": "0x20005000", 
    "size": "0x1000",  # 4KB region
    "type": "RAM",
    "description": "Map data structure memory region"
}

# Alternative: Initialize memory controller if needed
controller_action = {
    "action": "configure_memory_controller",
    "enable_region": "SRAM_BANK2",
    "description": "Enable additional SRAM bank for data structures"
}
```

---

## Example 5: Peripheral Not Responding

### Scenario
Code configures a peripheral but it doesn't respond as expected:
```
QEMU Status: SPI transfer appears to hang
Code wrote to SPI registers but no response
PC=0x00001B00, waiting for SPI.STATUS.READY
```

### Analysis Workflow

#### Step 1: Analyze SPI Configuration Sequence
```python
# Get all SPI register writes to understand configuration
spi_config = list_comments(peripheral="SPI")
write_operations = [c for c in spi_config["results"] 
                   if c["operation"].startswith("WRITE:")]

print("SPI Configuration Sequence:")
for op in write_operations:
    print(f"  {op['register']}: {op['operation']}")
    print(f"    Fields: {op['fields']}")
```

**Expected Output**:
```
SPI Configuration Sequence:
  CTRLA: WRITE:0x01
    Fields: [{"name": "ENABLE", "value": "0x1"}]
  CTRLB: WRITE:0x04  
    Fields: [{"name": "MODE", "value": "0x1", "description": "Master Mode"}]
  BAUD: WRITE:0x07
    Fields: [{"name": "BAUD", "value": "0x7", "description": "Baud Rate"}]
```

#### Step 2: Check Required Dependencies
```python
# Look for clock or other peripheral dependencies
clock_setup = list_comments(filter="CLOCK")
spi_clocks = [c for c in clock_setup["results"] if "SPI" in c["comment"]]

print("SPI Clock Configuration:")
for clock in spi_clocks:
    print(f"  {clock}")
```

#### Step 3: Verify Pin Configuration
```python
# Check for PORT/GPIO configuration for SPI pins
port_config = list_comments(peripheral="PORT")
spi_pins = [c for c in port_config["results"] if "SPI" in c["comment"]]

print("SPI Pin Configuration:")
for pin in spi_pins:
    print(f"  {pin}")
```

#### Step 4: Check for Interrupt Configuration
```python
# See if SPI should use interrupts vs polling
spi_interrupts = list_interrupts()
spi_irqs = [irq for irq in spi_interrupts["results"] 
           if irq["peripheral"] == "SPI"]

print("SPI Interrupts:")
for irq in spi_irqs:
    print(f"  {irq}")
```

### Resolution
```python
# QEMU Action: Complete SPI peripheral configuration
qemu_actions = [
    {
        "action": "configure_peripheral",
        "peripheral": "SPI",
        "register": "STATUS", 
        "set_bits": "READY",
        "description": "Set SPI ready status"
    },
    {
        "action": "enable_clock",
        "peripheral": "SPI",
        "description": "Ensure SPI clock is enabled"
    },
    {
        "action": "configure_pins",
        "peripheral": "SPI",
        "pins": ["MISO", "MOSI", "SCK"],
        "description": "Configure SPI pin functions"
    }
]
```

---

## Pattern Recognition Guide

### Common Patterns and Solutions

#### Pattern 1: Polling vs Interrupt Confusion
**Signs**: Code stuck in polling loop, interrupt configured but not triggering
**Analysis**: Check if interrupt enable matches polling register
**Solution**: Either trigger interrupt or set polled register value

#### Pattern 2: Missing Peripheral Dependencies  
**Signs**: Peripheral configuration looks correct but doesn't work
**Analysis**: Check clocks, pin configuration, power management
**Solution**: Configure all peripheral dependencies in QEMU

#### Pattern 3: Memory Layout Mismatch
**Signs**: Invalid memory access, unexpected data values
**Analysis**: Compare memory segments with code expectations
**Solution**: Map missing memory regions or adjust memory controller

#### Pattern 4: Initialization Order Issues
**Signs**: Early access to unconfigured peripherals
**Analysis**: Trace initialization sequence in main function
**Solution**: Complete prerequisite initialization in QEMU

#### Pattern 5: Exception in Handler
**Signs**: Exception within interrupt handler
**Analysis**: Check handler logic and peripheral register access
**Solution**: Fix peripheral register configuration or handler logic

### Debugging Checklist

For any QEMU execution issue:

1. **✓ Identify current PC and instruction**
2. **✓ Decompile function at PC for context**  
3. **✓ Check if PC matches any interrupt handlers**
4. **✓ Analyze any memory/peripheral access in code**
5. **✓ Verify memory regions and peripheral configuration**
6. **✓ Check for missing clocks, pins, or dependencies**
7. **✓ Consider interrupt vs polling alternatives**
8. **✓ Apply targeted QEMU configuration changes**

This systematic approach ensures comprehensive analysis and effective resolution of firmware execution issues.