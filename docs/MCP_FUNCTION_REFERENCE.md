# GhidraMCP Function Reference Guide

## Overview

This reference guide provides comprehensive documentation for all MCP functions available in the GhidraMCP server, organized by category and use case. Each function includes keywords, aliases, workflow integration details, and specific examples for QEMU + Ghidra reverse engineering workflows.

## Function Categories

### 🔧 Core Analysis Functions
Functions for understanding code structure and behavior
- [`decompile_function_by_address`](#decompile_function_by_address)
- [`get_main_function`](#get_main_function)
- [`list_interrupts`](#list_interrupts)
- [`list_comments`](#list_comments)

### 📊 Memory & Structure Analysis
Functions for understanding program layout and organization
- [`list_segments`](#list_segments)
- [`list_strings`](#list_strings)
- [`list_methods`](#list_methods)
- [`list_classes`](#list_classes)

### 🔍 Cross-Reference Analysis
Functions for understanding code relationships and data flow
- [`get_function_xrefs`](#get_function_xrefs)
- [`xrefs_to`](#xrefs_to)
- [`xrefs_from`](#xrefs_from)

---

## Core Analysis Functions

### `decompile_function_by_address`

**Purpose**: Analyze code at specific address for detailed understanding

**Keywords**: `decompile`, `disassemble`, `function analysis`, `code analysis`, `address analysis`

**Aliases**: `analyze function`, `decompile address`, `function code`, `show code at address`

#### QEMU Integration Scenarios

**🔧 QEMU PC Analysis**:
- **QEMU stops at address**: Use this to understand what code is executing
- **Exception occurs**: Decompile handler function to understand expected behavior  
- **Code is stuck**: Analyze function logic to determine why execution stopped

**Critical Debugging Examples**:
```python
# QEMU PC = 0x00001234, what is this code doing?
decompile_function_by_address("0x00001234")

# Exception at handler address - understand handler expectations
decompile_function_by_address("0x0000196C")  # From interrupt handler_address

# Code stuck in polling loop - analyze loop conditions
decompile_function_by_address(qemu_pc)
```

#### Parameters
- **address**: Memory address of function to decompile (e.g., "0x00001234")
  - **Format**: Hex address with or without 0x prefix
  - **Sources**: QEMU PC, `handler_address` from `list_interrupts()`, `instruction_address` from `list_comments()`

#### Returns
Decompiled C-like code showing:
- Function structure and logic flow
- Variable assignments and operations
- Conditional branches and loops  
- Function calls and memory access
- Register and peripheral interactions

#### Related Functions
- `get_function_xrefs(name="function_name")` → See what references this function
- `xrefs_to(address="0x1234")` → Find all references to specific addresses
- `list_comments(filter="0x40001000")` → Understand memory-mapped register access

---

### `get_main_function`

**Purpose**: Find firmware's main entry point from reset vector analysis

**Keywords**: `main`, `entry point`, `reset vector`, `startup`, `firmware entry`, `program start`

**Aliases**: `find main`, `entry point`, `reset handler`, `startup function`, `program entry`

#### QEMU Integration Scenarios

**🔧 QEMU Startup Analysis**:
- **QEMU execution begins**: Use this to find where main program logic starts
- **Analyzing firmware flow**: Identify the primary entry point after reset
- **Debugging initialization**: Find the start of application code

**Debugging Examples**:
```python
# Where does the program start?
main_info = get_main_function()
if main_info["found"]:
    main_address = main_info["instruction_address"]
    
# QEMU reset, where should execution begin?
# Use instruction_address to set QEMU PC

# Need to set QEMU PC for main analysis
qemu.set_pc(main_info["instruction_address"])
```

#### Parameters
None

#### Returns
```json
{
  "found": true,
  "instruction_address": "0x00000F04",     // Set QEMU PC here for main analysis
  "comment": "SVD: Main entry point - Application start..."
}
```

#### Related Functions
- `decompile_function_by_address(address=instruction_address)` → Analyze main function code
- `get_function_xrefs(name="main")` → See what calls or references main
- `list_interrupts()` → Understand interrupt setup in main initialization

---

### `list_interrupts`

**Purpose**: Analyze and list active interrupts in ARM Cortex-M firmware

**Keywords**: `interrupts`, `IRQ`, `vector`, `handler`, `exception`, `peripheral interrupts`, `NVIC`

**Aliases**: `show interrupts`, `get IRQs`, `interrupt handlers`, `vector table`, `exceptions`

#### QEMU Integration Scenarios

**🔧 QEMU Exception Analysis**:
- **QEMU hits exception**: Use this to find expected interrupt handlers
- **Code is stuck waiting**: Check what interrupts should trigger
- **Polling detected**: Identify which IRQ might advance execution

**Debugging Examples**:
```python
# Code stuck, what interrupt is it waiting for?
interrupts = list_interrupts()
enabled_irqs = [irq for irq in interrupts["results"] if irq["enabled"]]

# Exception at handler, which IRQ triggered?
for irq in interrupts["results"]:
    if irq["handler_address"] == qemu_pc:
        print(f"IRQ {irq['irq_number']}: {irq['name']}")

# Need to advance execution
high_confidence_irqs = [irq for irq in interrupts["results"] 
                       if irq["confidence"] == "high"]
# Trigger specific IRQ in QEMU
```

#### Parameters
- **offset**: Pagination offset for large interrupt lists (default: 0)
- **limit**: Maximum interrupts to return (default: 100)

#### Returns
```json
{
  "results": [
    {
      "irq_number": 27,              // Use to trigger in QEMU: "IRQ_27"
      "name": "EIC_INTREQ_15",       // Specific peripheral interrupt name
      "vector": 27,                  // Vector table position
      "handler_address": "0x196C",   // Match against QEMU PC for analysis
      "handler_function": "eic_handler", // Function name for cross-reference
      "peripheral": "EIC",           // Peripheral that generates this IRQ
      "confidence": "high",          // Reliability of detection
      "enabled": true                // Whether interrupt is enabled
    }
  ]
}
```

#### QEMU Integration
- Match QEMU PC against `handler_address` to identify triggered interrupt
- Use `irq_number` to send interrupt trigger commands to QEMU
- Cross-reference `peripheral` name with register access for root cause analysis

#### Related Functions
- `list_segments()` → Find peripheral memory regions for interrupt sources
- `list_comments(peripheral="EIC")` → Understand interrupt configuration details
- `get_function_xrefs(name="eic_handler")` → Analyze interrupt handler code
- `decompile_function(address="0x196C")` → Understand handler implementation

---

### `list_comments`

**Purpose**: Analyze SVD comments showing detailed peripheral register access patterns

**Keywords**: `comments`, `SVD`, `registers`, `peripheral config`, `register access`, `memory mapped`

**Aliases**: `show registers`, `peripheral analysis`, `register operations`, `memory access`

#### QEMU Integration Scenarios

**🔧 QEMU Memory Access Analysis**:
- **Invalid memory access**: Check if address maps to peripheral register
- **Code polls memory location**: Understand what register/peripheral it's waiting on
- **Interrupt fails to trigger**: Analyze peripheral configuration for proper setup

**Debugging Examples**:
```python
# Code stuck polling 0x40001000
comments = list_comments(filter="0x40001000")
if comments["results"]:
    reg_info = comments["results"][0]
    print(f"Polling {reg_info['peripheral']}.{reg_info['register']}")

# UART not working
uart_config = list_comments(peripheral="UART")
for comment in uart_config["results"]:
    if comment["operation"].startswith("WRITE:"):
        # Apply configuration to QEMU

# Interrupt not triggering  
intenset_regs = list_comments(filter="INTENSET")

# What's configured for EIC?
eic_config = list_comments(peripheral="EIC")
```

#### Parameters
- **offset**: Pagination offset for large comment sets (default: 0)
- **limit**: Maximum comments to return (default: 1000)
- **filter**: Text search within comment content
  - Examples: `"0x40001000"`, `"INTENSET"`, `"WRITE:0x8000"`
- **peripheral**: Filter by peripheral name (get names from `list_segments()`)
  - Examples: `"EIC"`, `"RTC"`, `"DMAC"`, `"UART"`, `"SPI"`

#### Returns
```json
{
  "results": [
    {
      "instruction_address": "0x00001234",  // Code location for this register access
      "peripheral": "EIC",                  // Peripheral name (matches list_segments)
      "register": "INTENSET",               // Specific register name
      "operation": "WRITE:0x8000",          // Read/Write with value
      "fields": [                           // Bit field breakdown
        {
          "name": "EXTINT",
          "offset": "15", 
          "width": "1",
          "value": "0x1",
          "description": "External Interrupt 15 Enable"
        }
      ],
      "interrupts": [                       // Related interrupt information
        {
          "action": "ENABLE",
          "name": "EIC_INTREQ_15", 
          "vector": "27"
        }
      ]
    }
  ]
}
```

#### QEMU Integration
- Match `instruction_address` against QEMU PC to understand current operation
- Use `peripheral`/`register` info to set proper QEMU peripheral state
- Apply `field` configurations to simulate realistic peripheral behavior
- Use `interrupt` info to determine when to trigger interrupts in QEMU

#### Workflow Integration
1. Use `list_segments()` to identify peripheral memory regions
2. Use `list_comments(peripheral="NAME")` for detailed register analysis
3. Use `list_interrupts()` to correlate with interrupt configuration  
4. Apply findings to configure QEMU peripheral state

#### Related Functions
- `list_segments()` → Get peripheral names and memory regions
- `list_interrupts()` → See interrupts related to peripheral configuration
- `xrefs_to(address="0x40001000")` → Find all code that accesses specific registers
- `decompile_function()` → Understand register access context within functions

---

## Memory & Structure Analysis Functions

### `list_segments`

**Purpose**: List memory segments and regions in the program

**Keywords**: `segments`, `memory`, `regions`, `blocks`, `peripherals`, `memory map`, `address space`

**Use Cases**:
- "Show me all memory segments"
- "List peripherals"
- "What memory regions exist?"
- "Show memory map"

**Returns**: List of memory segments with start/end addresses and names
**Format**: `"SEGMENT_NAME: 0xSTART_ADDR - 0xEND_ADDR"`

**Related Functions**:
- `list_comments(peripheral="NAME")` → Get detailed register info for a peripheral
- `list_interrupts()` → See interrupts associated with peripherals

---

### `list_strings`

**Purpose**: List all defined strings in the program with their addresses

**Keywords**: `strings`, `string data`, `text`, `string literals`

**Parameters**:
- **filter**: Optional filter to match within string content

**Use Cases**:
- Finding debug messages or error strings
- Locating configuration strings
- Understanding program functionality through string analysis

---

## Cross-Reference Analysis Functions

### `get_function_xrefs`

**Purpose**: Get all references to a specific function by name

**Keywords**: `cross references`, `function calls`, `references`, `callers`

**Parameters**:
- **name**: Function name to search for
- **offset**: Pagination offset (default: 0)  
- **limit**: Maximum references to return (default: 100)

**Use Cases**:
- Understanding which functions call a specific function
- Analyzing interrupt handler usage
- Tracing function call chains

---

### `xrefs_to`

**Purpose**: Get all references TO a specific address

**Keywords**: `references to`, `memory access`, `address usage`

**Parameters**:
- **address**: Target address to find references to
- **offset**: Pagination offset (default: 0)
- **limit**: Maximum references to return (default: 100)

**Use Cases**:
- Finding all code that accesses a specific memory location
- Analyzing peripheral register usage
- Understanding data structure access patterns

---

### `xrefs_from`

**Purpose**: Get all references FROM a specific address

**Keywords**: `references from`, `outgoing references`, `calls from`

**Parameters**:
- **address**: Source address to find references from
- **offset**: Pagination offset (default: 0)
- **limit**: Maximum references to return (default: 100)

**Use Cases**:
- Understanding what a function calls or accesses
- Analyzing code flow from specific locations
- Mapping function dependencies

---

## Quick Reference: Common Workflow Patterns

### Pattern 1: QEMU Exception Analysis
```python
# 1. Get QEMU PC address
qemu_pc = "0x00001234"

# 2. Analyze code at that address
code = decompile_function_by_address(qemu_pc)

# 3. Check if it's an interrupt handler
interrupts = list_interrupts()
handler = next((irq for irq in interrupts["results"] 
               if irq["handler_address"] == qemu_pc), None)

# 4. Analyze peripheral context if needed
if handler:
    peripheral_config = list_comments(peripheral=handler["peripheral"])
```

### Pattern 2: Memory Access Investigation  
```python
# 1. Get memory address from QEMU
memory_addr = "0x40001000"

# 2. Find what register this is
reg_info = list_comments(filter=memory_addr)

# 3. Get full peripheral configuration
if reg_info["results"]:
    peripheral = reg_info["results"][0]["peripheral"]
    full_config = list_comments(peripheral=peripheral)

# 4. Find all code that accesses this register
access_points = xrefs_to(address=memory_addr)
```

### Pattern 3: Startup Analysis
```python
# 1. Find main entry point
main_info = get_main_function()

# 2. Analyze main function
if main_info["found"]:
    main_code = decompile_function_by_address(main_info["instruction_address"])

# 3. Find initialization sequences
init_writes = list_comments(filter="WRITE")

# 4. Understand interrupt setup
interrupts = list_interrupts()
```

This reference guide provides the foundation for sophisticated automated firmware reverse engineering using the QEMU + Ghidra MCP integration.