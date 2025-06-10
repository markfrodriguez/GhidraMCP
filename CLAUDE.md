# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GhidraMCP is a Model Context Protocol (MCP) server that enables LLMs to autonomously reverse engineer applications through Ghidra integration. The project consists of two main components:

1. **Ghidra Plugin** (`src/main/java/com/lauriewired/GhidraMCPPlugin.java`) - An HTTP server plugin that runs inside Ghidra and exposes reverse engineering functionality via REST endpoints
2. **MCP Bridge** (`bridge_mcp_ghidra.py`) - A Python MCP server that bridges between MCP clients and the Ghidra HTTP server

## Build Commands

### Prerequisites
- Set `GHIDRA_INSTALL_DIR` environment variable pointing to your Ghidra installation directory
- Gradle automatically references Ghidra JARs from the installation directory

### Gradle Build Commands (Recommended for IntelliJ development)
```bash
# Build the plugin JAR
./gradlew build

# Build and package the complete Ghidra extension
./gradlew buildExtension

# Build and install extension to Ghidra extensions directory (recommended)
./gradlew install
# or
./gradlew installExtension

# Prepare for debugging and get debug instructions
./gradlew debugExtension
```

### Maven Build Commands (Legacy)
```bash
# For CI/CD builds when Ghidra JARs are copied to lib/ directory
mvn clean package assembly:single
```

### Testing
```bash
./gradlew test
```

### IntelliJ Development Setup
1. Open project in IntelliJ IDEA
2. Gradle will automatically configure classpath with Ghidra dependencies
3. Run `./gradlew debugExtension` to install extension and get debug setup instructions
4. Use IntelliJ's Remote JVM Debug configuration to attach to Ghidra

## Architecture

### Ghidra Plugin Architecture
- **HTTP Server**: Embedded HTTP server (default port 8080) with REST endpoints for Ghidra operations
- **Swing Thread Safety**: All Ghidra API operations must run on the Swing EDT using `SwingUtilities.invokeAndWait()`
- **Transaction Management**: All program modifications require transactions (`program.startTransaction()` / `program.endTransaction()`)
- **Decompilation**: Uses `DecompInterface` and `HighFunction` APIs for advanced analysis

### MCP Bridge Architecture  
- **FastMCP Framework**: Uses the MCP Python SDK's FastMCP for tool registration
- **HTTP Client**: Makes requests to the Ghidra HTTP server endpoints
- **Transport Modes**: Supports both stdio (for Claude Desktop) and SSE (for web clients)

### Key API Endpoints
The Ghidra plugin exposes these core endpoints:
- `/decompile` - Decompile functions by name or address
- `/methods`, `/classes`, `/imports`, `/exports` - List program components with pagination
- `/renameFunction`, `/renameData`, `/renameVariable` - Rename operations
- `/xrefs_to`, `/xrefs_from` - Cross-reference analysis
- `/strings` - List defined strings with filtering
- `/interrupts` - Comprehensive interrupt analysis for ARM Cortex-M programs

### Configuration
- Ghidra plugin port is configurable via Tool Options → "GhidraMCP HTTP Server" → "Server Port"
- MCP bridge connects to Ghidra server URL (default: http://127.0.0.1:8080/)

## Development Notes

### Java Development
- Plugin extends Ghidra's `Plugin` class with proper `@PluginInfo` annotation
- Uses Ghidra's `ProgramManager` service to access the current program
- All UI operations must be thread-safe (use Swing EDT)
- Handle address parsing with `program.getAddressFactory().getAddress()`

### Python Development  
- MCP tools are registered with `@mcp.tool()` decorator
- All HTTP requests include proper error handling and timeouts
- Support pagination parameters (offset, limit) for large result sets

## Interrupt Analysis Features

### Overview
The `/interrupts` endpoint provides comprehensive interrupt analysis specifically designed for ARM Cortex-M microcontrollers. It combines multiple analysis techniques to identify all interrupts used in embedded firmware.

### Analysis Methods
1. **Vector Table Analysis** - Parses ARM Cortex-M vector table starting at 0x00000000
   - System exceptions (Reset, NMI, HardFault, etc.)
   - External IRQs (starting at offset 0x40)
   - Handler address extraction with Thumb bit clearing

2. **NVIC Register Analysis** - Scans for NVIC control register operations
   - Interrupt Set Enable Registers (ISER0-3)
   - Interrupt Clear Enable Registers (ICER0-3)
   - Extracts immediate values from instructions
   - Identifies which specific IRQs are enabled/disabled

3. **Handler Function Identification** - Maps handler addresses to functions
   - Locates functions at vector table addresses
   - Identifies containing functions for offset handlers
   - Provides function names for better analysis

4. **GhidraSVD Comment Analysis** - Comprehensive SVD comment parsing
   - Parses structured SVD comments (format: "SVD: PERIPHERAL.REGISTER - Description")
   - Extracts register write values from "<== VALUE" patterns
   - **Generic interrupt source detection** using dual strategy:
     - **Value-based analysis**: Analyzes configured register values and enabled bit fields
     - **Pattern recognition**: Uses universal patterns (SENSE7→EXTINT7, CH3→CH3_INT, etc.)
   - Maps peripheral configurations to specific IRQ numbers
   - Analyzes bit field configurations for trigger types (rising/falling edge)
   - Works across different microcontrollers and peripherals

5. **Peripheral Register Configuration** - Analyzes peripheral memory writes
   - Scans peripheral memory regions (0x40000000+)
   - Identifies interrupt enable register writes (INTENSET, INTEN, etc.)
   - Correlates register operations with interrupt sources

6. **Smart Filtering** - Filters out dummy/unused interrupts
   - Identifies default handler addresses (most common)
   - Assigns confidence levels (HIGH/MEDIUM/LOW)
   - Provides reasoning for inclusion (unique_handler, nvic_config, etc.)

### Output Format
Each interrupt entry includes:
- IRQ number and name (e.g., "IRQ_11" or system exception names)
- Interrupt type (system_exception or external_irq)
- Confidence level and reasoning ({HIGH:unique_handler}, {MEDIUM:nvic_config}, etc.)
- Handler address and function name
- Peripheral information (name and interrupt source)
- Enable status from NVIC analysis
- Vector table offset information
- NVIC operation details (which registers were accessed)
- Configuration addresses (peripheral config, comment locations)

### Example Enhanced Output
```
IRQ 11: EIC_EXTINT7 [external_irq] {HIGH:unique_handler} -> 0x000018C0 (eic_handler) VT:0x6C EIC.CONFIG1(EXTINT7) "External Interrupt Controller" [rising_edge] Value:0x10000000 Fields:{SENSE7:RISE - Rising edge detection (0x1)} Cfg:0x00005678
```

### Generic Interrupt Source Detection
The system now uses **universal patterns** that work across different microcontrollers:

- **Field Mapping**: SENSE7 → EXTINT7, CH3 → CH3_INT, OC1 → OC1_INT
- **Value Analysis**: Identifies which bit fields have non-zero values (enabled)
- **Pattern Recognition**: Recognizes common interrupt patterns (OVF, ERROR, READY, etc.)
- **Priority Selection**: Chooses most specific source when multiple candidates exist

### Filtering Intelligence
The enhanced analysis now filters results to show only genuinely configured interrupts:
- **System exceptions** - Always included for completeness
- **Unique handlers** - Interrupts with dedicated handler functions (HIGH confidence)
- **NVIC configured** - Interrupts with explicit enable/disable operations (MEDIUM confidence)
- **Peripheral configured** - Interrupts with peripheral register setup (MEDIUM confidence)
- **Comment mentioned** - Interrupts referenced in GhidraSVD comments (LOW confidence)

### Implementation Notes
- Uses Ghidra's Memory API for direct vector table reading
- Leverages ReferenceManager for NVIC register cross-references
- Handles ARM Cortex-M specific addressing (Thumb bit clearing)
- Parses structured GhidraSVD comments with regex patterns
- Includes hardcoded SAME54 peripheral-to-IRQ mappings
- Validates code addresses to filter corrupted vector entries
- Stops vector table parsing after consecutive zeros or invalid addresses
- Extracts bit field configurations and trigger types from SVD data
- Correlates register write values with interrupt configurations
- Robust error handling for invalid memory addresses and malformed comments