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