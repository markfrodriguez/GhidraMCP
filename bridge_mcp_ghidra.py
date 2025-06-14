# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile function code at specific address for detailed analysis.
    
    KEYWORDS: decompile, disassemble, function analysis, code analysis, address analysis
    ALIASES: analyze function, decompile address, function code, show code at address
    
    REVERSE ENGINEERING WORKFLOWS:
    
    🔧 QEMU PC Analysis:
    - When QEMU stops at address: Use this to understand what code is executing
    - When exception occurs: Decompile handler function to understand expected behavior
    - When code is stuck: Analyze function logic to determine why execution stopped
    
    🔍 Critical Debugging Scenarios:
    - "QEMU PC = 0x00001234, what is this code doing?" → decompile_function_by_address("0x00001234")
    - "Exception at handler address" → Decompile to understand handler expectations
    - "Code stuck in polling loop" → Analyze loop conditions and exit criteria
    - "Interrupt handler analysis" → Understand what interrupt handler should do
    
    📊 Analysis Output:
    - High-level C-like pseudocode for easier understanding
    - Variable and parameter identification
    - Control flow analysis (loops, conditionals, function calls)
    - Memory access patterns and register operations
    
    Args:
        address: Memory address of function to decompile (e.g., "0x00001234")
                Format: Hex address with or without 0x prefix
                Sources: QEMU PC, handler_address from list_interrupts(), instruction_address from list_comments()
    
    Returns:
        Decompiled C-like code showing:
        - Function structure and logic flow
        - Variable assignments and operations  
        - Conditional branches and loops
        - Function calls and memory access
        - Register and peripheral interactions
    
    INTEGRATION WITH QEMU ANALYSIS:
    - Use QEMU PC value directly as address parameter
    - Understand why QEMU execution stopped or failed
    - Identify what conditions code is waiting for
    - Determine what memory/peripheral access should succeed
    
    WORKFLOW INTEGRATION:
    - Follow up with xrefs_to(address) to see what calls this function
    - Use list_comments(filter="address") to understand peripheral context
    - Cross-reference with list_interrupts() for interrupt handler analysis
    
    RELATED FUNCTIONS:
        - get_function_xrefs(name="function_name") → See what references this function
        - xrefs_to(address="0x1234") → Find all references to specific addresses
        - list_comments(filter="0x40001000") → Understand memory-mapped register access
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def list_interrupts(offset: int = 0, limit: int = 100) -> dict:
    """
    Analyze and list active interrupts in ARM Cortex-M firmware.
    
    KEYWORDS: interrupts, IRQ, vector, handler, exception, peripheral interrupts, NVIC
    ALIASES: show interrupts, get IRQs, interrupt handlers, vector table, exceptions
    
    REVERSE ENGINEERING WORKFLOWS:
    
    🔧 QEMU Exception Analysis:
    - When QEMU hits exception: Use this to find expected interrupt handlers
    - When code is stuck waiting: Check what interrupts should trigger
    - When polling detected: Identify which IRQ might advance execution
    
    🔍 Debugging Scenarios:
    - "Code stuck, what interrupt is it waiting for?" → Check enabled interrupts
    - "Exception at handler, which IRQ triggered?" → Match handler address to IRQ
    - "Need to advance execution" → Trigger specific IRQ in QEMU
    
    📊 Analysis Sources:
    - ARM Cortex-M vector table (system exceptions + external IRQs)
    - Unique interrupt handler functions (filters out default handlers)
    - SVD comments with interrupt enable/disable operations
    - NVIC register analysis for explicit interrupt configuration
    
    Returns ONLY active interrupts:
    - System exceptions (Reset, NMI, HardFault, etc.)
    - External interrupts with dedicated handler functions
    
    Args:
        offset: Pagination offset for large interrupt lists (default: 0)
        limit: Maximum interrupts to return (default: 100)
        
    Returns:
        JSON with structured interrupt data:
        {
          "results": [
            {
              "irq_number": 27,              # Use to trigger in QEMU: "IRQ_27"
              "name": "EIC_INTREQ_15",       # Specific peripheral interrupt name
              "vector": 27,                  # Vector table position
              "handler_address": "0x196C",   # Match against QEMU PC for analysis
              "handler_function": "eic_handler", # Function name for cross-reference
              "peripheral": "EIC",           # Peripheral that generates this IRQ
              "confidence": "high",          # Reliability of detection
              "enabled": true                # Whether interrupt is enabled
            }
          ]
        }
    
    INTEGRATION WITH QEMU ANALYSIS:
    - Match QEMU PC against handler_address to identify triggered interrupt
    - Use irq_number to send interrupt trigger commands to QEMU
    - Cross-reference peripheral name with register access for root cause analysis
    
    RELATED FUNCTIONS:
        - list_segments() → Find peripheral memory regions for interrupt sources
        - list_comments(peripheral="EIC") → Understand interrupt configuration details
        - get_function_xrefs(name="eic_handler") → Analyze interrupt handler code
        - decompile_function(address="0x196C") → Understand handler implementation
    """
    return safe_get("interrupts", {"offset": offset, "limit": limit})

@mcp.tool()
def list_comments(offset: int = 0, limit: int = 1000, filter: str = None, peripheral: str = None) -> dict:
    """
    Analyze SVD comments showing detailed peripheral register access patterns.
    
    KEYWORDS: comments, SVD, registers, peripheral config, register access, memory mapped
    ALIASES: show registers, peripheral analysis, register operations, memory access
    
    REVERSE ENGINEERING WORKFLOWS:
    
    🔧 QEMU Memory Access Analysis:
    - When QEMU shows invalid memory access: Check if address maps to peripheral register
    - When code polls memory location: Understand what register/peripheral it's waiting on
    - When interrupt fails to trigger: Analyze peripheral configuration for proper setup
    
    🔍 Debugging Scenarios:
    - "Code stuck polling 0x40001000" → list_comments(filter="0x40001000")
    - "UART not working" → list_comments(peripheral="UART") 
    - "Interrupt not triggering" → list_comments(filter="INTENSET")
    - "What's configured for EIC?" → list_comments(peripheral="EIC")
    
    📊 Analysis Capabilities:
    - Peripheral register read/write operations with exact values
    - Bit field configurations and their meanings
    - Interrupt enable/disable operations
    - Register access patterns and sequences
    - Memory-mapped peripheral identification
    
    WORKFLOW INTEGRATION:
    1. Use list_segments() to identify peripheral memory regions
    2. Use list_comments(peripheral="NAME") for detailed register analysis  
    3. Use list_interrupts() to correlate with interrupt configuration
    4. Apply findings to configure QEMU peripheral state
    
    Args:
        offset: Pagination offset for large comment sets (default: 0)
        limit: Maximum comments to return (default: 1000)
        filter: Text search within comment content
                Examples: "0x40001000", "INTENSET", "WRITE:0x8000"
        peripheral: Filter by peripheral name (get names from list_segments())
                   Examples: "EIC", "RTC", "DMAC", "UART", "SPI"
        
    Returns:
        JSON with detailed register access information:
        {
          "results": [
            {
              "instruction_address": "0x00001234",  # Code location for this register access
              "peripheral": "EIC",                  # Peripheral name (matches list_segments)
              "register": "INTENSET",               # Specific register name
              "operation": "WRITE:0x8000",          # Read/Write with value
              "fields": [                           # Bit field breakdown
                {
                  "name": "EXTINT",
                  "offset": "15", 
                  "width": "1",
                  "value": "0x1",
                  "description": "External Interrupt 15 Enable"
                }
              ],
              "interrupts": [                       # Related interrupt information
                {
                  "action": "ENABLE",
                  "name": "EIC_INTREQ_15", 
                  "vector": "27"
                }
              ]
            }
          ]
        }
    
    INTEGRATION WITH QEMU ANALYSIS:
    - Match instruction_address against QEMU PC to understand current operation
    - Use peripheral/register info to set proper QEMU peripheral state
    - Apply field configurations to simulate realistic peripheral behavior
    - Use interrupt info to determine when to trigger interrupts in QEMU
    
    RELATED FUNCTIONS:
        - list_segments() → Get peripheral names and memory regions
        - list_interrupts() → See interrupts related to peripheral configuration
        - xrefs_to(address="0x40001000") → Find all code that accesses specific registers
        - decompile_function() → Understand register access context within functions
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if peripheral:
        params["peripheral"] = peripheral
    return safe_get("comments", params)

@mcp.tool()
def get_main_function() -> dict:
    """
    Find the firmware's main entry point from reset vector analysis.
    
    KEYWORDS: main, entry point, reset vector, startup, firmware entry, program start
    ALIASES: find main, entry point, reset handler, startup function, program entry
    
    REVERSE ENGINEERING WORKFLOWS:
    
    🔧 QEMU Startup Analysis:
    - When QEMU execution begins: Use this to find where main program logic starts
    - When analyzing firmware flow: Identify the primary entry point after reset
    - When debugging initialization: Find the start of application code
    
    🔍 Debugging Scenarios:
    - "Where does the program start?" → Use this to get main entry point
    - "QEMU reset, where should execution begin?" → Get reset vector target
    - "Need to set QEMU PC for main analysis" → Use instruction_address
    
    📊 Analysis Method:
    - Searches for special SVD comment marking main function
    - Identified through ARM Cortex-M reset vector analysis
    - Points to actual application start (not just reset handler)
    
    Returns:
        JSON with main function details:
        {
          "found": true,
          "instruction_address": "0x00000F04",     # Set QEMU PC here for main analysis
          "comment": "SVD: Main entry point - Application start..."
        }
        
        Or if not found:
        {
          "found": false,
          "instruction_address": null,
          "comment": null
        }
    
    INTEGRATION WITH QEMU ANALYSIS:
    - Use instruction_address to set QEMU PC for main program analysis
    - Start dynamic analysis from this point after reset
    - Compare against QEMU reset vector execution path
    
    RELATED FUNCTIONS:
        - decompile_function(address=instruction_address) → Analyze main function code
        - get_function_xrefs(name="main") → See what calls or references main
        - list_interrupts() → Understand interrupt setup in main initialization
    """
    return safe_get("main_function", {})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

