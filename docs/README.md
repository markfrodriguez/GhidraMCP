# GhidraMCP Documentation

## Overview

This documentation package provides comprehensive guidance for using the GhidraMCP server in sophisticated firmware reverse engineering workflows, particularly for QEMU + Ghidra integration scenarios.

## Document Structure

### 📘 [QEMU_GHIDRA_INTEGRATION.md](./QEMU_GHIDRA_INTEGRATION.md)
**Primary integration guide covering the complete QEMU + Ghidra workflow architecture**

- System architecture and communication flow
- Core integration workflows (Exception Analysis, Polling Detection, Interrupt Waiting, etc.)
- Advanced integration patterns and state synchronization
- Error handling and best practices
- Complete mermaid diagrams showing workflow decision trees

**When to use**: Start here for understanding the overall system architecture and workflow concepts.

### 📗 [MCP_FUNCTION_REFERENCE.md](./MCP_FUNCTION_REFERENCE.md)
**Comprehensive reference for all MCP functions with reverse engineering focus**

- Complete function documentation with QEMU integration scenarios
- Keywords, aliases, and natural language mappings for LLM discovery
- Detailed parameter explanations and return value structures
- Cross-function relationships and workflow integration
- Quick reference patterns for common analysis tasks

**When to use**: Reference guide for specific function usage, parameter details, and integration examples.

### 📙 [WORKFLOW_EXAMPLES.md](./WORKFLOW_EXAMPLES.md)
**Real-world scenario examples with step-by-step analysis procedures**

- 5 detailed examples covering common firmware debugging scenarios
- Complete code examples with expected outputs
- Root cause analysis procedures and resolution actions
- Pattern recognition guide for similar scenarios
- Debugging checklist for systematic problem solving

**When to use**: Practical examples for implementing specific debugging workflows and understanding problem-solving approaches.

## Quick Start Guide

### For LLM Agents
1. **System Understanding**: Read [QEMU_GHIDRA_INTEGRATION.md](./QEMU_GHIDRA_INTEGRATION.md) sections 1-2
2. **Function Discovery**: Use keywords and aliases from [MCP_FUNCTION_REFERENCE.md](./MCP_FUNCTION_REFERENCE.md)
3. **Scenario Handling**: Reference [WORKFLOW_EXAMPLES.md](./WORKFLOW_EXAMPLES.md) for similar situations

### For Developers
1. **Architecture**: Review complete [QEMU_GHIDRA_INTEGRATION.md](./QEMU_GHIDRA_INTEGRATION.md)
2. **Implementation**: Study workflow examples in [WORKFLOW_EXAMPLES.md](./WORKFLOW_EXAMPLES.md)
3. **Function Reference**: Use [MCP_FUNCTION_REFERENCE.md](./MCP_FUNCTION_REFERENCE.md) for API details

### For Reverse Engineers
1. **Problem Scenarios**: Start with [WORKFLOW_EXAMPLES.md](./WORKFLOW_EXAMPLES.md) for your specific issue
2. **Analysis Functions**: Use [MCP_FUNCTION_REFERENCE.md](./MCP_FUNCTION_REFERENCE.md) for detailed analysis
3. **Advanced Patterns**: Reference [QEMU_GHIDRA_INTEGRATION.md](./QEMU_GHIDRA_INTEGRATION.md) for complex scenarios

## Key Concepts

### Workflow Categories
- **🔧 Exception Analysis**: QEMU hits exception → Ghidra analysis → State correction
- **🔍 Polling Detection**: Code stuck waiting → Register analysis → State advancement  
- **⚡ Interrupt Analysis**: Missing interrupts → Configuration check → Trigger setup
- **🗺️ Memory Analysis**: Invalid access → Layout verification → Region mapping
- **🚀 Startup Analysis**: Initialization issues → Entry point analysis → Environment setup

### Function Categories
- **🔧 Core Analysis**: `decompile_function_by_address`, `get_main_function`, `list_interrupts`, `list_comments`
- **📊 Memory & Structure**: `list_segments`, `list_strings`, `list_methods`, `list_classes`
- **🔍 Cross-Reference**: `get_function_xrefs`, `xrefs_to`, `xrefs_from`

### Integration Patterns
- **State Correlation**: QEMU execution state ↔ Ghidra code analysis
- **Progressive Analysis**: Incremental understanding and targeted fixes
- **Bidirectional Flow**: QEMU informs analysis → Ghidra guides corrections → QEMU validation

## Common Use Cases

| Scenario | Primary Document | Key Functions |
|----------|------------------|---------------|
| QEMU exception during execution | [Examples #1](./WORKFLOW_EXAMPLES.md#example-1-exception-in-interrupt-handler) | `decompile_function_by_address`, `list_interrupts` |
| Code stuck in polling loop | [Examples #2](./WORKFLOW_EXAMPLES.md#example-2-code-stuck-in-polling-loop) | `list_comments`, `xrefs_to` |
| Interrupt never triggers | [Examples #3](./WORKFLOW_EXAMPLES.md#example-3-missing-interrupt-trigger) | `list_interrupts`, `list_comments` |
| Memory access failure | [Examples #4](./WORKFLOW_EXAMPLES.md#example-4-memory-initialization-issue) | `list_segments`, `xrefs_to` |
| Peripheral not responding | [Examples #5](./WORKFLOW_EXAMPLES.md#example-5-peripheral-not-responding) | `list_comments`, `decompile_function_by_address` |
| Understanding system architecture | [Integration Guide](./QEMU_GHIDRA_INTEGRATION.md) | `get_main_function`, `list_segments` |
| Function-specific analysis | [Function Reference](./MCP_FUNCTION_REFERENCE.md) | All functions with detailed examples |

## Advanced Topics

### Multi-Agent Coordination
- **QEMU Agent**: Monitors execution, reports state, applies corrections
- **Ghidra Agent**: Analyzes code structure, provides insights, suggests actions
- **Orchestrator Agent**: Coordinates analysis flow, makes decisions, manages workflow

### State Synchronization
- **Memory Layout**: Ensure QEMU memory map matches Ghidra analysis
- **Peripheral State**: Configure QEMU peripherals based on Ghidra configuration analysis
- **Interrupt Timing**: Coordinate interrupt triggers with code execution state

### Error Recovery
- **Analysis Failures**: Fallback strategies when primary analysis methods fail
- **State Corruption**: Recovery procedures for invalid QEMU states
- **Integration Issues**: Handling communication failures between systems

## Contributing

When extending this documentation:

1. **Maintain Structure**: Follow the three-document pattern (Architecture → Reference → Examples)
2. **Include Examples**: Provide concrete code examples for all new patterns
3. **Cross-Reference**: Link related concepts across documents
4. **Update Keywords**: Add relevant keywords and aliases for LLM discovery
5. **Test Workflows**: Validate examples with actual QEMU + Ghidra scenarios

## Support

For implementation questions:
- Check [WORKFLOW_EXAMPLES.md](./WORKFLOW_EXAMPLES.md) for similar scenarios
- Reference [MCP_FUNCTION_REFERENCE.md](./MCP_FUNCTION_REFERENCE.md) for function details
- Review [QEMU_GHIDRA_INTEGRATION.md](./QEMU_GHIDRA_INTEGRATION.md) for architectural guidance

This documentation framework enables sophisticated automated firmware reverse engineering through the coordinated use of QEMU dynamic analysis and Ghidra static analysis capabilities.