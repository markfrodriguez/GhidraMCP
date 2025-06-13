package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        server.createContext("/interrupts", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listInterrupts(offset, limit));
        });

        server.createContext("/comments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 1000);
            String filter = qparams.get("filter");
            String peripheral = qparams.get("peripheral");
            sendResponse(exchange, listComments(offset, limit, filter, peripheral));
        });

        server.createContext("/main_function", exchange -> {
            sendResponse(exchange, getMainFunction());
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Interrupt Analysis Methods
    // ----------------------------------------------------------------------------------

    /**
     * List all interrupts found through comprehensive analysis
     */
    private String listInterrupts(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            List<InterruptInfo> interrupts = analyzeInterrupts(program);
            
            // Apply pagination
            List<String> formattedResults = new ArrayList<>();
            for (InterruptInfo interrupt : interrupts) {
                formattedResults.add(formatInterruptInfo(interrupt));
            }
            
            return paginateList(formattedResults, offset, limit);
        } catch (Exception e) {
            return "Error analyzing interrupts: " + e.getMessage();
        }
    }

    /**
     * List all SVD comments in the program with their addresses and parsed information
     */
    private String listComments(int offset, int limit, String filter, String peripheral) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            List<CommentInfo> comments = collectAllSVDComments(program, filter, peripheral);
            
            // Apply pagination
            List<Map<String, Object>> formattedResults = new ArrayList<>();
            for (CommentInfo comment : comments) {
                Map<String, Object> commentData = new HashMap<>();
                commentData.put("instruction_address", String.format("0x%08X", comment.address.getOffset()));
                commentData.put("comment", comment.fullComment);
                commentData.put("peripheral", comment.peripheral);
                commentData.put("register", comment.register);
                commentData.put("operation", comment.operation);
                commentData.put("size", comment.size);
                commentData.put("fields", comment.fields);
                commentData.put("interrupts", comment.interrupts);
                commentData.put("mode_context", comment.modeContext);
                formattedResults.add(commentData);
            }
            
            return formatCommentsAsJson(formattedResults, offset, limit);
        } catch (Exception e) {
            return "Error collecting comments: " + e.getMessage();
        }
    }

    /**
     * Get the main function entry point identified from reset vector analysis
     */
    private String getMainFunction() {
        Program program = getCurrentProgram();
        if (program == null) {
            return formatMainFunctionResponse(false, null, null, "No program loaded");
        }

        try {
            Listing listing = program.getListing();
            
            // Search for the special main function SVD comment
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                Address start = block.getStart();
                Address end = block.getEnd();
                
                // Iterate through addresses in the block
                for (Address address = start; address.compareTo(end) <= 0; address = address.add(1)) {
                    // Check all comment types at each address
                    for (int commentType : new int[]{CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT, 
                                                    CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT}) {
                        String comment = listing.getComment(commentType, address);
                        if (comment != null && isMainFunctionComment(comment)) {
                            // Found the main function comment
                            String instructionAddress = String.format("0x%08X", address.getOffset());
                            return formatMainFunctionResponse(true, instructionAddress, comment, null);
                        }
                    }
                }
            }
            
            // Main function comment not found
            return formatMainFunctionResponse(false, null, null, null);
            
        } catch (Exception e) {
            return formatMainFunctionResponse(false, null, null, "Error searching for main function: " + e.getMessage());
        }
    }

    /**
     * Check if a comment is the special main function marker
     */
    private boolean isMainFunctionComment(String comment) {
        return comment.startsWith("SVD: Main entry point") && 
               comment.contains("Application start") &&
               comment.contains("auto-identified from reset vector analysis");
    }

    /**
     * Format the main function response as JSON
     */
    private String formatMainFunctionResponse(boolean found, String instructionAddress, String comment, String error) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"found\":").append(found).append(",");
        
        if (instructionAddress != null) {
            json.append("\"instruction_address\":\"").append(instructionAddress).append("\",");
        } else {
            json.append("\"instruction_address\":null,");
        }
        
        if (comment != null) {
            json.append("\"comment\":\"").append(escapeJsonString(comment)).append("\"");
        } else {
            json.append("\"comment\":null");
        }
        
        if (error != null) {
            json.append(",\"error\":\"").append(escapeJsonString(error)).append("\"");
        }
        
        json.append("}");
        return json.toString();
    }

    /**
     * Comprehensive interrupt analysis combining multiple techniques
     */
    private List<InterruptInfo> analyzeInterrupts(Program program) {
        Map<Integer, InterruptInfo> interruptMap = new HashMap<>();
        
        // 1. Analyze vector table (primary source)
        analyzeVectorTable(program, interruptMap);
        
        // 2. Analyze NVIC register operations
        analyzeNVICOperations(program, interruptMap);
        
        // 3. Identify interrupt handler functions
        identifyInterruptHandlers(program, interruptMap);
        
        // 4. Analyze GhidraSVD comments for interrupt information
        analyzeGhidraSVDComments(program, interruptMap);
        
        // 5. Analyze peripheral register configurations
        analyzePeripheralInterruptConfig(program, interruptMap);
        
        // 6. Filter to only include actually configured interrupts
        List<InterruptInfo> interrupts = filterActiveInterrupts(interruptMap);
        interrupts.sort((a, b) -> Integer.compare(a.irqNumber, b.irqNumber));
        
        return interrupts;
    }

    /**
     * Analyze the ARM Cortex-M vector table starting at address 0x00000000
     */
    private void analyzeVectorTable(Program program, Map<Integer, InterruptInfo> interruptMap) {
        try {
            Address vectorTableBase = program.getAddressFactory().getAddress("0x00000000");
            Memory memory = program.getMemory();
            
            // ARM Cortex-M system exception vectors
            Map<Integer, String> systemVectors = new HashMap<>();
            systemVectors.put(0x04, "Reset");
            systemVectors.put(0x08, "NMI");
            systemVectors.put(0x0C, "HardFault");
            systemVectors.put(0x10, "MemManage");
            systemVectors.put(0x14, "BusFault");
            systemVectors.put(0x18, "UsageFault");
            systemVectors.put(0x2C, "SVCall");
            systemVectors.put(0x38, "PendSV");
            systemVectors.put(0x3C, "SysTick");
            
            // Read system exception vectors
            for (Map.Entry<Integer, String> entry : systemVectors.entrySet()) {
                int offset = entry.getKey();
                String name = entry.getValue();
                
                Address vectorAddr = vectorTableBase.add(offset);
                if (memory.contains(vectorAddr)) {
                    try {
                        long handlerAddr = memory.getInt(vectorAddr) & 0xFFFFFFFEL; // Clear thumb bit
                        if (handlerAddr != 0) {
                            int irqNumber = getSystemExceptionNumber(name);
                            InterruptInfo info = interruptMap.computeIfAbsent(irqNumber, 
                                k -> new InterruptInfo(k, name, "system_exception"));
                            info.handlerAddress = handlerAddr;
                            info.vectorTableOffset = offset;
                        }
                    } catch (Exception e) {
                        // Skip invalid addresses
                    }
                }
            }
            
            // Read external interrupt vectors (starting at 0x40)
            int irqOffset = 0x40;
            int irqNum = 0;
            int consecutiveZeros = 0;
            
            while (irqNum < 150) { // Reasonable limit for ARM Cortex-M4
                Address vectorAddr = vectorTableBase.add(irqOffset);
                if (!memory.contains(vectorAddr)) {
                    break;
                }
                
                try {
                    long handlerAddr = memory.getInt(vectorAddr) & 0xFFFFFFFEL; // Clear thumb bit
                    if (handlerAddr == 0) {
                        consecutiveZeros++;
                        if (consecutiveZeros > 10) {
                            // Likely reached end of valid vector table
                            break;
                        }
                        irqOffset += 4;
                        irqNum++;
                        continue;
                    }
                    
                    consecutiveZeros = 0; // Reset counter
                    
                    // Validate handler address is within reasonable code range
                    if (isValidCodeAddress(program, handlerAddr)) {
                        String irqName = "IRQ_" + irqNum;
                        InterruptInfo info = interruptMap.computeIfAbsent(irqNum, 
                            k -> new InterruptInfo(k, irqName, "external_irq"));
                        info.handlerAddress = handlerAddr;
                        info.vectorTableOffset = irqOffset;
                    }
                    
                } catch (Exception e) {
                    // Skip invalid addresses
                }
                
                irqOffset += 4;
                irqNum++;
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error analyzing vector table: " + e.getMessage());
        }
    }

    /**
     * Analyze NVIC register operations to find interrupt configurations
     */
    private void analyzeNVICOperations(Program program, Map<Integer, InterruptInfo> interruptMap) {
        // NVIC register addresses for ARM Cortex-M
        Map<String, Long> nvicRegisters = new HashMap<>();
        nvicRegisters.put("ISER0", 0xE000E100L); // Interrupt Set Enable Register 0
        nvicRegisters.put("ISER1", 0xE000E104L); // Interrupt Set Enable Register 1
        nvicRegisters.put("ISER2", 0xE000E108L); // Interrupt Set Enable Register 2
        nvicRegisters.put("ISER3", 0xE000E10CL); // Interrupt Set Enable Register 3
        nvicRegisters.put("ICER0", 0xE000E180L); // Interrupt Clear Enable Register 0
        nvicRegisters.put("ICER1", 0xE000E184L); // Interrupt Clear Enable Register 1
        nvicRegisters.put("ICER2", 0xE000E188L); // Interrupt Clear Enable Register 2
        nvicRegisters.put("ICER3", 0xE000E18CL); // Interrupt Clear Enable Register 3
        
        ReferenceManager refManager = program.getReferenceManager();
        
        for (Map.Entry<String, Long> entry : nvicRegisters.entrySet()) {
            String regName = entry.getKey();
            Long regAddr = entry.getValue();
            
            try {
                Address nvicAddr = program.getAddressFactory().getAddress(String.format("0x%08X", regAddr));
                ReferenceIterator refs = refManager.getReferencesTo(nvicAddr);
                
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    if (ref.getReferenceType().isWrite()) {
                        analyzeNVICWrite(program, ref, regName, regAddr, interruptMap);
                    }
                }
            } catch (Exception e) {
                // Skip invalid addresses
            }
        }
    }

    /**
     * Analyze a specific NVIC register write operation
     */
    private void analyzeNVICWrite(Program program, Reference ref, String regName, long nvicAddr, 
                                 Map<Integer, InterruptInfo> interruptMap) {
        try {
            Address fromAddr = ref.getFromAddress();
            Instruction instruction = program.getListing().getInstructionAt(fromAddr);
            
            if (instruction != null) {
                // Try to extract immediate value from the instruction
                Long immediateValue = extractImmediateValue(instruction);
                if (immediateValue != null) {
                    // Determine register index (0-3 for different 32-bit chunks)
                    int registerIndex = getRegisterIndex(regName);
                    
                    // Decode which IRQ bits are set
                    for (int bit = 0; bit < 32; bit++) {
                        if ((immediateValue & (1L << bit)) != 0) {
                            int irqNum = registerIndex * 32 + bit;
                            
                            InterruptInfo info = interruptMap.computeIfAbsent(irqNum, 
                                k -> new InterruptInfo(k, "IRQ_" + k, "external_irq"));
                            
                            // Record NVIC operation
                            info.nvicOperations.add(new NVICOperation(regName, fromAddr.getOffset(), immediateValue));
                            
                            if (regName.startsWith("ISER")) {
                                info.enabled = true;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Skip invalid instructions
        }
    }

    /**
     * Identify interrupt handler functions by analyzing calling patterns
     */
    private void identifyInterruptHandlers(Program program, Map<Integer, InterruptInfo> interruptMap) {
        FunctionManager funcManager = program.getFunctionManager();
        
        // Check if any known handler addresses correspond to actual functions
        for (InterruptInfo interrupt : interruptMap.values()) {
            if (interrupt.handlerAddress != 0) {
                try {
                    Address handlerAddr = program.getAddressFactory().getAddress(String.format("0x%08X", interrupt.handlerAddress));
                    Function handler = funcManager.getFunctionAt(handlerAddr);
                    
                    if (handler != null) {
                        interrupt.handlerFunctionName = handler.getName();
                        interrupt.isHandlerFunction = true;
                    } else {
                        // Check if there's a function containing this address
                        Function containingFunc = funcManager.getFunctionContaining(handlerAddr);
                        if (containingFunc != null) {
                            interrupt.handlerFunctionName = containingFunc.getName() + "+offset";
                            interrupt.isHandlerFunction = true;
                        }
                    }
                } catch (Exception e) {
                    // Skip invalid addresses
                }
            }
        }
    }

    /**
     * Format interrupt information for display
     */
    private String formatInterruptInfo(InterruptInfo interrupt) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("IRQ %d: %s", interrupt.irqNumber, interrupt.name));
        sb.append(String.format(" [%s]", interrupt.type));
        
        // Add confidence and reason
        if (!"unknown".equals(interrupt.confidence)) {
            sb.append(String.format(" {%s:%s}", interrupt.confidence.toUpperCase(), interrupt.reason));
        }
        
        if (interrupt.handlerAddress != 0) {
            sb.append(String.format(" -> 0x%08X", interrupt.handlerAddress));
            if (interrupt.handlerFunctionName != null) {
                sb.append(" (").append(interrupt.handlerFunctionName).append(")");
            }
        }
        
        if (interrupt.vectorTableOffset != -1) {
            sb.append(String.format(" VT:0x%02X", interrupt.vectorTableOffset));
        }
        
        // Add peripheral information with register details
        if (interrupt.peripheralName != null) {
            sb.append(String.format(" %s", interrupt.peripheralName));
            if (interrupt.registerName != null) {
                sb.append(String.format(".%s", interrupt.registerName));
            }
            if (interrupt.interruptSource != null) {
                sb.append(String.format("(%s)", interrupt.interruptSource));
            }
        }
        
        // Add SVD description if available
        if (interrupt.svdDescription != null && !interrupt.svdDescription.isEmpty()) {
            sb.append(String.format(" \"%s\"", interrupt.svdDescription));
        }
        
        // Add trigger type if detected
        if (interrupt.triggerType != null) {
            sb.append(String.format(" [%s]", interrupt.triggerType));
        }
        
        // Add configured value
        if (interrupt.configuredValue != null) {
            sb.append(String.format(" Value:%s", interrupt.configuredValue));
        }
        
        // Add bit field configuration (shortened)
        if (interrupt.bitFieldConfig != null && !interrupt.bitFieldConfig.isEmpty()) {
            String shortBitFields = interrupt.bitFieldConfig.length() > 50 
                ? interrupt.bitFieldConfig.substring(0, 47) + "..." 
                : interrupt.bitFieldConfig;
            sb.append(String.format(" Fields:{%s}", shortBitFields));
        }
        
        if (interrupt.enabled) {
            sb.append(" [ENABLED]");
        }
        
        if (!interrupt.nvicOperations.isEmpty()) {
            sb.append(" NVIC:");
            for (NVICOperation op : interrupt.nvicOperations) {
                sb.append(String.format(" %s@0x%08X", op.operation, op.address));
            }
        }
        
        // Add configuration addresses if available
        if (interrupt.hasPeripheralConfig) {
            sb.append(String.format(" Cfg:0x%08X", interrupt.peripheralConfigAddress));
        }
        
        return sb.toString();
    }

    /**
     * Helper method to extract immediate values from instructions
     */
    private Long extractImmediateValue(Instruction instruction) {
        try {
            // Check each operand for immediate values
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                Object[] opObjects = instruction.getOpObjects(i);
                for (Object obj : opObjects) {
                    if (obj instanceof Number) {
                        return ((Number) obj).longValue();
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get system exception number for ARM Cortex-M
     */
    private int getSystemExceptionNumber(String name) {
        switch (name) {
            case "Reset": return -3;
            case "NMI": return -2;
            case "HardFault": return -1;
            case "MemManage": return -12;
            case "BusFault": return -11;
            case "UsageFault": return -10;
            case "SVCall": return -5;
            case "PendSV": return -2;
            case "SysTick": return -1;
            default: return 0;
        }
    }

    /**
     * Get register index from NVIC register name
     */
    private int getRegisterIndex(String regName) {
        if (regName.endsWith("0")) return 0;
        if (regName.endsWith("1")) return 1;
        if (regName.endsWith("2")) return 2;
        if (regName.endsWith("3")) return 3;
        return 0;
    }

    /**
     * Analyze GhidraSVD comments using peripheral-centric approach
     */
    private void analyzeGhidraSVDComments(Program program, Map<Integer, InterruptInfo> interruptMap) {
        try {
            // Step 1: Collect all SVD comments grouped by peripheral
            Map<String, List<SVDComment>> peripheralComments = collectSVDCommentsByPeripheral(program);
            
            // Debug: Write all collected SVD comments to file
            writeSVDCommentsToFile(peripheralComments);
            
            // Step 2: For each peripheral, find the best interrupt configuration
            for (Map.Entry<String, List<SVDComment>> entry : peripheralComments.entrySet()) {
                String peripheralName = entry.getKey();
                List<SVDComment> comments = entry.getValue();
                
                // Find the best interrupt configuration for this peripheral
                SVDComment bestConfig = findBestInterruptConfiguration(comments);
                if (bestConfig != null) {
                    // Map this peripheral to its IRQ and update interrupt info
                    updateInterruptInfoFromBestConfig(peripheralName, bestConfig, interruptMap);
                }
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error analyzing GhidraSVD comments: " + e.getMessage());
        }
    }

    /**
     * Collect all SVD comments grouped by peripheral name
     */
    private Map<String, List<SVDComment>> collectSVDCommentsByPeripheral(Program program) {
        Map<String, List<SVDComment>> peripheralComments = new HashMap<>();
        Listing listing = program.getListing();
        
        // Search through all memory blocks for SVD comments
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            collectCommentsFromBlock(listing, block, peripheralComments);
        }
        
        return peripheralComments;
    }

    /**
     * Collect SVD comments from a specific memory block
     */
    private void collectCommentsFromBlock(Listing listing, MemoryBlock block, 
                                        Map<String, List<SVDComment>> peripheralComments) {
        try {
            Address start = block.getStart();
            Address end = block.getEnd();
            
            // Check data comments
            DataIterator dataIter = listing.getDefinedData(start, true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.getAddress().compareTo(end) > 0) break;
                
                collectCommentsFromAddress(listing, data.getAddress(), peripheralComments);
            }
            
            // Check instruction comments
            InstructionIterator instrIter = listing.getInstructions(start, true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                if (instr.getAddress().compareTo(end) > 0) break;
                
                collectCommentsFromAddress(listing, instr.getAddress(), peripheralComments);
            }
            
        } catch (Exception e) {
            // Skip problematic blocks
        }
    }

    /**
     * Collect all SVD comments from a specific address
     */
    private void collectCommentsFromAddress(Listing listing, Address address, 
                                          Map<String, List<SVDComment>> peripheralComments) {
        for (int commentType : new int[]{CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT, 
                                        CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT}) {
            String comment = listing.getComment(commentType, address);
            if (comment != null && comment.startsWith("SVD:")) {
                SVDComment svdComment = parseSVDCommentStructure(comment, address);
                if (svdComment != null) {
                    peripheralComments.computeIfAbsent(svdComment.peripheralName, k -> new ArrayList<>()).add(svdComment);
                }
            }
        }
    }

    /**
     * Find the best interrupt configuration from a list of peripheral comments
     */
    private SVDComment findBestInterruptConfiguration(List<SVDComment> comments) {
        if (comments.isEmpty()) {
            return null;
        }
        
        // Sort comments by priority (best interrupt config first)
        comments.sort((a, b) -> {
            int priorityA = getInterruptConfigPriority(a);
            int priorityB = getInterruptConfigPriority(b);
            return Integer.compare(priorityB, priorityA); // Higher priority first
        });
        
        // Return the highest priority comment that has interrupt relevance
        for (SVDComment comment : comments) {
            if (getInterruptConfigPriority(comment) > 0) {
                return comment;
            }
        }
        
        return null;
    }

    /**
     * Get priority score for interrupt configuration (higher = better)
     */
    private int getInterruptConfigPriority(SVDComment comment) {
        String regName = comment.registerName.toUpperCase();
        
        // Priority 1: Explicit interrupt enable registers (highest priority)
        if (regName.matches(".*(INTENSET|INTENCLR|INTEN|IER|IMR|IMASK).*")) {
            // Extra points if it has actual interrupt source details in bit fields
            if (hasSpecificInterruptSources(comment)) {
                return 100;
            }
            return 90;
        }
        
        // Priority 2: Configuration registers with interrupt details
        if (regName.matches(".*(CONFIG|CFG).*") && hasSpecificInterruptSources(comment)) {
            return 80;
        }
        
        // Priority 3: Control registers with interrupt-related fields
        if (regName.matches(".*(CTRL|CTRLA|CTRLB).*") && hasInterruptRelatedFields(comment)) {
            return 60;
        }
        
        // Priority 4: Event control registers
        if (regName.matches(".*(EVCTRL|EVACT).*")) {
            return 50;
        }
        
        // Priority 5: Status/flag registers (lower priority)
        if (regName.matches(".*(STATUS|INTFLAG|FLAG).*")) {
            return 30;
        }
        
        // No interrupt relevance
        return 0;
    }

    /**
     * Check if comment has specific interrupt sources (SENSE7, CH3, EXTINT15, etc.)
     */
    private boolean hasSpecificInterruptSources(SVDComment comment) {
        String content = comment.fullComment.toUpperCase();
        
        // Look for numbered interrupt sources
        return content.matches(".*(SENSE\\d+|CH\\d+|EXTINT\\d+|INT\\d+|OC\\d+|CC\\d+|IC\\d+).*") ||
               content.matches(".*(OVF|COMPA|COMPB|CAPT|ERROR|READY|DONE).*");
    }

    /**
     * Check if comment has interrupt-related fields (even if not specific sources)
     */
    private boolean hasInterruptRelatedFields(SVDComment comment) {
        String content = comment.fullComment.toUpperCase();
        return content.contains("INTERRUPT") || content.contains("INTEN") || 
               content.contains("ENABLE") || content.contains("IE") ||
               content.contains("MASK") || content.contains("FLAG");
    }

    /**
     * Update interrupt info from the best configuration found for a peripheral
     */
    private void updateInterruptInfoFromBestConfig(String peripheralName, SVDComment bestConfig, 
                                                 Map<Integer, InterruptInfo> interruptMap) {
        try {
            // Get IRQ mapping for this peripheral
            int irqNum = mapPeripheralToIRQ(peripheralName, bestConfig.registerName);
            
            if (irqNum >= 0) {
                // Generate interrupt name with specific source if possible
                String interruptName = generateInterruptName(peripheralName, bestConfig.registerName, bestConfig.fullComment);
                InterruptInfo info = interruptMap.computeIfAbsent(irqNum, 
                    k -> new InterruptInfo(k, interruptName, "external_irq"));
                
                // Update with best configuration details
                info.name = interruptName;
                info.peripheralName = peripheralName;
                info.registerName = bestConfig.registerName;
                info.hasPeripheralConfig = true;
                info.peripheralConfigAddress = bestConfig.address.getOffset();
                info.svdDescription = bestConfig.description;
                info.configuredValue = bestConfig.configuredValue;
                
                // Parse bit field information from the best config
                parseBitFields(bestConfig.fullComment, info);
                
                // Mark this as a high-confidence peripheral config
                if (info.confidence.equals("unknown")) {
                    info.confidence = "high";
                    info.reason = "best_peripheral_config";
                }
            }
            
        } catch (Exception e) {
            // Skip problematic configurations
        }
    }

    /**
     * Extract interrupt information from GhidraSVD comments
     */
    private void extractInterruptInfoFromComment(String comment, Address address, 
                                               Map<Integer, InterruptInfo> interruptMap) {
        try {
            // Parse structured SVD comments (format: "SVD: PERIPHERAL.REGISTER - Description")
            if (comment.startsWith("SVD:")) {
                parseSVDComment(comment, address, interruptMap);
                return;
            }
            
            String lowerComment = comment.toLowerCase();
            
            // Look for interrupt enable patterns in regular comments
            if (lowerComment.contains("interrupt") && (lowerComment.contains("enable") || 
                lowerComment.contains("intenset") || lowerComment.contains("inten"))) {
                
                // Extract peripheral and interrupt names from the comment
                String peripheralName = extractPeripheralName(comment);
                String interruptName = extractInterruptName(comment);
                
                if (peripheralName != null && interruptName != null) {
                    // Try to map to IRQ number using known mappings
                    int irqNum = mapPeripheralToIRQ(peripheralName, interruptName);
                    if (irqNum >= 0) {
                        InterruptInfo info = interruptMap.computeIfAbsent(irqNum, 
                            k -> new InterruptInfo(k, peripheralName + "_" + interruptName, "external_irq"));
                        info.hasPeripheralConfig = true;
                        info.peripheralConfigAddress = address.getOffset();
                        info.peripheralName = peripheralName;
                        info.interruptSource = interruptName;
                    }
                }
            }
            
            // Look for NVIC register names in comments
            if (lowerComment.contains("nvic") || lowerComment.contains("iser") || 
                lowerComment.contains("icer") || lowerComment.contains("interrupt")) {
                
                // Extract IRQ numbers from comments like "IRQ11", "External Interrupt 11", etc.
                String irqNumber = extractIRQNumberFromComment(comment);
                if (irqNumber != null) {
                    try {
                        int irqNum = Integer.parseInt(irqNumber);
                        if (irqNum >= 0 && irqNum < 150) { // Validate reasonable range
                            InterruptInfo info = interruptMap.computeIfAbsent(irqNum, 
                                k -> new InterruptInfo(k, "IRQ_" + k, "external_irq"));
                            info.hasCommentInfo = true;
                            info.commentInfoAddress = address.getOffset();
                        }
                    } catch (NumberFormatException e) {
                        // Skip invalid numbers
                    }
                }
            }
            
        } catch (Exception e) {
            // Skip problematic comments
        }
    }

    /**
     * Parse structured SVD comments to extract detailed interrupt information
     */
    private void parseSVDComment(String comment, Address address, Map<Integer, InterruptInfo> interruptMap) {
        try {
            // Example: "SVD: EIC.CONFIG1 - External Interrupt Controller; External Interrupt Sense Configuration [32-bit] {SENSE7:RISE - Rising edge detection (0x1)} <== 0x10000000"
            
            // Extract peripheral name from "SVD: PERIPHERAL.REGISTER"
            String[] parts = comment.split(" - ", 2);
            if (parts.length < 2) return;
            
            String regPart = parts[0].trim();
            if (!regPart.startsWith("SVD:")) return;
            
            String regInfo = regPart.substring(4).trim(); // Remove "SVD:"
            String[] regComponents = regInfo.split("\\.", 2);
            if (regComponents.length < 2) return;
            
            String peripheralName = regComponents[0].trim();
            String registerName = regComponents[1].trim();
            
            // Extract the value written to the register from "<== VALUE" pattern
            String writtenValue = extractWrittenValueFromComment(comment);
            
            // Check if this is an interrupt-related register
            if (isInterruptRegister(registerName)) {
                // Get IRQ mapping for this peripheral
                int irqNum = mapPeripheralToIRQ(peripheralName, registerName);
                
                if (irqNum >= 0) {
                    // Create or update interrupt info
                    String interruptName = generateInterruptName(peripheralName, registerName, comment);
                    InterruptInfo info = interruptMap.computeIfAbsent(irqNum, 
                        k -> new InterruptInfo(k, interruptName, "external_irq"));
                    
                    // Update with SVD details
                    info.peripheralName = peripheralName;
                    info.registerName = registerName;
                    info.hasPeripheralConfig = true;
                    info.peripheralConfigAddress = address.getOffset();
                    info.svdDescription = extractDescription(parts[1]);
                    info.configuredValue = writtenValue;
                    
                    // Parse bit field information
                    parseBitFields(comment, info);
                } else {
                    // Store peripheral config for later correlation
                    storePeripheralConfig(peripheralName, registerName, address, writtenValue, comment, interruptMap);
                }
            }
            
        } catch (Exception e) {
            // Skip problematic SVD comments
        }
    }

    /**
     * Check if register name indicates interrupt functionality
     */
    private boolean isInterruptRegister(String registerName) {
        String lowerName = registerName.toLowerCase();
        return lowerName.contains("inten") || lowerName.contains("intenset") || 
               lowerName.contains("intenclr") || lowerName.contains("config") ||
               lowerName.contains("ctrl") || lowerName.contains("evctrl");
    }

    /**
     * Generate a descriptive interrupt name from SVD information
     */
    private String generateInterruptName(String peripheral, String register, String comment) {
        // Try to extract specific interrupt source from bit fields
        String specificSource = extractSpecificInterruptSource(comment);
        if (specificSource != null) {
            return peripheral + "_" + specificSource;
        }
        
        // Fallback to peripheral + register
        return peripheral + "_" + register;
    }

    /**
     * Extract specific interrupt source from bit field information using generic patterns
     */
    private String extractSpecificInterruptSource(String comment) {
        String configuredValue = extractWrittenValueFromComment(comment);
        
        // Strategy 1: Look for enabled fields with non-zero values in bit field config
        List<String> enabledSources = findEnabledInterruptSources(comment, configuredValue);
        if (!enabledSources.isEmpty()) {
            // Return the most specific source found
            return selectBestInterruptSource(enabledSources);
        }
        
        // Strategy 2: Generic pattern matching for interrupt source names
        return findInterruptSourceByPattern(comment);
    }

    /**
     * Find interrupt sources that are enabled (have non-zero values) in the bit fields
     */
    private List<String> findEnabledInterruptSources(String comment, String configuredValue) {
        List<String> enabledSources = new ArrayList<>();
        
        if (configuredValue == null) {
            return enabledSources;
        }
        
        try {
            // Parse the configured value
            long value = parseHexOrDecimal(configuredValue);
            if (value == 0) {
                return enabledSources;
            }
            
            // Extract bit field configurations from {...} pattern
            java.util.regex.Pattern bitFieldPattern = java.util.regex.Pattern.compile("\\{([^}]+)\\}");
            java.util.regex.Matcher matcher = bitFieldPattern.matcher(comment);
            
            while (matcher.find()) {
                String bitFields = matcher.group(1);
                enabledSources.addAll(analyzeEnabledBitFields(bitFields, value));
            }
            
        } catch (Exception e) {
            // Fall back to pattern matching if value parsing fails
        }
        
        return enabledSources;
    }

    /**
     * Analyze bit fields to find which interrupt sources are enabled
     */
    private List<String> analyzeEnabledBitFields(String bitFields, long configuredValue) {
        List<String> enabledSources = new ArrayList<>();
        
        // Parse individual bit field entries: "FIELDNAME:Description (0xVALUE)"
        java.util.regex.Pattern fieldPattern = java.util.regex.Pattern.compile("(\\w+\\d*):[^(]*\\(0x([0-9A-Fa-f]+)\\)");
        java.util.regex.Matcher matcher = fieldPattern.matcher(bitFields);
        
        while (matcher.find()) {
            String fieldName = matcher.group(1);
            String fieldValueStr = matcher.group(2);
            
            try {
                long fieldValue = Long.parseUnsignedLong(fieldValueStr, 16);
                
                // If this field has a non-zero value, it might be an enabled interrupt source
                if (fieldValue > 0) {
                    String interruptSource = mapFieldToInterruptSource(fieldName, fieldValue);
                    if (interruptSource != null) {
                        enabledSources.add(interruptSource);
                    }
                }
            } catch (NumberFormatException e) {
                // Skip invalid field values
            }
        }
        
        return enabledSources;
    }

    /**
     * Map a bit field name to an interrupt source using generic patterns
     */
    private String mapFieldToInterruptSource(String fieldName, long fieldValue) {
        String upperField = fieldName.toUpperCase();
        
        // Pattern 1: Direct interrupt source names
        if (upperField.matches("(EXTINT|INT|IRQ)\\d+")) {
            return upperField;
        }
        
        // Pattern 2: Sense fields (common in EIC) - SENSE7 -> EXTINT7
        java.util.regex.Pattern sensePattern = java.util.regex.Pattern.compile("SENSE(\\d+)");
        java.util.regex.Matcher senseMatcher = sensePattern.matcher(upperField);
        if (senseMatcher.find()) {
            return "EXTINT" + senseMatcher.group(1);
        }
        
        // Pattern 3: Channel fields - CH3 -> CH3_INT
        java.util.regex.Pattern channelPattern = java.util.regex.Pattern.compile("CH(\\d+)");
        java.util.regex.Matcher channelMatcher = channelPattern.matcher(upperField);
        if (channelMatcher.find()) {
            return "CH" + channelMatcher.group(1) + "_INT";
        }
        
        // Pattern 4: Timer/Counter patterns - OC1, CC2, etc.
        if (upperField.matches("(OC|CC|IC)\\d+")) {
            return upperField + "_INT";
        }
        
        // Pattern 5: Common interrupt source patterns
        if (upperField.matches("(OVF|OVIE|COMPA|COMPB|CAPT|ERROR|READY|DONE|SUSP|RESRDY|ENABLE)")) {
            return upperField;
        }
        
        // Pattern 6: Enable fields with numbers - convert to interrupt source
        java.util.regex.Pattern enablePattern = java.util.regex.Pattern.compile("(\\w+)(\\d+)EN");
        java.util.regex.Matcher enableMatcher = enablePattern.matcher(upperField);
        if (enableMatcher.find()) {
            return enableMatcher.group(1) + enableMatcher.group(2);
        }
        
        return null;
    }

    /**
     * Find interrupt source using generic pattern matching (fallback method)
     */
    private String findInterruptSourceByPattern(String comment) {
        // Look for common interrupt source patterns in the comment
        String[] patterns = {
            "(EXTINT\\d+)",
            "(INT\\d+)",
            "(IRQ\\d+)", 
            "(CH\\d+_INT)",
            "(OVF|COMPA|COMPB|CAPT|ERROR|READY|DONE)",
            "(SENSE\\d+)",
            "(\\w+_INT\\d*)"
        };
        
        for (String patternStr : patterns) {
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(patternStr, java.util.regex.Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher matcher = pattern.matcher(comment);
            if (matcher.find()) {
                String found = matcher.group(1).toUpperCase();
                
                // Convert SENSE patterns to EXTINT
                if (found.startsWith("SENSE")) {
                    java.util.regex.Pattern sensePattern = java.util.regex.Pattern.compile("SENSE(\\d+)");
                    java.util.regex.Matcher senseMatcher = sensePattern.matcher(found);
                    if (senseMatcher.find()) {
                        return "EXTINT" + senseMatcher.group(1);
                    }
                }
                
                return found;
            }
        }
        
        return null;
    }

    /**
     * Select the most specific interrupt source from a list of candidates
     */
    private String selectBestInterruptSource(List<String> sources) {
        if (sources.size() == 1) {
            return sources.get(0);
        }
        
        // Prioritize more specific sources
        for (String source : sources) {
            // Prefer numbered interrupt sources (EXTINT7, CH3_INT, etc.)
            if (source.matches(".+\\d+.*")) {
                return source;
            }
        }
        
        // Return the first source if no numbered ones found
        return sources.get(0);
    }

    /**
     * Parse hexadecimal or decimal string to long value
     */
    private long parseHexOrDecimal(String value) {
        if (value.startsWith("0x") || value.startsWith("0X")) {
            return Long.parseUnsignedLong(value.substring(2), 16);
        } else {
            return Long.parseUnsignedLong(value, 10);
        }
    }

    /**
     * Parse bit field information from SVD comments
     */
    private void parseBitFields(String comment, InterruptInfo info) {
        // Extract bit field information from {...} pattern
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\{([^}]+)\\}");
        java.util.regex.Matcher matcher = pattern.matcher(comment);
        
        if (matcher.find()) {
            String bitFields = matcher.group(1);
            info.bitFieldConfig = bitFields;
            
            // Look for specific interrupt sources in bit fields
            if (bitFields.contains("SENSE") && bitFields.contains("RISE")) {
                info.triggerType = "rising_edge";
            } else if (bitFields.contains("SENSE") && bitFields.contains("FALL")) {
                info.triggerType = "falling_edge";
            } else if (bitFields.contains("SENSE") && bitFields.contains("BOTH")) {
                info.triggerType = "both_edges";
            }
        }
    }

    /**
     * Store peripheral configuration for later correlation with interrupts
     */
    private void storePeripheralConfig(String peripheral, String register, Address address, 
                                     String value, String comment, Map<Integer, InterruptInfo> interruptMap) {
        // For now, create a placeholder entry that might be correlated later
        // This handles cases where we see peripheral config but don't immediately know the IRQ number
        String key = peripheral + "_CONFIG";
        InterruptInfo placeholder = new InterruptInfo(-1, key, "peripheral_config");
        placeholder.peripheralName = peripheral;
        placeholder.registerName = register;
        placeholder.hasPeripheralConfig = true;
        placeholder.peripheralConfigAddress = address.getOffset();
        placeholder.configuredValue = value;
        placeholder.svdDescription = extractDescription(comment);
    }

    /**
     * Validate that an address looks like valid ARM code
     */
    private boolean isValidCodeAddress(Program program, long address) {
        try {
            // Check if address is in a reasonable range for ARM Cortex-M
            if (address < 0x1000 || address > 0x20000000) {
                return false;
            }
            
            // Check if address is in an executable memory block
            Address addr = program.getAddressFactory().getAddress(String.format("0x%08X", address));
            if (addr == null) return false;
            
            MemoryBlock block = program.getMemory().getBlock(addr);
            if (block == null) return false;
            
            return block.isExecute() || block.getName().toLowerCase().contains("flash") || 
                   block.getName().toLowerCase().contains("rom") || block.getName().toLowerCase().contains("code");
            
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Analyze peripheral register configurations for interrupt enables
     */
    private void analyzePeripheralInterruptConfig(Program program, Map<Integer, InterruptInfo> interruptMap) {
        try {
            ReferenceManager refManager = program.getReferenceManager();
            
            // Common peripheral interrupt enable register patterns
            String[] interruptRegisterPatterns = {
                "INTENSET", "INTENCLR", "INTEN", "IER", "IMASK", "IE", "INT_EN"
            };
            
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                // Focus on peripheral memory regions (typically above 0x40000000 for ARM Cortex-M)
                if (block.getStart().getOffset() >= 0x40000000L) {
                    analyzePeripheralBlock(program, block, interruptMap, interruptRegisterPatterns);
                }
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error analyzing peripheral interrupt config: " + e.getMessage());
        }
    }

    /**
     * Analyze a specific peripheral memory block for interrupt configurations
     */
    private void analyzePeripheralBlock(Program program, MemoryBlock block, 
                                      Map<Integer, InterruptInfo> interruptMap, 
                                      String[] patterns) {
        try {
            ReferenceManager refManager = program.getReferenceManager();
            Listing listing = program.getListing();
            
            Address start = block.getStart();
            Address end = block.getEnd();
            
            // Look for writes to addresses in this block
            for (Address addr = start; addr.compareTo(end) <= 0; addr = addr.add(4)) {
                ReferenceIterator refs = refManager.getReferencesTo(addr);
                
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    if (ref.getReferenceType().isWrite()) {
                        // Check if this looks like an interrupt enable register
                        String comment = getAddressComment(listing, addr);
                        if (comment != null && containsInterruptPattern(comment, patterns)) {
                            analyzeInterruptEnableWrite(program, ref, addr, comment, interruptMap);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Skip problematic blocks
        }
    }

    /**
     * Filter interrupts to only include those that are actually configured/used
     */
    private List<InterruptInfo> filterActiveInterrupts(Map<Integer, InterruptInfo> interruptMap) {
        List<InterruptInfo> activeInterrupts = new ArrayList<>();
        
        // Find the most common handler address (likely the default/dummy handler)
        Map<Long, Integer> handlerCounts = new HashMap<>();
        for (InterruptInfo interrupt : interruptMap.values()) {
            if (interrupt.handlerAddress != 0) {
                handlerCounts.merge(interrupt.handlerAddress, 1, Integer::sum);
            }
        }
        
        // Identify the default handler (most common address)
        long defaultHandler = 0;
        int maxCount = 0;
        for (Map.Entry<Long, Integer> entry : handlerCounts.entrySet()) {
            if (entry.getValue() > maxCount) {
                maxCount = entry.getValue();
                defaultHandler = entry.getKey();
            }
        }
        
        // Include interrupts that meet certain criteria
        for (InterruptInfo interrupt : interruptMap.values()) {
            boolean shouldInclude = false;
            
            // Always include system exceptions
            if (interrupt.type.equals("system_exception")) {
                shouldInclude = true;
            }
            
            // Include if it has a unique handler (not the default)
            else if (interrupt.handlerAddress != 0 && interrupt.handlerAddress != defaultHandler) {
                shouldInclude = true;
                interrupt.confidence = "high";
                interrupt.reason = "unique_handler";
            }
            
            // Include if there's evidence of NVIC configuration
            else if (!interrupt.nvicOperations.isEmpty()) {
                shouldInclude = true;
                interrupt.confidence = "medium";
                interrupt.reason = "nvic_config";
            }
            
            // Include if there's peripheral configuration evidence
            else if (interrupt.hasPeripheralConfig) {
                shouldInclude = true;
                interrupt.confidence = "medium";
                interrupt.reason = "peripheral_config";
            }
            
            // Include if mentioned in comments
            else if (interrupt.hasCommentInfo) {
                shouldInclude = true;
                interrupt.confidence = "low";
                interrupt.reason = "comment_mention";
            }
            
            if (shouldInclude) {
                activeInterrupts.add(interrupt);
            }
        }
        
        return activeInterrupts;
    }

    // Helper methods for comment analysis
    private String extractPeripheralName(String comment) {
        // Look for peripheral names like "EIC", "TC0", "SERCOM0", etc.
        String[] lines = comment.split("\n");
        for (String line : lines) {
            if (line.matches(".*\\b[A-Z]{2,}[0-9]*\\b.*")) {
                String[] words = line.split("\\s+");
                for (String word : words) {
                    if (word.matches("[A-Z]{2,}[0-9]*")) {
                        return word;
                    }
                }
            }
        }
        return null;
    }

    private String extractInterruptName(String comment) {
        // Look for interrupt names like "EXTINT11", "COMPARE", etc.
        if (comment.contains("EXTINT")) {
            int idx = comment.indexOf("EXTINT");
            return comment.substring(idx, Math.min(idx + 10, comment.length())).split("\\s")[0];
        }
        
        String[] interruptKeywords = {"COMPARE", "OVERFLOW", "READY", "ERROR", "DONE"};
        for (String keyword : interruptKeywords) {
            if (comment.toUpperCase().contains(keyword)) {
                return keyword;
            }
        }
        
        return null;
    }

    private String extractIRQNumberFromComment(String comment) {
        // Look for patterns like "IRQ11", "Interrupt 11", "External Interrupt 11"
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("(?:IRQ|interrupt)\\s*(\\d+)", 
            java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = pattern.matcher(comment);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private int mapPeripheralToIRQ(String peripheral, String interrupt) {
        // Known IRQ mappings for SAME54 (common ARM Cortex-M4 microcontroller)
        // This should ideally be loaded from SVD data, but for now use hardcoded mappings
        
        if (peripheral == null) return -1;
        
        switch (peripheral.toUpperCase()) {
            case "EIC":
                // External Interrupt Controller - typically IRQ 11 for SAME54
                return 11;
            case "FREQM":
                return 12;
            case "NVMCTRL":
                return 13;
            case "DMAC":
                return 14; // Channel 0
            case "EVSYS":
                return 15; // Channel 0
            case "SERCOM0":
                return 16;
            case "SERCOM1":
                return 17;
            case "SERCOM2":
                return 18;
            case "SERCOM3":
                return 19;
            case "SERCOM4":
                return 20;
            case "SERCOM5":
                return 21;
            case "SERCOM6":
                return 22;
            case "SERCOM7":
                return 23;
            case "CAN0":
                return 24;
            case "CAN1":
                return 25;
            case "USB":
                return 26;
            case "GMAC":
                return 27;
            case "TCC0":
                return 28;
            case "TCC1":
                return 29;
            case "TCC2":
                return 30;
            case "TCC3":
                return 31;
            case "TCC4":
                return 32;
            case "TC0":
                return 33;
            case "TC1":
                return 34;
            case "TC2":
                return 35;
            case "TC3":
                return 36;
            case "TC4":
                return 37;
            case "TC5":
                return 38;
            case "TC6":
                return 39;
            case "TC7":
                return 40;
            case "PDEC":
                return 41;
            case "ADC0":
                return 42;
            case "ADC1":
                return 43;
            case "AC":
                return 44;
            case "DAC":
                return 45;
            case "I2S":
                return 46;
            case "PCC":
                return 47;
            default:
                return -1; // Unknown peripheral
        }
    }

    /**
     * Extract the written value from SVD comment (pattern: <== VALUE)
     */
    private String extractWrittenValueFromComment(String comment) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("<==\\s*(0x[0-9A-Fa-f]+|\\d+)");
        java.util.regex.Matcher matcher = pattern.matcher(comment);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Extract description from the second part of SVD comment
     */
    private String extractDescription(String descriptionPart) {
        // Extract description before bit fields or other details
        int idx = descriptionPart.indexOf("[");
        if (idx > 0) {
            return descriptionPart.substring(0, idx).trim();
        }
        
        idx = descriptionPart.indexOf("{");
        if (idx > 0) {
            return descriptionPart.substring(0, idx).trim();
        }
        
        return descriptionPart.trim();
    }

    private String getAddressComment(Listing listing, Address addr) {
        // Get the most relevant comment for this address
        String comment = listing.getComment(CodeUnit.PLATE_COMMENT, addr);
        if (comment != null) return comment;
        
        comment = listing.getComment(CodeUnit.PRE_COMMENT, addr);
        if (comment != null) return comment;
        
        comment = listing.getComment(CodeUnit.EOL_COMMENT, addr);
        if (comment != null) return comment;
        
        return listing.getComment(CodeUnit.POST_COMMENT, addr);
    }

    private boolean containsInterruptPattern(String comment, String[] patterns) {
        String upperComment = comment.toUpperCase();
        for (String pattern : patterns) {
            if (upperComment.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private void analyzeInterruptEnableWrite(Program program, Reference ref, Address addr, 
                                           String comment, Map<Integer, InterruptInfo> interruptMap) {
        try {
            // Extract interrupt information from the write operation
            String peripheralName = extractPeripheralName(comment);
            if (peripheralName != null) {
                // This is a simplified analysis - would be more sophisticated with full SVD integration
                Address fromAddr = ref.getFromAddress();
                Instruction instr = program.getListing().getInstructionAt(fromAddr);
                
                if (instr != null) {
                    Long value = extractImmediateValue(instr);
                    if (value != null && value != 0) {
                        // Create a placeholder interrupt entry
                        int estimatedIRQ = (int) ((addr.getOffset() - 0x40000000L) / 0x1000) % 100; // Rough estimate
                        InterruptInfo info = interruptMap.computeIfAbsent(estimatedIRQ, 
                            k -> new InterruptInfo(k, peripheralName + "_INT", "external_irq"));
                        info.hasPeripheralConfig = true;
                        info.peripheralConfigAddress = fromAddr.getOffset();
                        info.peripheralName = peripheralName;
                    }
                }
            }
        } catch (Exception e) {
            // Skip problematic instructions
        }
    }

    /**
     * Data class to hold interrupt information
     */
    private static class InterruptInfo {
        int irqNumber;
        String name;
        String type;
        long handlerAddress;
        String handlerFunctionName;
        boolean isHandlerFunction;
        boolean enabled;
        int vectorTableOffset;
        List<NVICOperation> nvicOperations;
        
        // Enhanced analysis fields
        boolean hasPeripheralConfig;
        long peripheralConfigAddress;
        String peripheralName;
        String interruptSource;
        boolean hasCommentInfo;
        long commentInfoAddress;
        String confidence;
        String reason;
        
        // SVD-specific fields
        String registerName;
        String svdDescription;
        String configuredValue;
        String bitFieldConfig;
        String triggerType;

        InterruptInfo(int irqNumber, String name, String type) {
            this.irqNumber = irqNumber;
            this.name = name;
            this.type = type;
            this.handlerAddress = 0;
            this.handlerFunctionName = null;
            this.isHandlerFunction = false;
            this.enabled = false;
            this.vectorTableOffset = -1;
            this.nvicOperations = new ArrayList<>();
            this.hasPeripheralConfig = false;
            this.peripheralConfigAddress = 0;
            this.peripheralName = null;
            this.interruptSource = null;
            this.hasCommentInfo = false;
            this.commentInfoAddress = 0;
            this.confidence = "unknown";
            this.reason = "vector_table";
            
            // SVD fields
            this.registerName = null;
            this.svdDescription = null;
            this.configuredValue = null;
            this.bitFieldConfig = null;
            this.triggerType = null;
        }
    }

    /**
     * Data class to hold NVIC operation information
     */
    private static class NVICOperation {
        String operation;
        long address;
        long value;

        NVICOperation(String operation, long address, long value) {
            this.operation = operation;
            this.address = address;
            this.value = value;
        }
    }

    /**
     * Data class to hold comprehensive SVD comment information for list_comments endpoint
     */
    private static class CommentInfo {
        String peripheral;
        String cluster;
        String register;
        String peripheralDesc;
        String clusterDesc;
        String registerDesc;
        String size;
        String operation;
        List<Map<String, String>> fields;
        List<Map<String, String>> interrupts;
        String modeContext;
        String fullComment;
        Address address;

        CommentInfo(String peripheral, String cluster, String register, String peripheralDesc,
                   String clusterDesc, String registerDesc, String size, String operation,
                   List<Map<String, String>> fields, List<Map<String, String>> interrupts,
                   String modeContext, String fullComment, Address address) {
            this.peripheral = peripheral;
            this.cluster = cluster;
            this.register = register;
            this.peripheralDesc = peripheralDesc;
            this.clusterDesc = clusterDesc;
            this.registerDesc = registerDesc;
            this.size = size;
            this.operation = operation;
            this.fields = fields;
            this.interrupts = interrupts;
            this.modeContext = modeContext;
            this.fullComment = fullComment;
            this.address = address;
        }
    }

    /**
     * Data class to hold parsed SVD comment information
     */
    private static class SVDComment {
        String peripheralName;
        String registerName;
        String description;
        String configuredValue;
        String fullComment;
        Address address;

        SVDComment(String peripheralName, String registerName, String description, 
                  String configuredValue, String fullComment, Address address) {
            this.peripheralName = peripheralName;
            this.registerName = registerName;
            this.description = description;
            this.configuredValue = configuredValue;
            this.fullComment = fullComment;
            this.address = address;
        }
    }

    /**
     * Write all collected SVD comments to a debug file for analysis
     */
    private void writeSVDCommentsToFile(Map<String, List<SVDComment>> peripheralComments) {
        try {
            java.io.FileWriter writer = new java.io.FileWriter("svd_comments_debug.txt");
            writer.write("=== SVD Comments Debug Output ===\n");
            writer.write("Total Peripherals: " + peripheralComments.size() + "\n\n");
            
            for (Map.Entry<String, List<SVDComment>> entry : peripheralComments.entrySet()) {
                String peripheralName = entry.getKey();
                List<SVDComment> comments = entry.getValue();
                
                writer.write("PERIPHERAL: " + peripheralName + " (" + comments.size() + " comments)\n");
                writer.write("=" + "=".repeat(peripheralName.length() + 20) + "\n");
                
                for (int i = 0; i < comments.size(); i++) {
                    SVDComment comment = comments.get(i);
                    writer.write(String.format("[%d] %s.%s @ 0x%08X\n", 
                        i + 1, comment.peripheralName, comment.registerName, 
                        comment.address.getOffset()));
                    writer.write("    Description: " + comment.description + "\n");
                    if (comment.configuredValue != null) {
                        writer.write("    Value: " + comment.configuredValue + "\n");
                    }
                    writer.write("    Full Comment: " + comment.fullComment + "\n");
                    writer.write("    Priority: " + getInterruptConfigPriority(comment) + "\n");
                    writer.write("\n");
                }
                writer.write("\n");
            }
            
            writer.close();
            Msg.info(this, "SVD comments written to svd_comments_debug.txt");
            
        } catch (Exception e) {
            Msg.error(this, "Error writing SVD comments to file: " + e.getMessage());
        }
    }

    /**
     * Collect all SVD comments in the program and parse them according to the new format
     */
    private List<CommentInfo> collectAllSVDComments(Program program, String filter, String peripheral) {
        List<CommentInfo> comments = new ArrayList<>();
        Listing listing = program.getListing();
        
        // Iterate through all memory blocks
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Address start = block.getStart();
            Address end = block.getEnd();
            
            // Iterate through addresses in the block
            for (Address address = start; address.compareTo(end) <= 0; address = address.add(1)) {
                // Check all comment types at each address
                for (int commentType : new int[]{CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT, 
                                                CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT}) {
                    String comment = listing.getComment(commentType, address);
                    if (comment != null && comment.startsWith("SVD:")) {
                        // Apply text filter if specified
                        if (filter == null || comment.toLowerCase().contains(filter.toLowerCase())) {
                            CommentInfo commentInfo = parseNewSVDCommentFormat(comment, address);
                            if (commentInfo != null) {
                                // Apply peripheral filter if specified
                                if (peripheral == null || peripheral.equalsIgnoreCase(commentInfo.peripheral)) {
                                    comments.add(commentInfo);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return comments;
    }

    /**
     * Parse the new pipe-delimited SVD comment format
     * Format: SVD: PERIPHERAL[CLUSTER].REGISTER|PERIPHERAL_DESC|CLUSTER_DESC|REGISTER_DESC|SIZE|OPERATION|FIELDS|INTERRUPTS|MODE_CONTEXT
     */
    private CommentInfo parseNewSVDCommentFormat(String comment, Address address) {
        try {
            if (!comment.startsWith("SVD: ")) {
                return null;
            }
            
            // Remove "SVD: " prefix
            String content = comment.substring(5);
            
            // Split by pipe delimiters
            String[] parts = content.split("\\|", -1); // -1 to include empty strings
            if (parts.length < 9) {
                return null; // Not enough parts for new format
            }
            
            // Parse peripheral and register
            String peripheralRegister = parts[0];
            String peripheral = "";
            String cluster = "";
            String register = "";
            
            // Extract peripheral[cluster].register
            if (peripheralRegister.contains(".")) {
                String[] regParts = peripheralRegister.split("\\.", 2);
                String peripheralPart = regParts[0];
                register = regParts[1];
                
                // Check for cluster in brackets
                if (peripheralPart.contains("[") && peripheralPart.contains("]")) {
                    int startBracket = peripheralPart.indexOf('[');
                    int endBracket = peripheralPart.indexOf(']');
                    peripheral = peripheralPart.substring(0, startBracket);
                    cluster = peripheralPart.substring(startBracket + 1, endBracket);
                } else {
                    peripheral = peripheralPart;
                    cluster = "N/A";
                }
            }
            
            String peripheralDesc = parts[1];
            String clusterDesc = parts[2];
            String registerDesc = parts[3];
            String size = parts[4];
            String operation = parts[5];
            String fieldsStr = parts[6];
            String interruptsStr = parts[7];
            String modeContext = parts[8];
            
            // Parse fields (separated by ^)
            List<Map<String, String>> fields = parseFields(fieldsStr);
            
            // Parse interrupts (separated by ^)  
            List<Map<String, String>> interrupts = parseInterrupts(interruptsStr);
            
            return new CommentInfo(peripheral, cluster, register, peripheralDesc, clusterDesc,
                                 registerDesc, size, operation, fields, interrupts, modeContext, 
                                 comment, address);
                                 
        } catch (Exception e) {
            // Return null for malformed comments
            return null;
        }
    }

    /**
     * Parse field information from the FIELDS section
     * Format: FIELD_NAME:OFFSET:WIDTH(VALUE):FIELD_DESCRIPTION:ENUMERATED_VALUE_DESCRIPTION
     */
    private List<Map<String, String>> parseFields(String fieldsStr) {
        List<Map<String, String>> fields = new ArrayList<>();
        if (fieldsStr == null || fieldsStr.isEmpty() || "N/A".equals(fieldsStr)) {
            return fields;
        }
        
        String[] fieldParts = fieldsStr.split("\\^");
        for (String fieldStr : fieldParts) {
            Map<String, String> field = parseField(fieldStr);
            if (field != null) {
                fields.add(field);
            }
        }
        
        return fields;
    }

    /**
     * Parse a single field
     */
    private Map<String, String> parseField(String fieldStr) {
        try {
            // FIELD_NAME:OFFSET:WIDTH(VALUE):FIELD_DESCRIPTION:ENUMERATED_VALUE_DESCRIPTION
            String[] parts = fieldStr.split(":", 5);
            if (parts.length < 4) {
                return null;
            }
            
            Map<String, String> field = new HashMap<>();
            field.put("name", parts[0]);
            field.put("offset", parts[1]);
            
            // Extract width and value
            String widthValue = parts[2];
            if (widthValue.contains("(") && widthValue.contains(")")) {
                int parenStart = widthValue.indexOf('(');
                int parenEnd = widthValue.indexOf(')');
                field.put("width", widthValue.substring(0, parenStart));
                field.put("value", widthValue.substring(parenStart + 1, parenEnd));
            }
            
            field.put("description", parts[3]);
            if (parts.length > 4) {
                field.put("enumerated_description", parts[4]);
            }
            
            return field;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parse interrupt information from the INTERRUPTS section
     * Format: ACTION:INTERRUPT_NAME:VECTOR_NUMBER
     */
    private List<Map<String, String>> parseInterrupts(String interruptsStr) {
        List<Map<String, String>> interrupts = new ArrayList<>();
        if (interruptsStr == null || interruptsStr.isEmpty() || "N/A".equals(interruptsStr)) {
            return interrupts;
        }
        
        String[] interruptParts = interruptsStr.split("\\^");
        for (String interruptStr : interruptParts) {
            String[] parts = interruptStr.split(":", 3);
            if (parts.length >= 3) {
                Map<String, String> interrupt = new HashMap<>();
                interrupt.put("action", parts[0]);
                interrupt.put("name", parts[1]);
                interrupt.put("vector", parts[2]);
                interrupts.add(interrupt);
            }
        }
        
        return interrupts;
    }

    /**
     * Format comments as JSON string manually (simple approach)
     */
    private String formatCommentsAsJson(List<Map<String, Object>> items, int offset, int limit) {
        int start = Math.min(offset, items.size());
        int end = Math.min(offset + limit, items.size());
        List<Map<String, Object>> paginatedItems = items.subList(start, end);
        
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"results\":[");
        
        for (int i = 0; i < paginatedItems.size(); i++) {
            if (i > 0) json.append(",");
            Map<String, Object> item = paginatedItems.get(i);
            json.append("{");
            
            boolean first = true;
            for (Map.Entry<String, Object> entry : item.entrySet()) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(entry.getKey()).append("\":");
                Object value = entry.getValue();
                if (value instanceof String) {
                    json.append("\"").append(escapeJsonString((String) value)).append("\"");
                } else if (value instanceof List) {
                    json.append(formatListAsJson((List<?>) value));
                } else {
                    json.append("\"").append(String.valueOf(value)).append("\"");
                }
            }
            
            json.append("}");
        }
        
        json.append("],");
        json.append("\"offset\":").append(offset).append(",");
        json.append("\"limit\":").append(limit).append(",");
        json.append("\"total\":").append(items.size()).append(",");
        json.append("\"has_more\":").append(end < items.size());
        json.append("}");
        
        return json.toString();
    }
    
    /**
     * Escape special characters in JSON strings
     */
    private String escapeJsonString(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
    
    /**
     * Format a list as JSON array
     */
    private String formatListAsJson(List<?> list) {
        StringBuilder json = new StringBuilder();
        json.append("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) json.append(",");
            Object item = list.get(i);
            if (item instanceof Map) {
                json.append(formatMapAsJson((Map<?, ?>) item));
            } else {
                json.append("\"").append(escapeJsonString(String.valueOf(item))).append("\"");
            }
        }
        json.append("]");
        return json.toString();
    }
    
    /**
     * Format a map as JSON object
     */
    private String formatMapAsJson(Map<?, ?> map) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) json.append(",");
            first = false;
            json.append("\"").append(String.valueOf(entry.getKey())).append("\":");
            json.append("\"").append(escapeJsonString(String.valueOf(entry.getValue()))).append("\"");
        }
        json.append("}");
        return json.toString();
    }

    /**
     * Parse SVD comment structure into SVDComment object
     * Expected format: "SVD: PERIPHERAL.REGISTER - Description <== VALUE"
     */
    private SVDComment parseSVDCommentStructure(String comment, Address address) {
        try {
            if (!comment.startsWith("SVD:")) {
                return null;
            }
            
            // Remove "SVD:" prefix
            String content = comment.substring(4).trim();
            
            // Split by " - " to separate register info from description
            String[] parts = content.split(" - ", 2);
            if (parts.length < 2) {
                return null;
            }
            
            // Parse peripheral.register part
            String regPart = parts[0].trim();
            String[] regComponents = regPart.split("\\.", 2);
            if (regComponents.length < 2) {
                return null;
            }
            
            String peripheralName = regComponents[0].trim();
            String registerName = regComponents[1].trim();
            
            // Parse description and extract configured value
            String descriptionPart = parts[1].trim();
            String description = descriptionPart;
            String configuredValue = null;
            
            // Look for "<== VALUE" pattern to extract configured value
            int valueIndex = descriptionPart.indexOf(" <== ");
            if (valueIndex != -1) {
                description = descriptionPart.substring(0, valueIndex).trim();
                configuredValue = descriptionPart.substring(valueIndex + 5).trim();
            }
            
            return new SVDComment(peripheralName, registerName, description, 
                                configuredValue, comment, address);
                                
        } catch (Exception e) {
            // Return null for malformed comments
            return null;
        }
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
