// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 APIs: DecompInterface.openProgram/decompileFunction,
// DecompileResults.getDecompiledFunction/getHighFunction,
// HighFunction.getGlobalSymbolMap, GlobalSymbolMap.getSymbols, HighSymbol.getDataType.
//
// ExportDecompiledSignatures.java plus the global declarations the decompiled text
// refers to: for every address in the file named by the first script argument
// (one hex address per line) the function is created when stock analysis did not
// find one, decompiled, and recorded with its C text, its signature and one
// `extern <type> <name>;` line per global symbol its high function names, typed as
// stock Ghidra types it (the global symbol map plus the global symbols of the printed variable tokens). Only primitive and pointer/array-of-primitive types are
// spelled; anything else is declared `undefined4`. Nothing is saved to the program.
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighSymbol;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.List;

public class ExportDecompiledC extends GhidraScript {
    private static String declare(DataType type, String name) {
        if (type instanceof Array) {
            Array array = (Array) type;
            return declare(array.getDataType(), name + "[" + array.getNumElements() + "]");
        }
        String spelled = type.getDisplayName();
        if (type instanceof Pointer || spelled.matches("[A-Za-z_0-9 ]+( \\*+)?")) {
            if (spelled.matches("[A-Za-z_0-9 ]+( \\*+)?")) {
                return spelled + " " + name;
            }
        }
        return "undefined4 " + name;
    }

    private void collect(ClangNode node, Set<String> seen, JsonArray out) {
        if (node instanceof ClangVariableToken) {
            ClangVariableToken token = (ClangVariableToken) node;
            HighVariable variable = token.getHighVariable();
            HighSymbol symbol = variable == null ? null : variable.getSymbol();
            if (variable instanceof HighGlobal && variable.getDataType() != null && token.getText() != null
                    && seen.add(token.getText())) {
                out.add("extern " + declare(variable.getDataType(), token.getText()) + ";");
            } else if (symbol != null && symbol.isGlobal() && symbol.getDataType() != null && symbol.getName() != null
                    && seen.add(symbol.getName())) {
                out.add("extern " + declare(symbol.getDataType(), symbol.getName()) + ";");
            }
        }
        for (int index = 0; index < node.numChildren(); index++) {
            collect(node.Child(index), seen, out);
        }
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        List<String> lines = Files.readAllLines(Path.of(arguments[0]));
        int timeout = arguments.length > 2 ? Integer.parseInt(arguments[2]) : 60;
        JsonObject functions = new JsonObject();
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(decompiler.getLastMessage());
            }
            for (String line : lines) {
                monitor.checkCancelled();
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                Address address = toAddr(Long.parseUnsignedLong(line, 16));
                JsonObject row = new JsonObject();
                Function function = getFunctionAt(address);
                row.addProperty("existed", function != null);
                row.addProperty("address", address.toString());
                if (function == null) {
                    function = createFunction(address, null);
                }
                if (function == null) {
                    row.addProperty("error", "no function could be created");
                    functions.add(line, row);
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    row.addProperty("error", String.valueOf(result.getErrorMessage()));
                    functions.add(line, row);
                    continue;
                }
                DecompiledFunction decompiled = result.getDecompiledFunction();
                row.addProperty("signature", decompiled.getSignature());
                row.addProperty("c", decompiled.getC());
                JsonArray declarations = new JsonArray();
                Set<String> seen = new HashSet<>();
                if (result.getCCodeMarkup() != null) {
                    collect(result.getCCodeMarkup(), seen, declarations);
                }
                HighFunction high = result.getHighFunction();
                if (high != null) {
                    GlobalSymbolMap globals = high.getGlobalSymbolMap();
                    Iterator<HighSymbol> symbols = globals.getSymbols();
                    while (symbols.hasNext()) {
                        HighSymbol symbol = symbols.next();
                        if (symbol.getDataType() == null || symbol.getName() == null) {
                            continue;
                        }
                        if (seen.add(symbol.getName())) {
                            declarations.add("extern " + declare(symbol.getDataType(), symbol.getName()) + ";");
                        }
                    }
                }
                row.add("declarations", declarations);
                functions.add(line, row);
            }
        } finally {
            decompiler.dispose();
        }
        JsonObject result = new JsonObject();
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.add("functions", functions);
        Files.writeString(Path.of(arguments[1]), result.toString());
    }
}
