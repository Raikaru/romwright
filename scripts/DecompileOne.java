// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 APIs verified in the extracted sources (Apache-2.0):
// FlatProgramAPI.getGlobalFunctions, DecompInterface.openProgram and
// decompileFunction, DecompileResults.getDecompiledFunction, DecompiledFunction.getC.
// Decompiles exactly one function, named by the first script argument, and
// prints one machine-readable line. Nothing is written to the program, so the
// timed run neither analyses nor saves.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.util.List;

public class DecompileOne extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        String wanted = arguments.length > 0 ? arguments[0] : "main";
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(decompiler.getLastMessage());
            }
            List<Function> matches = getGlobalFunctions(wanted);
            if (matches.isEmpty()) {
                throw new IllegalStateException("no global function named " + wanted);
            }
            Function function = matches.get(0);
            DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
            if (!result.decompileCompleted()) {
                throw new IllegalStateException(function.getEntryPoint() + ": " + result.getErrorMessage());
            }
            DecompiledFunction decompiled = result.getDecompiledFunction();
            if (decompiled == null || decompiled.getC() == null || decompiled.getC().isEmpty()) {
                throw new IllegalStateException(function.getEntryPoint() + ": no C produced");
            }
            println("DECOMPILED " + wanted + " " + function.getEntryPoint() + " chars "
                    + decompiled.getC().length());
        } finally {
            decompiler.dispose();
        }
    }
}
