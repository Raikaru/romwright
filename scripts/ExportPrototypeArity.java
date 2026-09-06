// Oracle-only postScript. Input must be the stripped corpus binary.
// Ghidra 12.1.3 APIs verified in DecompilerFunctionAnalyzer,
// DecompilerParameterIdCmd, Function, FunctionManager, Program,
// CompilerSpec, and GhidraScript (Apache-2.0).
import com.google.gson.JsonObject;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportPrototypeArity extends GhidraScript {
    @Override
    public void run() throws Exception {
        // The stock analyzer is disabled by default for ELF. Run its command
        // explicitly with exactly its default clear/commit/timeout settings.
        DecompilerParameterIdCmd command = new DecompilerParameterIdCmd(
            "Decompiler Parameter ID", currentProgram.getMemory(),
            SourceType.ANALYSIS, true, false, 60);
        if (!command.applyTo(currentProgram, monitor)) {
            throw new IllegalStateException("Stock parameter ID failed");
        }
        monitor.checkCancelled();
        JsonObject arities = new JsonObject();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            arities.addProperty(function.getEntryPoint().toString(), function.getParameterCount());
        }
        JsonObject result = new JsonObject();
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.add("arities", arities);
        Files.writeString(Path.of(getScriptArgs()[0]), result.toString());
    }
}
