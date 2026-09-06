// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 Program, FunctionManager, Function.hasNoReturn and GhidraScript
// contracts verified in extracted Apache-2.0 sources.
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportReturnBehaviors extends GhidraScript {
    @Override
    public void run() throws Exception {
        JsonObject functions = new JsonObject();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            functions.addProperty(function.getEntryPoint().toString(), function.hasNoReturn());
        }
        JsonObject result = new JsonObject();
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.add("functions", functions);
        Files.writeString(Path.of(getScriptArgs()[0]), result.toString());
    }
}
