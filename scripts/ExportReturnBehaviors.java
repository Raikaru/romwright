// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 Program, FunctionManager, Function.hasNoReturn and GhidraScript
// contracts verified in extracted Apache-2.0 sources.
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.AddressRange;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportReturnBehaviors extends GhidraScript {
    @Override
    public void run() throws Exception {
        JsonObject functions = new JsonObject();
        JsonObject bodies = new JsonObject();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            functions.addProperty(function.getEntryPoint().toString(), function.hasNoReturn());
            JsonArray ranges = new JsonArray();
            for (AddressRange range : function.getBody().getAddressRanges()) {
                if (!range.getMinAddress().getAddressSpace().equals(
                        function.getEntryPoint().getAddressSpace())) {
                    throw new IllegalStateException("Function body crosses address spaces");
                }
                JsonArray bounds = new JsonArray();
                bounds.add(range.getMinAddress().toString());
                bounds.add(range.getMaxAddress().toString());
                ranges.add(bounds);
            }
            bodies.add(function.getEntryPoint().toString(), ranges);
        }
        JsonObject result = new JsonObject();
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.add("functions", functions);
        result.add("bodies", bodies);
        Files.writeString(Path.of(getScriptArgs()[0]), result.toString());
    }
}
