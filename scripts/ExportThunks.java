// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 Function.isThunk, Function.getThunkedFunction(boolean),
// Function.isExternal and GhidraScript contracts verified in extracted
// Apache-2.0 sources. Non-recursive thunk targets keep one hop per fact.
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportThunks extends GhidraScript {
    @Override
    public void run() throws Exception {
        JsonObject thunks = new JsonObject();
        int functions = 0;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) {
                continue; // Synthetic external block entries are not image code.
            }
            ++functions;
            if (!function.isThunk()) {
                continue;
            }
            Function thunked = function.getThunkedFunction(false);
            JsonObject fact = new JsonObject();
            fact.addProperty("thunked", thunked == null ? null : thunked.getEntryPoint().toString());
            fact.addProperty("external", thunked != null && thunked.isExternal());
            fact.addProperty("name", function.getName(false));
            thunks.add(function.getEntryPoint().toString(), fact);
        }
        JsonObject result = new JsonObject();
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.addProperty("functions", functions);
        result.add("thunks", thunks);
        Files.writeString(Path.of(getScriptArgs()[0]), result.toString());
    }
}
