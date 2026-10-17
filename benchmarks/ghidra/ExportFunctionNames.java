// Headless postScript (benchmark only; the product never runs a JVM,
// docs/adr/0001-process-topology-no-jvm.md).
//
// Writes one JSON file (first script argument): every non-external function's
// entry, its name, and its fully qualified name after auto-analysis, so the
// demangling stock performs can be counted against ours
// (benchmarks/mwcc_names_gate.py). APIs: GhidraScript, FunctionManager,
// Function.getName/getName(boolean) (Ghidra 12.1.3).
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportFunctionNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        JsonArray functions = new JsonArray();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) continue;
            JsonObject row = new JsonObject();
            row.addProperty("entry", function.getEntryPoint().getOffset());
            row.addProperty("name", function.getName());
            row.addProperty("qualified", function.getName(true));
            functions.add(row);
        }
        JsonObject out = new JsonObject();
        out.addProperty("program", currentProgram.getName());
        out.add("functions", functions);
        Files.writeString(Path.of(getScriptArgs()[0]), out.toString());
    }
}
