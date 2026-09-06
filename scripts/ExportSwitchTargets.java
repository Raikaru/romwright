// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 APIs verified in extracted DecompInterface, DecompileResults,
// HighFunction and JumpTable sources (Apache-2.0).
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.JumpTable;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportSwitchTargets extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        JsonObject functions = new JsonObject();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(decompiler.getLastMessage());
            }
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted() || result.getHighFunction() == null) {
                    throw new IllegalStateException(function.getEntryPoint() + ": " + result.getErrorMessage());
                }
                JsonArray tables = new JsonArray();
                for (JumpTable table : result.getHighFunction().getJumpTables()) {
                    JsonObject recovered = new JsonObject();
                    recovered.addProperty("branch", table.getSwitchAddress().toString());
                    JsonArray targets = new JsonArray();
                    for (Address target : table.getCases()) {
                        targets.add(target.toString());
                    }
                    recovered.add("targets", targets);
                    tables.add(recovered);
                }
                functions.add(function.getEntryPoint().toString(), tables);
            }
        } finally {
            decompiler.dispose();
        }
        JsonObject result = new JsonObject();
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.add("functions", functions);
        Files.writeString(Path.of(getScriptArgs()[0]), result.toString());
    }
}
