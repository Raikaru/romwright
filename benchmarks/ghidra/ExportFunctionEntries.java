// Headless postScript for benchmarks/import_speed.py (benchmark only; the
// product never runs a JVM, docs/adr/0001-process-topology-no-jvm.md).
//
// Writes one JSON file (first script argument) describing what stock
// auto-analysis produced: the program's language, compiler spec, loader and
// image base, its memory blocks, and every non-external function with the
// size of the body range that contains its entry (the contiguous extent an
// ELF symbol size describes). APIs: GhidraScript, FunctionManager,
// AddressSetView.getRangeContaining, Memory.getBlocks (Ghidra 12.1.3).
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportFunctionEntries extends GhidraScript {
    @Override
    public void run() throws Exception {
        JsonObject out = new JsonObject();
        out.addProperty("program", currentProgram.getName());
        out.addProperty("language", currentProgram.getLanguageID().getIdAsString());
        out.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        out.addProperty("format", currentProgram.getExecutableFormat());
        out.addProperty("image_base", currentProgram.getImageBase().toString());
        JsonArray blocks = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject row = new JsonObject();
            row.addProperty("name", block.getName());
            row.addProperty("start", block.getStart().getOffset());
            row.addProperty("size", block.getSize());
            row.addProperty("space", block.getStart().getAddressSpace().getName());
            row.addProperty("execute", block.isExecute());
            row.addProperty("initialized", block.isInitialized());
            row.addProperty("overlay", block.getStart().getAddressSpace().isOverlaySpace());
            blocks.add(row);
        }
        out.add("blocks", blocks);
        JsonArray functions = new JsonArray();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) continue;
            Address entry = function.getEntryPoint();
            if (!entry.isMemoryAddress()) continue;
            AddressRange range = function.getBody().getRangeContaining(entry);
            JsonObject row = new JsonObject();
            row.addProperty("entry", entry.getOffset());
            row.addProperty("space", entry.getAddressSpace().getName());
            row.addProperty("size", range == null ? 0 : range.getLength());
            row.addProperty("overlay", entry.getAddressSpace().isOverlaySpace());
            row.addProperty("thunk", function.isThunk());
            functions.add(row);
        }
        out.add("functions", functions);
        Files.writeString(Path.of(getScriptArgs()[0]), out.toString());
    }
}
