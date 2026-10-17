// Headless postScript for benchmarks/locals_stock.py (benchmark only; the
// product never runs a JVM, docs/adr/0001-process-topology-no-jvm.md).
//
// Decompiles the functions listed in a file with stock Ghidra's decompiler
// (default simplification) and writes their C, as the decompiler prints it,
// to one JSON file. Script arguments: OUT.json ADDRESSES.txt (one hex entry
// address per line, offsets in the default address space). A listed address
// that stock analysis did not make a function is reported as missing, not
// created: the comparison is of what stock does with the image it analysed.
// With a third argument `create` it is instead disassembled and made a
// function in the default decode state (the row says `created`), the way
// benchmarks/hexrays_research.py asks Hex-Rays to decompile the same address;
// `existed` is true for every function the analysis made itself.
// APIs: GhidraScript, DecompInterface (Ghidra 12.1.3).
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;

public class ExportDecompiledC extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        JsonObject out = new JsonObject();
        out.addProperty("program", currentProgram.getName());
        out.addProperty("language", currentProgram.getLanguageID().getIdAsString());
        JsonObject functions = new JsonObject();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            line = line.trim();
            if (line.isEmpty()) continue;
            JsonObject row = new JsonObject();
            Address address = toAddr(Long.parseUnsignedLong(line, 16));
            Function function = getFunctionAt(address);
            row.addProperty("existed", function != null);
            if (function == null && args.length > 2 && args[2].equals("create")) {
                disassemble(address);
                function = createFunction(address, null);
                if (function != null) row.addProperty("created", true);
            }
            if (function == null) {
                row.addProperty("error", "no function at address");
            } else {
                DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    row.addProperty("c", result.getDecompiledFunction().getC());
                    row.addProperty("name", function.getName());
                } else {
                    row.addProperty("error", String.valueOf(result.getErrorMessage()));
                }
            }
            functions.add(line.toLowerCase(), row);
        }
        decompiler.dispose();
        out.add("functions", functions);
        Files.writeString(Path.of(args[0]), out.toString());
    }
}
