// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 APIs verified in the extracted sources (Apache-2.0):
// FlatProgramAPI.toAddr/createFunction/getFunctionAt, DecompInterface.openProgram
// and decompileFunction, DecompileResults.getDecompiledFunction,
// DecompiledFunction.getSignature/getC.
//
// For every address in the file named by the first script argument (one hex
// address per line, or `<memory block>+<hex offset>` for an address relative to
// a loaded module's block, since a REL's placement differs per loader), makes sure a function starts there (creating one at the
// address when the stock analysis did not) and records what the stock
// decompiler prints: its C signature, whether the function existed before the
// script, and the decompiled text. Nothing is saved to the program.
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.math.BigInteger;
import java.util.List;

public class ExportDecompiledSignatures extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        List<String> lines = Files.readAllLines(Path.of(arguments[0]));
        int timeout = arguments.length > 2 ? Integer.parseInt(arguments[2]) : 60;
        // `thumb` as the fourth argument: a function the stock analysis did not
        // find is created in Thumb state (a GBA ROM's C functions are Thumb),
        // unless the stock analysis already disassembled an instruction there:
        // that instruction's mode stands (ContextChangeException), and the row
        // records `context_kept`.
        boolean thumb = arguments.length > 3 && arguments[3].equals("thumb");
        Register tmode = currentProgram.getLanguage().getRegister("TMode");
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
                Address address;
                int plus = line.indexOf('+');
                if (plus > 0) {
                    MemoryBlock block = currentProgram.getMemory().getBlock(line.substring(0, plus));
                    if (block == null) {
                        throw new IllegalStateException("no memory block " + line.substring(0, plus));
                    }
                    address = block.getStart().add(Long.parseUnsignedLong(line.substring(plus + 1), 16));
                } else {
                    address = toAddr(Long.parseUnsignedLong(line, 16));
                }
                JsonObject row = new JsonObject();
                Function function = getFunctionAt(address);
                row.addProperty("existed", function != null);
                row.addProperty("address", address.toString());
                if (function == null) {
                    if (thumb && tmode != null) {
                        try {
                            currentProgram.getProgramContext().setValue(tmode, address, address, BigInteger.ONE);
                        } catch (ContextChangeException conflict) {
                            row.addProperty("context_kept", true);
                        }
                    }
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
