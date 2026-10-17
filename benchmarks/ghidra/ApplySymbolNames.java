// Headless preScript (benchmark only): names the image's functions from a
// dtk `symbols.txt` (`name = .section:0xADDR; // type:function ...`) before
// auto-analysis runs, so stock sees the same names we import with `--map`
// and its demanglers get the chance to rename them. First script argument:
// the symbols file. Creates the function when none exists at the address.
// APIs: GhidraScript.createFunction, Function.setName, SourceType.IMPORTED.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApplySymbolNames extends GhidraScript {
    private static final Pattern ROW =
        Pattern.compile("^(\\S+)\\s*=\\s*\\S*?:?0x([0-9A-Fa-f]+);.*type:function");

    @Override
    public void run() throws Exception {
        int applied = 0;
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            Matcher m = ROW.matcher(line);
            if (!m.find()) continue;
            Address address = toAddr(Long.parseUnsignedLong(m.group(2), 16));
            if (address == null || !currentProgram.getMemory().contains(address)) continue;
            Function function = getFunctionAt(address);
            if (function == null) function = createFunction(address, null);
            if (function == null) continue;
            function.setName(m.group(1), SourceType.IMPORTED);
            applied++;
        }
        println("ApplySymbolNames: " + applied + " names applied");
    }
}
