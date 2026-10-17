// Headless postScript for benchmarks/gc_rel_gate.py (benchmark only; the
// product never runs a JVM, docs/adr/0001-process-topology-no-jvm.md).
//
// Counts the references stock auto-analysis holds between modules of one
// program. A module is the set of memory blocks sharing a name prefix before
// the first `_` (GameCubeLoader names a REL's blocks `<file>_.text0`,
// `<file>_.data0`, `<file>_.uninitialized0`; every other block is the DOL).
// Writes one JSON file (first script argument): per ordered module pair, the
// number of distinct (from, to) reference pairs and their count by reference
// type. APIs: ReferenceManager.getReferenceSourceIterator / getReferencesFrom,
// Memory.getBlock (Ghidra 12.1.3).
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class ExportModuleReferences extends GhidraScript {
    private String moduleOf(Address address) {
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        if (block == null) return "unmapped";
        String name = block.getName();
        int cut = name.indexOf("_.");
        // GameCubeLoader names the DOL's blocks `MAIN_.text0`, `MAIN_.data0`, ...
        // and the system blocks (OSGlobals, hardware registers) have no prefix.
        String module = cut > 0 ? name.substring(0, cut) : "dol";
        return module.equals("MAIN") ? "dol" : module;
    }

    private String blockName(Address address) {
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        return block == null ? "unmapped" : block.getName();
    }

    @Override
    public void run() throws Exception {
        Map<String, Set<String>> pairs = new TreeMap<>();
        Map<String, Map<String, Integer>> kinds = new TreeMap<>();
        long total = 0;
        StringBuilder detail = new StringBuilder();
        AddressIterator sources = currentProgram.getReferenceManager().getReferenceSourceIterator(
            currentProgram.getMemory(), true);
        while (sources.hasNext() && !monitor.isCancelled()) {
            Address from = sources.next();
            if (!from.isMemoryAddress()) continue;
            String fromModule = moduleOf(from);
            for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(from)) {
                Address to = reference.getToAddress();
                if (!to.isMemoryAddress()) continue;
                total++;
                String toModule = moduleOf(to);
                if (fromModule.equals(toModule)) continue;
                String key = fromModule + "->" + toModule;
                pairs.computeIfAbsent(key, k -> new HashSet<>())
                    .add(from.getOffset() + ":" + to.getOffset());
                kinds.computeIfAbsent(key, k -> new TreeMap<>())
                    .merge(reference.getReferenceType().getName(), 1, Integer::sum);
                detail.append(String.format("%x\t%x\t%s\t%s\t%s\t%s%n", from.getOffset(), to.getOffset(),
                    reference.getReferenceType().getName(), key,
                    blockName(from), blockName(to)));
            }
        }
        JsonObject out = new JsonObject();
        out.addProperty("references_total", total);
        JsonObject crossing = new JsonObject();
        for (Map.Entry<String, Set<String>> entry : pairs.entrySet()) {
            JsonObject row = new JsonObject();
            row.addProperty("distinct_pairs", entry.getValue().size());
            JsonObject byKind = new JsonObject();
            for (Map.Entry<String, Integer> kind : kinds.get(entry.getKey()).entrySet()) {
                byKind.addProperty(kind.getKey(), kind.getValue());
            }
            row.add("by_type", byKind);
            crossing.add(entry.getKey(), row);
        }
        out.add("cross_module", crossing);
        Files.writeString(Path.of(getScriptArgs()[0]), out.toString());
        Files.writeString(Path.of(getScriptArgs()[0] + ".pairs.tsv"), detail.toString());
    }
}
