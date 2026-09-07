// Oracle-only postScript; never part of the native runtime.
// Ghidra 12.1.3 APIs verified in the extracted sources (Apache-2.0):
// FileDataTypeManager.openFileArchive(File, boolean) (FileDataTypeManager.java
// :194-197), DataTypeManager.getAllDataTypes (iterator over every type),
// FunctionDefinition extends FunctionSignature (FunctionDefinition.java:26),
// FunctionSignature.getArguments/getReturnType/hasVarArgs.
//
// Exports the function declarations a Ghidra type archive holds, so the
// JVM-free runtime can apply them without a packed-database parser. The
// output is committed with the archive's hash; nothing here reads a program.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Iterator;

public class ExportLibraryPrototypes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 2) {
            throw new IllegalArgumentException("usage: <archive.gdt> <output.json>");
        }
        File archive = new File(arguments[0]);
        Path output = Path.of(arguments[1]);

        FileDataTypeManager manager = FileDataTypeManager.openFileArchive(archive, false);
        JsonObject functions = new JsonObject();
        try {
            Iterator<DataType> types = manager.getAllDataTypes();
            while (types.hasNext()) {
                DataType type = types.next();
                if (!(type instanceof FunctionDefinition)) {
                    continue;
                }
                FunctionDefinition definition = (FunctionDefinition) type;
                JsonObject entry = new JsonObject();
                entry.addProperty("return_type", definition.getReturnType().getName());
                entry.addProperty("varargs", definition.hasVarArgs());
                JsonArray parameters = new JsonArray();
                for (ParameterDefinition parameter : definition.getArguments()) {
                    JsonObject argument = new JsonObject();
                    argument.addProperty("name", parameter.getName());
                    argument.addProperty("type", parameter.getDataType().getName());
                    argument.addProperty("size", parameter.getLength());
                    parameters.add(argument);
                }
                entry.add("parameters", parameters);
                functions.add(definition.getName(), entry);
            }
        } finally {
            manager.close();
        }

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        StringBuilder digest = new StringBuilder();
        for (byte value : sha.digest(Files.readAllBytes(archive.toPath()))) {
            digest.append(String.format("%02x", value));
        }

        JsonObject document = new JsonObject();
        document.addProperty("archive", arguments.length > 2 ? arguments[2] : archive.getPath());
        document.addProperty("archive_sha256", digest.toString());
        document.addProperty("generator", "scripts/ExportLibraryPrototypes.java");
        document.addProperty("upstream_version", getGhidraVersion());
        document.add("functions", functions);
        try (PrintWriter writer = new PrintWriter(output.toFile(), "UTF-8")) {
            writer.println(new Gson().toJson(document));
        }
        println("EXPORTED " + functions.size() + " declarations to " + output);
    }
}
