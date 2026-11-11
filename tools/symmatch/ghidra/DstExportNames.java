// Dump every user-defined function symbol with its size, qualified name and tags.
// Usage: DstExportNames.java <out.tsv>
// Output: va \t end_va \t size \t qualified_name \t source \t tags
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.TreeSet;

public class DstExportNames extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExportNames.java <out.tsv>");
            return;
        }
        int rows = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                if (f.isExternal() || f.isThunk()) continue;
                Symbol s = f.getSymbol();
                SourceType src = s == null ? SourceType.DEFAULT : s.getSource();
                if (src == SourceType.DEFAULT) continue;
                String qname = f.getName(true);
                long start = f.getEntryPoint().getOffset();
                long size = f.getBody().getNumAddresses();
                Set<String> tags = new TreeSet<>();
                for (FunctionTag t : f.getTags()) tags.add(t.getName());
                w.write("0x" + Long.toHexString(start) + "\t0x" + Long.toHexString(start + size)
                        + "\t" + size + "\t" + qname.replace('\t', ' ')
                        + "\t" + src.toString() + "\t" + String.join(",", tags));
                w.newLine();
                rows++;
            }
        }
        println("names: program=" + currentProgram.getName() + " user_named_functions=" + rows
                + " out=" + args[0]);
    }
}
