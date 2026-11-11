// Clear migrated names: restore the default FUN_* name, drop sym:* tags and the
// provenance plate comment. Used when a review verdict rejects a candidate that
// was already written.
// Usage: DstClearNames.java <tsv with addresses in column 1> <dry|apply>
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DstClearNames extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: DstClearNames.java <tsv> <dry|apply>");
            return;
        }
        boolean apply = "apply".equalsIgnoreCase(args[1]);
        Listing listing = currentProgram.getListing();
        int cleared = 0, missing = 0;
        List<String> samples = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(args[0], StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String field = line.split("\t")[0].replace("0x", "");
                long va = Long.parseUnsignedLong(field, 16);
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
                Function f = currentProgram.getFunctionManager().getFunctionAt(a);
                if (f == null) { missing++; continue; }
                if (!apply) { cleared++; continue; }
                for (FunctionTag t : new ArrayList<>(f.getTags())) {
                    if (t.getName().startsWith("sym:")) f.removeTag(t.getName());
                }
                listing.setComment(a, CommentType.PLATE, null);
                f.setName(null, SourceType.DEFAULT);
                cleared++;
                if (samples.size() < 10) samples.add("0x" + field + " -> " + f.getName());
            }
        }
        println("clear mode=" + (apply ? "apply" : "dry") + " cleared=" + cleared
                + " missing=" + missing);
        for (String s : samples) println("  " + s);
    }
}
