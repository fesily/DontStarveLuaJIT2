// Delete functions listed in a text file (one hex entry per line).
//
// Roll-back path for a structural repair that turned out to be wrong: the
// `.pdata` sweep created functions at EH funclets / chained-unwind fragments
// (74% of them are not 16-byte aligned, which MSVC never emits for a real
// function start).  Removing the function does not touch the instructions, so
// re-creating it later restores the previous state.
//
// Usage: DstDeleteFunctionsFromList.java <in.txt> <report.tsv> <dry|apply>
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class DstDeleteFunctionsFromList extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        boolean apply = args.length > 2 && "apply".equalsIgnoreCase(args[2]);
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int removed = 0, skipped = 0, missing = 0;
        try (BufferedReader r = new BufferedReader(new FileReader(args[0]));
             BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                     new FileOutputStream(args[1]), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                long v;
                try {
                    v = Long.parseUnsignedLong(line.replace("0x", ""), 16);
                } catch (Exception e) {
                    continue;
                }
                Address a = sp.getAddress(v);
                Function f = a == null ? null : fm.getFunctionAt(a);
                if (f == null) {
                    missing++;
                    w.write("0x" + Long.toHexString(v) + "\tmissing");
                    w.newLine();
                    continue;
                }
                // never delete a function that carries a real name
                if (!f.getName().startsWith("FUN_")) {
                    skipped++;
                    w.write("0x" + Long.toHexString(v) + "\tskipped-named\t" + f.getName());
                    w.newLine();
                    continue;
                }
                if (!apply) {
                    removed++;
                    w.write("0x" + Long.toHexString(v) + "\twould-remove");
                    w.newLine();
                    continue;
                }
                try {
                    fm.removeFunction(a);
                    removed++;
                    w.write("0x" + Long.toHexString(v) + "\tremoved");
                } catch (Exception e) {
                    skipped++;
                    w.write("0x" + Long.toHexString(v) + "\tfailed\t" + e.getMessage());
                }
                w.newLine();
            }
        }
        println("delete-list: " + (apply ? "removed=" : "would_remove=") + removed
                + " skipped=" + skipped + " missing=" + missing + " -> " + args[1]);
    }
}
