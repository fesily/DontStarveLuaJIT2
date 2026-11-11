// Define functions at the addresses listed in a text file (one hex address per line).
//
// Generalisation of DstDefinePdataFunctions: used for ELF `.eh_frame_hdr` FDE
// starts, vtable slot targets, or any other externally derived function list.
//
// Usage: DstDefineFunctionsFromList.java <in.txt> <report.tsv>
// Output: address \t created|exists|refused
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class DstDefineFunctionsFromList extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int created = 0, exists = 0, refused = 0;
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
                if (a == null || !mem.contains(a)) continue;
                String kind;
                if (fm.getFunctionAt(a) != null) {
                    exists++;
                    kind = "exists";
                } else {
                    try {
                        Function f = createFunction(a, null);
                        if (f != null) { created++; kind = "created"; }
                        else { refused++; kind = "refused"; }
                    } catch (Exception e) {
                        refused++;
                        kind = "refused";
                    }
                }
                w.write("0x" + Long.toHexString(v) + "\t" + kind);
                w.newLine();
            }
        }
        println("define-list: created=" + created + " existed=" + exists
                + " refused=" + refused + " -> " + args[1]);
    }
}
