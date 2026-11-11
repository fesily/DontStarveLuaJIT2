// Define a function at every .pdata begin address that lacks one.
//
// The exception directory is the linker's own function list: on this image it
// holds 25,270 ranges while only 14,698 begin at a defined function, i.e. 42%
// of the code is invisible to the call graph and to every structural matcher.
// Defining those starts is mechanical and safe (no renaming, no code change).
//
// Usage: DstPdataCoverage/DstDefinePdataFunctions.java <report.tsv>
// Output: begin \t created|refused|exists
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class DstDefinePdataFunctions extends GhidraScript {

    private static final boolean ALIGN16 = true;

    private static long u32(byte[] b, int o) {
        return (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8)
                | ((b[o + 2] & 0xffL) << 16) | ((b[o + 3] & 0xffL) << 24);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long imageBase = currentProgram.getImageBase().getOffset();

        MemoryBlock pdata = null;
        for (MemoryBlock b : mem.getBlocks()) {
            if (b.getName().equals(".pdata")) { pdata = b; break; }
        }
        if (pdata == null) { printerr(".pdata not found"); return; }

        byte[] buf = new byte[(int) pdata.getSize()];
        mem.getBytes(pdata.getStart(), buf);

        int created = 0, exists = 0, refused = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (int o = 0; o + 12 <= buf.length; o += 12) {
                long begin = u32(buf, o);
                long end = u32(buf, o + 4);
                if (begin == 0 || end == 0) continue;
                // MSVC aligns x64 function starts to 16 bytes; entries that are
                // not aligned are EH funclets / chained-unwind fragments, not
                // callable entries.  Creating them invents functions in the
                // middle of real bodies (measured: 74% of the naive set).
                if (!ALIGN16 || (begin % 16) == 0) {
                Address a = sp.getAddress(begin + imageBase);
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
                w.write("0x" + Long.toHexString(begin + imageBase) + "\t"
                        + Long.toHexString(end + imageBase) + "\t" + kind);
                w.newLine();
                } else {
                    w.write("0x" + Long.toHexString(begin + imageBase) + "\t"
                            + Long.toHexString(end + imageBase) + "\tunaligned-skip");
                    w.newLine();
                }
            }
        }
        println("pdata: created=" + created + " existed=" + exists
                + " refused=" + refused + " -> " + args[0]);
    }
}
