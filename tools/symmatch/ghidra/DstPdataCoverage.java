// Compare the exception directory with the defined function set.
//
// Every x64 function with a frame has a RUNTIME_FUNCTION entry (12 bytes:
// begin RVA, end RVA, unwind RVA) in .pdata.  Entries whose begin address is
// not a function start are bodies Ghidra does not model: they are invisible to
// the call graph, to order-based reasoning and to every structural matcher.
//
// Usage: DstPdataCoverage.java <out.tsv>
// Output: begin \t end \t kind   (kind = defined | undefined)
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

public class DstPdataCoverage extends GhidraScript {

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
            if (b.getName().equals(".pdata")) {
                pdata = b;
                break;
            }
        }
        if (pdata == null) {
            printerr(".pdata not found");
            return;
        }
        long size = pdata.getSize();
        byte[] buf = new byte[(int) size];
        mem.getBytes(pdata.getStart(), buf);

        int total = 0, defined = 0, undefined = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (int o = 0; o + 12 <= buf.length; o += 12) {
                long begin = u32(buf, o);
                long end = u32(buf, o + 4);
                if (begin == 0 || end == 0) continue;
                total++;
                Address a = sp.getAddress(begin + imageBase);
                Function f = fm.getFunctionAt(a);
                String kind;
                if (f != null) {
                    defined++;
                    kind = "defined";
                } else {
                    undefined++;
                    kind = "undefined";
                }
                w.write("0x" + Long.toHexString(begin + imageBase) + "\t0x"
                        + Long.toHexString(end + imageBase) + "\t" + kind);
                w.newLine();
            }
        }
        println("pdata entries=" + total + " defined=" + defined
                + " undefined=" + undefined + " -> " + args[0]);
    }
}
