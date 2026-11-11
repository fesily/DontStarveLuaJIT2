// Locate every occurrence of a 32-bit constant in the executable image.
//
// Component ids, enum values and four-character tags are materialised as 32-bit
// immediates. Rather than pattern-matching one instruction shape at a time
// (`mov eax,imm32; ret` misses the ones MSVC builds from two halves, or that
// sit behind a stack-cookie prologue), search the raw bytes for the little
// endian value and report which function contains it. That covers every
// encoding at once.
//
// Usage: DstFindConstants.java <values.tsv> <out.tsv>
//   values.tsv: one hex value per line, optionally "0x1d c8 eb 7e" style rows
//               (only the first field is read)
// Output: function_entry \t value_hex \t offset_in_function \t in_function(0/1)
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public class DstFindConstants extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();

        List<Long> values = new ArrayList<>();
        java.util.Set<Long> seen = new LinkedHashSet<>();
        try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String first = line.split("[\\t, ]+")[0];
                try {
                    long v = Long.parseUnsignedLong(first.replace("0x", ""), 16);
                    if (v > 0xffffL && v <= 0xffffffffL && seen.add(v)) values.add(v);
                } catch (Exception e) {
                    // skip junk rows
                }
            }
        }
        println("distinct 32-bit values: " + values.size());

        int hits = 0;
        int inFunc = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[1]), StandardCharsets.UTF_8))) {
            for (long v : values) {
                if (monitor.isCancelled()) break;
                byte[] pat = new byte[]{
                        (byte) (v & 0xff), (byte) ((v >>> 8) & 0xff),
                        (byte) ((v >>> 16) & 0xff), (byte) ((v >>> 24) & 0xff)};
                for (MemoryBlock blk : mem.getBlocks()) {
                    if (!blk.isInitialized() || !blk.isExecute()) continue;
                    Address cur = blk.getStart();
                    Address end = blk.getEnd();
                    while (cur != null && cur.compareTo(end) < 0) {
                        Address a = mem.findBytes(cur, pat, null, true, monitor);
                        if (a == null || a.compareTo(end) > 0) break;
                        hits++;
                        Function f = fm.getFunctionContaining(a);
                        long offset = -1;
                        if (f != null) {
                            offset = a.subtract(f.getEntryPoint());
                            inFunc++;
                            w.write("0x" + Long.toHexString(f.getEntryPoint().getOffset()) + "\t"
                                    + Long.toHexString(v) + "\t" + offset + "\t1");
                        } else {
                            w.write("0x0\t" + Long.toHexString(v) + "\t" + Long.toHexString(a.getOffset()) + "\t0");
                        }
                        w.newLine();
                        cur = a.add(1);
                    }
                }
            }
        }
        println("constant hits=" + hits + " inside_functions=" + inFunc + " -> " + args[1]);
    }
}
