// Extract script-binding tables on Mach-O and emit *every* row with its table and index, so the
// table contents can be aligned one-to-one across two builds.
//
// Layouts: {name, func, 0, 0} stride 32 (clang/macOS), {name, func, 0} stride 24,
//          {name, func} stride 16.  Tables live in __data / __DATA_CONST, sometimes read-only.
//
// Usage: DstExtractBindingsRows.java <out.tsv>
// Output: table_base_hex \t index \t name \t func_addr_hex \t stride   (no header)
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

public class DstExtractBindingsRows extends GhidraScript {

    private static final int[] STRIDES = {32, 24, 16};
    private static final int MIN_RUN = 3;
    private static final int MAX_NAME = 64;

    private Memory memory;
    private FunctionManager funcs;

    private static class Run {
        long start;
        List<String> names = new ArrayList<>();
        List<Long> addrs = new ArrayList<>();
    }

    private static long rd(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xffL);
        return v;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExtractBindingsRows.java <out.tsv>");
            return;
        }
        memory = currentProgram.getMemory();
        funcs = currentProgram.getFunctionManager();

        TreeMap<Long, Run> tables = new TreeMap<>();     // table base -> run (longest wins)
        TreeMap<Integer, Integer> stats = new TreeMap<>();

        for (int stride : STRIDES) {
            List<Run> runs = new ArrayList<>();
            for (MemoryBlock blk : memory.getBlocks()) {
                if (!blk.isInitialized() || blk.isExecute()) continue;
                String bn = blk.getName();
                if (bn == null || bn.contains("LINKEDIT") || bn.startsWith("__cstring")
                        || bn.startsWith("__objc") || bn.startsWith("__ustring")
                        || bn.startsWith("__unwind") || bn.startsWith("__eh_frame")
                        || bn.contains("stub") || bn.startsWith("__got")) continue;
                long size = blk.getSize();
                if (size < stride * MIN_RUN || size > 32L * 1024 * 1024) continue;
                byte[] buf = new byte[(int) size];
                try {
                    memory.getBytes(blk.getStart(), buf);
                } catch (Exception e) {
                    continue;
                }
                walk(buf, blk.getStart().getOffset(), stride, runs);
            }
            int n = 0;
            for (Run r : runs) n += r.names.size();
            stats.put(stride, n);
            for (Run r : runs) {
                Run prev = tables.get(r.start);
                if (prev == null || r.names.size() > prev.names.size()) tables.put(r.start, r);
            }
        }

        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            int rows = 0;
            for (Run r : tables.values()) {
                for (int i = 0; i < r.names.size(); i++) {
                    w.write(hex(r.start) + "\t" + i + "\t" + r.names.get(i) + "\t"
                            + hex(r.addrs.get(i)) + "\t0");
                    w.newLine();
                    rows++;
                }
            }
            println("bindrows: program=" + currentProgram.getName() + " tables=" + tables.size()
                    + " rows=" + rows + " runs_by_stride=" + stats);
        }
    }

    private void walk(byte[] buf, long baseOffset, int stride, List<Run> runs) {
        int n = buf.length;
        int o = 0;
        Run cur = null;
        while (o + stride <= n) {
            String name = null;
            long faddr = -1;
            long p1 = rd(buf, o);
            long p2 = rd(buf, o + 8);
            if (p1 != 0 && p2 != 0) {
                Address fa = addr(p2);
                Function f = (fa == null) ? null : funcs.getFunctionAt(fa);
                if (f != null && !f.isExternal() && !f.isThunk()) {
                    boolean zeroPad = true;
                    for (int k = 16; k < stride; k += 8) {
                        if (rd(buf, o + k) != 0) {
                            zeroPad = false;
                            break;
                        }
                    }
                    if (zeroPad) {
                        name = stringAt(p1);
                        if (name != null && !plausible(name)) name = null;
                        if (name != null) faddr = p2;
                    }
                }
            }
            if (name != null) {
                if (cur == null) {
                    cur = new Run();
                    cur.start = baseOffset + o;
                }
                cur.names.add(name);
                cur.addrs.add(faddr);
                o += stride;
            } else {
                if (cur != null && cur.names.size() >= MIN_RUN) runs.add(cur);
                cur = null;
                o += 8;
            }
        }
        if (cur != null && cur.names.size() >= MIN_RUN) runs.add(cur);
    }

    private Address addr(long v) {
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            return memory.contains(a) ? a : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String stringAt(long ptr) {
        Address a = addr(ptr);
        if (a == null) return null;
        try {
            byte[] b = new byte[MAX_NAME + 1];
            int len = -1;
            for (int i = 0; i < b.length; i++) {
                byte v = memory.getByte(a.add(i));
                if (v == 0) {
                    len = i;
                    break;
                }
                if (v < 0x20 || v > 0x7e) return null;
                b[i] = v;
            }
            if (len < 2) return null;
            return new String(b, 0, len, StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean plausible(String n) {
        if (n.length() < 2 || n.length() > 48) return false;
        if (!Character.isJavaIdentifierStart(n.charAt(0))) return false;
        for (int i = 1; i < n.length(); i++) {
            if (!Character.isJavaIdentifierPart(n.charAt(i))) return false;
        }
        return true;
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }
}
