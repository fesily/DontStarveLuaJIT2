// Extract script-binding tables (name pointer + function pointer arrays) from writable data.
// Works for both layouts seen in DST: {name, func, 0} stride 24 (MSVC) and
// {name, func, 0, 0} stride 32 (NDK/ARM64), plus bare {name, func} stride 16.
//
// Usage: DstExtractBindings.java <out.tsv>
// Output: name \t func_addr_hex \t table_base_hex \t stride   (no header)
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class DstExtractBindings extends GhidraScript {

    private static final int[] STRIDES = {32, 24, 16};
    private static final int MIN_RUN = 3;
    private static final int MAX_NAME = 64;

    private Memory memory;
    private FunctionManager funcs;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExtractBindings.java <out.tsv>");
            return;
        }
        memory = currentProgram.getMemory();
        funcs = currentProgram.getFunctionManager();

        // longest run first, so a spurious short match cannot steal an address
        Map<Long, String[]> best = new LinkedHashMap<>();
        Map<Integer, Integer> stats = new TreeMap<>();

        for (int stride : STRIDES) {
            List<long[]> runs = new ArrayList<>(); // [startOffset, count]
            for (MemoryBlock blk : memory.getBlocks()) {
                if (!blk.isInitialized() || blk.isExecute() || !blk.isWrite()) continue;
                Address base = blk.getStart();
                long size = blk.getSize();
                if (size < stride * MIN_RUN || size > 32L * 1024 * 1024) continue;
                byte[] buf = new byte[(int) size];
                try {
                    memory.getBytes(base, buf);
                } catch (Exception e) {
                    printerr("skip block " + blk.getName() + ": " + e.getMessage());
                    continue;
                }
                walk(buf, base.getOffset(), stride, runs, best);
            }
            int n = 0;
            for (long[] r : runs) n += (int) r[1];
            stats.put(stride, n);
        }

        // dedupe by function address, keeping the entry from the longest table
        Map<Long, String[]> chosen = new LinkedHashMap<>();
        for (Map.Entry<Long, String[]> e : best.entrySet()) {
            chosen.putIfAbsent(e.getKey(), e.getValue());
        }

        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (Map.Entry<Long, String[]> e : chosen.entrySet()) {
                String[] v = e.getValue();
                w.write(v[0] + "\t" + hex(e.getKey()) + "\t" + v[1] + "\t" + v[2]);
                w.newLine();
            }
        }
        println("bindings: program=" + currentProgram.getName() + " entries=" + chosen.size()
                + " runs_by_stride=" + stats);
    }

    private void walk(byte[] buf, long baseOffset, int stride, List<long[]> runs,
                      Map<Long, String[]> best) {
        int n = buf.length;
        int o = 0;
        List<Long> curFuncs = new ArrayList<>();
        List<String> curNames = new ArrayList<>();
        long curStart = -1;
        while (o + stride <= n) {
            String name = null;
            long faddr = -1;
            if (valid(buf, o, stride)) {
                long p1 = readLong(buf, o);
                long p2 = readLong(buf, o + 8);
                name = stringAt(baseOffset, p1);
                if (name != null) faddr = p2;
            }
            if (name != null) {
                if (curNames.isEmpty()) curStart = baseOffset + o;
                curNames.add(name);
                curFuncs.add(faddr);
                o += stride;
            } else {
                if (curNames.size() >= MIN_RUN) {
                    runs.add(new long[]{curStart, curNames.size()});
                    boolean clean = true;
                    for (String cn : curNames) {
                        if (!plausible(cn)) {
                            clean = false;
                            break;
                        }
                    }
                    if (clean) {
                        for (int i = 0; i < curNames.size(); i++) {
                            long f = curFuncs.get(i);
                            String[] prev = best.get(f);
                            if (prev == null || curNames.size() > Integer.parseInt(prev[3])) {
                                best.put(f, new String[]{curNames.get(i), hex(curStart), Integer.toString(stride),
                                        Integer.toString(curNames.size())});
                            }
                        }
                    }
                }
                curNames = new ArrayList<>();
                curFuncs = new ArrayList<>();
                o += 8;
            }
        }
        if (curNames.size() >= MIN_RUN) {
            boolean clean = true;
            for (String cn : curNames) {
                if (!plausible(cn)) {
                    clean = false;
                    break;
                }
            }
            if (clean) {
                for (int i = 0; i < curNames.size(); i++) {
                    long f = curFuncs.get(i);
                    String[] prev = best.get(f);
                    if (prev == null || curNames.size() > Integer.parseInt(prev[3])) {
                        best.put(f, new String[]{curNames.get(i), hex(curStart), Integer.toString(stride),
                                Integer.toString(curNames.size())});
                    }
                }
            }
        }
    }

    private boolean valid(byte[] buf, int off, int stride) {
        long p1 = readLong(buf, off);
        long p2 = readLong(buf, off + 8);
        if (p1 == 0 || p2 == 0) return false;
        Address fa = addr(p2);
        if (fa == null) return false;
        Function f = funcs.getFunctionAt(fa);
        if (f == null || f.isExternal() || f.isThunk()) return false;
        for (int k = 16; k < stride; k += 8) {
            if (readLong(buf, off + k) != 0) return false;
        }
        return true;
    }

    private long readLong(byte[] buf, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | (buf[off + i] & 0xffL);
        }
        return v;
    }

    private Address addr(long v) {
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            return memory.contains(a) ? a : null;
        } catch (Exception e) {
            return null;
        }
    }

    // Strings are read straight out of memory: on ELF programs Ghidra often leaves
    // .rodata strings undefined, so relying on defined Data silently yields zero tables.
    private String stringAt(long blockBase, long ptr) {
        if (ptr == 0) return null;
        Address a = addr(ptr);
        if (a == null) return null;
        try {
            byte[] buf = new byte[MAX_NAME + 1];
            int n = -1;
            for (int i = 0; i < buf.length; i++) {
                byte b = memory.getByte(a.add(i));
                if (b == 0) { n = i; break; }
                if (b < 0x20 || b > 0x7e) return null;
                buf[i] = b;
            }
            if (n < 2) return null;
            return new String(buf, 0, n, java.nio.charset.StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return null;
        }
    }

    // A real luaL_Reg name is a compact identifier.  Spurious alignments inside
    // pointer arrays of unrelated tables yield source paths, format strings and
    // sentence fragments; rejecting them keeps the longest-run heuristic from
    // letting a junk alignment overwrite a correct 24-byte table.
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
