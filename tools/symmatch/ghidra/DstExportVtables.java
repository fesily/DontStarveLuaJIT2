// Export vtable-like arrays (runs of function pointers) for cross-architecture alignment.
// Android: every `_ZTV*` label is a vtable (Itanium layout: [0]=offset-to-top, [1]=typeinfo).
// Windows: MSVC emits no names, so scan .rdata/.data for runs of >=3 function-entry pointers.
// Usage: DstExportVtables.java <out.tsv>
// Output: label \t start \t slot_count \t slot,slot,...   (no header)
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DstExportVtables extends GhidraScript {

    private static final int MIN_RUN = 3;
    private static final int MAX_SLOTS = 512;

    private Memory memory;
    private FunctionManager funcs;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExportVtables.java <out.tsv>");
            return;
        }
        memory = currentProgram.getMemory();
        funcs = currentProgram.getFunctionManager();

        Map<Long, String[]> out = new LinkedHashMap<>(); // start -> {label, slotsCSV}
        int labelled = scanLabelled(out);
        int scanned = scanPointers(out);

        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (Map.Entry<Long, String[]> e : out.entrySet()) {
                w.write(e.getValue()[0] + "\t" + hex(e.getKey()) + "\t"
                        + e.getValue()[2] + "\t" + e.getValue()[1]);
                w.newLine();
            }
        }
        println("vtables: program=" + currentProgram.getName() + " total=" + out.size()
                + " labelled=" + labelled + " scanned_runs=" + scanned);
    }

    private int scanLabelled(Map<Long, String[]> out) {
        int n = 0;
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Symbol s = it.next();
            String name = s.getName();
            if (!name.startsWith("_ZTV")) continue;
            if (name.contains("__cxxabiv1")) continue;
            Address a = s.getAddress();
            if (a == null || !memory.contains(a)) continue;
            List<Long> slots = readRun(a);
            if (slots.size() < 1) continue;
            out.put(a.getOffset(), new String[]{name, csv(slots), Integer.toString(slots.size())});
            n++;
        }
        return n;
    }

    private int scanPointers(Map<Long, String[]> out) {
        int runs = 0;
        for (MemoryBlock blk : memory.getBlocks()) {
            if (!blk.isInitialized() || blk.isExecute() || blk.isWrite()) continue;
            long size = blk.getSize();
            if (size < MIN_RUN * 8 || size > 8L * 1024 * 1024) continue;
            Address base = blk.getStart();
            long start = -1;
            List<Long> cur = new ArrayList<>();
            for (long off = 0; off + 8 <= size; off += 8) {
                Long v = readPointer(base.add(off));
                boolean ok = v != null && isFunctionEntry(v);
                if (ok) {
                    if (cur.isEmpty()) start = base.getOffset() + off;
                    cur.add(v);
                    continue;
                }
                // A zero qword between the destructor slot and the first
                // declared virtual is common in MSVC vtables; keep the run
                // together when a function entry follows immediately.
                if (v != null && v == 0 && !cur.isEmpty()) {
                    Long next = readPointer(base.add(off + 8));
                    if (next != null && isFunctionEntry(next)) {
                        cur.add(0L);
                        continue;
                    }
                }
                if (cur.size() >= MIN_RUN) {
                    runs++;
                    String label = "ptr_" + hex(start);
                    // a labelled vtable wins; otherwise keep the longest run
                    String[] prev = out.get(start);
                    if (prev == null) {
                        out.put(start, new String[]{label, csv(cur), Integer.toString(cur.size())});
                    }
                }
                cur = new ArrayList<>();
            }
            if (cur.size() >= MIN_RUN) {
                runs++;
                String label = "ptr_" + hex(start);
                if (!out.containsKey(start)) {
                    out.put(start, new String[]{label, csv(cur), Integer.toString(cur.size())});
                }
            }
        }
        return runs;
    }

    private List<Long> readRun(Address a) {
        // Itanium layout keeps two non-code header words ([0]=offset-to-top,
        // [1]=typeinfo) before the method slots; stop at the first non-code
        // pointer after the header.
        List<Long> slots = new ArrayList<>();
        for (int i = 0; i < MAX_SLOTS; i++) {
            Address cur = a.add((long) i * 8);
            Long v = readPointer(cur);
            if (v == null) break;
            if (i >= 2 && !isFunctionEntry(v)) break;
            slots.add(v);
        }
        return slots;
    }

    private Long readPointer(Address a) {
        try {
            return memory.getLong(a);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isFunctionEntry(long v) {
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            if (!memory.contains(a)) return false;
            // A vtable slot may be a thunk (pure virtual -> __purecall import) or an
            // external; those still belong to the table. Only a non-code pointer ends it.
            // Slots can point at linker thunks / undefined stubs (e.g. __purecall),
            // so accept any executable address instead of requiring a defined function.
            MemoryBlock b = memory.getBlock(a);
            if (b == null) return false;
            // vtable slots may be code, linker thunks, or IAT entries for imports;
            // anything inside an initialized block is a candidate slot value.
            return b.isInitialized();
        } catch (Exception e) {
            return false;
        }
    }

    private static String csv(List<Long> slots) {
        StringBuilder sb = new StringBuilder(slots.size() * 12);
        for (int i = 0; i < slots.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(hex(slots.get(i)));
        }
        return sb.toString();
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }
}
