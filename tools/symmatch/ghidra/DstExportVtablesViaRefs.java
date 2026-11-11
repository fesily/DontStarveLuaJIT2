// Find vtables the reliable way: data references from code (constructors store the
// vptr) whose target starts a run of code pointers. Run-based scanning merges
// neighbouring tables, which corrupts slot counts.
// Usage: DstExportVtablesViaRefs.java <out.tsv>
// Output: start \t slot_count \t slots(hex,...)
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

public class DstExportVtablesViaRefs extends GhidraScript {

    private Memory mem;
    private FunctionManager fm;
    private AddressSpace sp;
    private ReferenceManager refMgr;
    private TreeMap<Long, List<Long>> tables = new TreeMap<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExportVtablesViaRefs.java <out.tsv>");
            return;
        }
        mem = currentProgram.getMemory();
        fm = currentProgram.getFunctionManager();
        sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        refMgr = currentProgram.getReferenceManager();

        TreeSet<Long> targets = new TreeSet<>();
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            for (var ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                for (Reference r : refMgr.getReferencesFrom(ins.getAddress())) {
                    if (r.getReferenceType().isCall()) continue;
                    Address to = r.getToAddress();
                    if (to == null) continue;
                    MemoryBlock b = mem.getBlock(to);
                    if (b == null || !b.isInitialized() || b.isExecute()) continue;
                    targets.add(to.getOffset());
                }
            }
        }
        println("candidate data targets from code refs: " + targets.size());

        for (long t : targets) {
            List<Long> slots = readRun(sp.getAddress(t));
            if (slots.size() >= 2) tables.put(t, slots);
        }

        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (var e : tables.entrySet()) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < e.getValue().size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append("0x").append(Long.toHexString(e.getValue().get(i)));
                }
                w.write("0x" + Long.toHexString(e.getKey()) + "\t" + e.getValue().size() + "\t" + sb);
                w.newLine();
            }
        }
        println("vtables-via-refs: " + tables.size());
    }

    private List<Long> readRun(Address a) {
        List<Long> out = new ArrayList<>();
        int holes = 0;
        for (int i = 0; i < 400; i++) {
            long v;
            try { v = mem.getLong(a.add(i * 8L)); } catch (Exception e) { break; }
            if (!isCodePtr(v)) {
                // MSVC vtables may contain a zero or a vtordisp-style hole
                // between the destructor and the first declared virtual, and
                // neighbours are not always code pointers. Tolerate isolated
                // holes but stop after a longer non-code stretch.
                if (v == 0 && holes < 2) {
                    holes++;
                    out.add(0L);
                    continue;
                }
                break;
            }
            holes = 0;
            out.add(v);
        }
        while (!out.isEmpty() && out.get(out.size() - 1) == 0L) out.remove(out.size() - 1);
        return out;
    }

    private boolean isCodePtr(long v) {
        try {
            Address a = sp.getAddress(v);
            if (!mem.contains(a)) return false;
            MemoryBlock b = mem.getBlock(a);
            if (b != null && b.isExecute()) return true;
            return fm.getFunctionAt(a) != null;   // import thunk / external
        } catch (Exception e) {
            return false;
        }
    }
}
