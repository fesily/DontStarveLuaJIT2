// Dump vtable layouts with full Itanium typeinfo hierarchy (handles multiple
// inheritance): class_type_info / si_class_type_info / vmi_class_type_info.
// Usage: DstExportVtablesRich2.java <out.tsv>
// Output: vtable \t kind \t nbase \t bases(name:offsetflags,...) \t slot_count \t slots(addr:func,...)
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DstExportVtablesRich2 extends GhidraScript {

    private Memory mem;
    private SymbolTable st;
    private FunctionManager fm;
    private AddressSpace sp;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExportVtablesRich2.java <out.tsv>");
            return;
        }
        mem = currentProgram.getMemory();
        st = currentProgram.getSymbolTable();
        fm = currentProgram.getFunctionManager();
        sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int written = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            w.write("# vtable\tkind\tnbase\tbases\tslot_count\tslots\n");
            SymbolIterator it = st.getAllSymbols(true);
            while (it.hasNext()) {
                if (monitor.isCancelled()) break;
                Symbol s = it.next();
                String name = s.getName();
                if (!name.startsWith("_ZTV") || name.contains("__cxxabiv1")) continue;
                Address a = s.getAddress();
                String kind = "none";
                List<String> bases = new ArrayList<>();
                try {
                    long ti = mem.getLong(a.add(8));
                    if (ti != 0) {
                        Address tiA = sp.getAddress(ti);
                        long tiVt = mem.getLong(tiA);
                        // the typeinfo vptr points at the vtable address point (symbol + 16)
                        String tiVtName = symbolName(sp.getAddress(tiVt));
                        if (tiVtName.isEmpty()) tiVtName = symbolName(sp.getAddress(tiVt - 16));
                        if (tiVtName.endsWith("117__class_type_infoE")) kind = "class";
                        else if (tiVtName.endsWith("120__si_class_type_infoE")) kind = "si";
                        else if (tiVtName.endsWith("121__vmi_class_type_infoE")) kind = "vmi";
                        if (kind.equals("si")) {
                            long b = mem.getLong(tiA.add(16));
                            String bn = symbolName(sp.getAddress(b));
                            if (bn.isEmpty()) bn = symbolName(sp.getAddress(b - 16));
                            bases.add(bn + ":0");
                        } else if (kind.equals("vmi")) {
                            int n = mem.getInt(tiA.add(20));
                            for (int k = 0; k < Math.min(n, 8); k++) {
                                long bp = mem.getLong(tiA.add(24 + 16L * k));
                                long off = mem.getLong(tiA.add(32 + 16L * k));
                                String bn = symbolName(sp.getAddress(bp));
                                if (bn.isEmpty()) bn = symbolName(sp.getAddress(bp - 16));
                                bases.add(bn + ":" + off);
                            }
                        }
                    }
                } catch (Exception e) {
                    // keep kind/bases as parsed so far
                }
                List<String> slots = new ArrayList<>();
                for (int i = 2; i < 400; i++) {
                    long v;
                    try { v = mem.getLong(a.add(i * 8L)); } catch (Exception e) { break; }
                    Address t = sp.getAddress(v);
                    Function f = fm.getFunctionAt(t);
                    if (f == null) break;
                    slots.add(Long.toHexString(v) + ":" + f.getName());
                }
                if (slots.isEmpty()) continue;
                w.write(name + "\t" + kind + "\t" + bases.size() + "\t"
                        + String.join(",", bases) + "\t" + slots.size() + "\t"
                        + String.join(",", slots));
                w.newLine();
                written++;
            }
        }
        println("vtables-rich2: program=" + currentProgram.getName() + " tables=" + written);
    }

    private String symbolName(Address a) {
        if (a == null) return "";
        Symbol[] syms = st.getSymbols(a);
        String best = "";
        for (Symbol s : syms) {
            String n = s.getName();
            if (n.startsWith("_ZT")) return n;          // typeinfo symbol wins
            if (best.isEmpty()) best = n;
        }
        return best;
    }
}
