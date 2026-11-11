// Dump vtable layouts with Itanium hierarchy information.
// Usage: DstExportVtablesRich.java <out.tsv>
// Output: vtable_label \t base_typeinfo \t slot_count \t slot_addr:funcname,...
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

public class DstExportVtablesRich extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExportVtablesRich.java <out.tsv>");
            return;
        }
        Memory mem = currentProgram.getMemory();
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int written = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            w.write("# vtable\tbase_ti\tslot_count\tslots\n");
            SymbolIterator it = st.getAllSymbols(true);
            while (it.hasNext()) {
                if (monitor.isCancelled()) break;
                Symbol s = it.next();
                String name = s.getName();
                if (!name.startsWith("_ZTV")) continue;
                if (name.contains("__cxxabiv1")) continue;
                Address a = s.getAddress();
                // typeinfo pointer sits in header word 1; its base class pointer at TI+16
                String baseTi = "";
                try {
                    long ti = mem.getLong(a.add(8));
                    if (ti != 0) {
                        long basePtr = mem.getLong(sp.getAddress(ti).add(16));
                        if (basePtr != 0) {
                            Symbol bs = st.getPrimarySymbol(sp.getAddress(basePtr));
                            if (bs != null) baseTi = bs.getName();
                        }
                    }
                } catch (Exception e) {
                    // header layout may differ; leave base empty
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
                w.write(name + "\t" + baseTi + "\t" + slots.size() + "\t"
                        + String.join(",", slots));
                w.newLine();
                written++;
            }
        }
        println("vtables-rich: program=" + currentProgram.getName() + " tables=" + written);
    }
}
