// Debug: print raw typeinfo chain for one vtable symbol.
// Usage: DstDebugTypeInfo.java <vtableSymbol>
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class DstDebugTypeInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String want = args.length > 0 ? args[0] : "_ZTV16cEntityComponent";
        Memory mem = currentProgram.getMemory();
        SymbolTable st = currentProgram.getSymbolTable();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        SymbolIterator it = st.getSymbols(want);
        while (it.hasNext()) {
            Address a = it.next().getAddress();
            println("vtable " + want + " @ " + a);
            long ti = mem.getLong(a.add(8));
            println("  ti=" + Long.toHexString(ti));
            Address tiA = sp.getAddress(ti);
            long vptr = mem.getLong(tiA);
            println("  ti[0] vptr=" + Long.toHexString(vptr));
            for (Address probe : new Address[]{sp.getAddress(vptr), sp.getAddress(vptr - 16)}) {
                Symbol[] syms = st.getSymbols(probe);
                StringBuilder sb = new StringBuilder();
                for (Symbol sym : syms) sb.append(sym.getName()).append(' ');
                println("    symbol@ " + probe + " -> " + sb);
            }
            println("  ti[2] (16)=" + Long.toHexString(mem.getLong(tiA.add(16))));
            println("  ti[3] (20)=" + mem.getInt(tiA.add(20)));
        }
    }
}
