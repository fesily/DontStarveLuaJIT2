// Map constructors to the vtables they store.
//
// MSVC writes the vptr in the constructor (`lea rax,[vtable]; mov [rcx],rax`),
// which Ghidra records as a data reference from the constructor. Emitting
// (function, referenced-table) pairs gives the ctor of every concrete class,
// and ctor -> ctor calls then reveal the base class chain: derive the class
// hierarchy the Windows image has no RTTI for.
//
// Usage: DstExportCtorVtables.java <out.tsv>
// Output: ctor_va \t vtable_va \t first_slot_is_code(0/1)
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

public class DstExportCtorVtables extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refs = currentProgram.getReferenceManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int rows = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (Function f : fm.getFunctions(true)) {
                if (monitor.isCancelled()) break;
                for (var ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                    for (Reference r : refs.getReferencesFrom(ins.getAddress())) {
                        if (r.getReferenceType().isCall()) continue;
                        Address to = r.getToAddress();
                        if (to == null) continue;
                        MemoryBlock b = mem.getBlock(to);
                        if (b == null || !b.isInitialized() || b.isExecute()) continue;
                        long first;
                        long second = 0;
                        try {
                            first = mem.getLong(to);
                        } catch (Exception e) {
                            continue;
                        }
                        Address fa = sp.getAddress(first);
                        MemoryBlock fb = mem.getBlock(fa);
                        if (fb == null || !fb.isExecute()) continue;
                        try {
                            second = mem.getLong(to.add(8));
                        } catch (Exception e) {
                            second = 0;
                        }
                        // a vtable start: code pointer followed by code/zero
                        Address sa = sp.getAddress(second);
                        MemoryBlock sb = second == 0 ? null : mem.getBlock(sa);
                        if (!(second == 0 || (sb != null && sb.isExecute()))) continue;
                        w.write("0x" + Long.toHexString(f.getEntryPoint().getOffset()) + "\t0x"
                                + Long.toHexString(to.getOffset()) + "\t1");
                        w.newLine();
                        rows++;
                    }
                }
            }
        }
        println("ctor->vtable rows=" + rows + " -> " + args[0]);
    }
}
