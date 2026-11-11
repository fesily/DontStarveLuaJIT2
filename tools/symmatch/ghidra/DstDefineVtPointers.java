// Define every plausible vtable slot target as a function.
//
// Why: Ghidra leaves tiny virtuals undefined (10-byte name getters, empty
// `ret` stubs, `jmp [import]` thunks). Undefined slots break vtable runs
// (`isFunctionEntry`), shape classification (E/P/N) and fingerprints, so the
// slot tables look short and random. This pass creates functions for every
// qword in non-executable, read-only blocks that points into an executable
// block. It writes nothing else; names are untouched.
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

public class DstDefineVtPointers extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : null;
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        long qwords = 0;
        long codePtrs = 0;
        long created = 0;
        long failed = 0;
        StringBuilder report = new StringBuilder();
        for (MemoryBlock blk : mem.getBlocks()) {
            if (!blk.isInitialized() || blk.isExecute() || blk.isWrite()) continue;
            long size = blk.getSize();
            if (size < 8 || size > 64L * 1024 * 1024) continue;
            Address base = blk.getStart();
            for (long off = 0; off + 8 <= size; off += 8) {
                if (monitor.isCancelled()) break;
                long v;
                try { v = mem.getLong(base.add(off)); } catch (Exception e) { continue; }
                qwords++;
                Address target = sp.getAddress(v);
                if (!mem.contains(target)) continue;
                MemoryBlock tb = mem.getBlock(target);
                if (tb == null || !tb.isExecute()) continue;
                codePtrs++;
                if (fm.getFunctionAt(target) != null) continue;
                try {
                    Function f = createFunction(target, null);
                    if (f != null) created++;
                    else failed++;
                } catch (Exception e) {
                    failed++;
                }
            }
        }
        println("qwords=" + qwords + " code_pointers=" + codePtrs + " created=" + created + " failed=" + failed);
        if (out != null) {
            try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
                w.write("qwords=" + qwords + " code_pointers=" + codePtrs + " created=" + created + " failed=" + failed);
                w.newLine();
            }
        }
    }
}
