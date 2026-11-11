// Export what a PDB needs: PE section headers + public symbols (rva + name).
// Usage: DstExportPdb.java <out_sections.tsv> <out_publics.tsv>
// sections: index\tname\trva\tvsize\trawsize\trawptr\tcharacteristics
// publics:  rva\tname
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class DstExportPdb extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: DstExportPdb.java <out_sections.tsv> <out_publics.tsv>");
            return;
        }
        Memory mem = currentProgram.getMemory();
        long base = currentProgram.getImageBase().getOffset();

        // --- PE section headers (read straight from the mapped headers) ---
        Address hdr = currentProgram.getImageBase();
        int lfanew = mem.getInt(hdr.add(0x3c));
        Address pe = hdr.add(lfanew);
        int nsec = mem.getShort(pe.add(6)) & 0xffff;
        int optsz = mem.getShort(pe.add(20)) & 0xffff;
        Address sec0 = pe.add(24 + optsz);

        int written = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            w.write("# index\tname\trva\tvsize\trawsize\trawptr\tcharacteristics\n");
            for (int i = 0; i < nsec; i++) {
                Address s = sec0.add((long) i * 40);
                StringBuilder nm = new StringBuilder();
                for (int k = 0; k < 8; k++) {
                    int c = mem.getByte(s.add(k)) & 0xff;
                    if (c == 0) break;
                    nm.append((char) c);
                }
                long vsize = mem.getInt(s.add(8)) & 0xffffffffL;
                long rva = mem.getInt(s.add(12)) & 0xffffffffL;
                long rawsize = mem.getInt(s.add(16)) & 0xffffffffL;
                long rawptr = mem.getInt(s.add(20)) & 0xffffffffL;
                long chars = mem.getInt(s.add(36)) & 0xffffffffL;
                w.write((i + 1) + "\t" + nm + "\t" + rva + "\t" + vsize + "\t"
                        + rawsize + "\t" + rawptr + "\t" + chars);
                w.newLine();
                written++;
            }
        }

        // --- public symbols: every user-named, non-external function ---
        int pubs = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[1]), StandardCharsets.UTF_8))) {
            w.write("# rva\tname\n");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                if (f.isExternal() || f.isThunk()) continue;
                Symbol sym = f.getSymbol();
                SourceType src = sym == null ? SourceType.DEFAULT : sym.getSource();
                if (src == SourceType.DEFAULT) continue;
                String name = f.getName(true);
                if (name == null || name.isEmpty()) continue;
                long rva = f.getEntryPoint().getOffset() - base;
                if (rva < 0 || rva > 0xffffffffL) continue;
                w.write(rva + "\t" + name);
                w.newLine();
                pubs++;
            }
        }
        println("pdb export: sections=" + written + " publics=" + pubs);
    }
}
