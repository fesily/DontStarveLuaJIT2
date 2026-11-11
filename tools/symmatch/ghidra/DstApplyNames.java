// Apply cross-architecture symbol transfers produced by tools/symmatch.
// Usage: DstApplyNames.java <matches.tsv> <dry|apply>
// TSV columns: entry_addr_hex \t name \t tier \t note   (no header)
// Only existing functions are renamed; nothing is created. Idempotent.
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class DstApplyNames extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: DstApplyNames.java <matches.tsv> <dry|apply>");
            return;
        }
        String tsv = args[0];
        boolean apply = "apply".equalsIgnoreCase(args[1]);

        Listing listing = currentProgram.getListing();
        SymbolTable symtab = currentProgram.getSymbolTable();
        FunctionTagManager tagMgr = currentProgram.getFunctionManager().getFunctionTagManager();

        int rows = 0, renamed = 0, skipped = 0, missing = 0, conflict = 0, failed = 0, folded = 0;
        Map<String, Integer> byTier = new LinkedHashMap<>();
        StringBuilder samples = new StringBuilder();

        try (BufferedReader r = new BufferedReader(new FileReader(tsv, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (monitor.isCancelled()) break;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] f = line.split("\t");
                if (f.length < 3) continue;
                rows++;
                long entry = Long.parseUnsignedLong(f[0].replace("0x", ""), 16);
                String name = f[1];
                String tier = f[2];
                String note = f.length > 3 ? f[3] : "";
                byTier.merge(tier, 1, Integer::sum);

                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(entry);
                Function func = currentProgram.getFunctionManager().getFunctionAt(a);
                if (func == null) {
                    missing++;
                    if (samples.length() < 4000) samples.append("MISSING ").append(f[0]).append(' ').append(name).append('\n');
                    continue;
                }
                // Names arrive either plain ("Save") or namespace qualified
                // ("SimLuaProxy::GetScreenPos"); rebuild the namespace chain.
                String[] parts = name.split("::");
                Namespace ns = currentProgram.getGlobalNamespace();
                for (int i = 0; i < parts.length - 1; i++) {
                    if (parts[i].isEmpty()) continue;
                    Namespace child = symtab.getNamespace(parts[i], ns);
                    if (child == null) {
                        child = symtab.createNameSpace(ns, parts[i], SourceType.USER_DEFINED);
                    }
                    ns = child;
                }
                String base = parts[parts.length - 1];
                if (base.equals(func.getName()) && ns.equals(func.getParentNamespace())) {
                    skipped++;
                    continue;
                }

                boolean dup = false;
                java.util.List<Symbol> existing = symtab.getSymbols(base, ns);
                for (Symbol s : existing) {
                    if (!s.getAddress().equals(a)) {
                        dup = true;
                        break;
                    }
                }
                if (dup) {
                    // ICF folds identical implementations (every empty override of
                    // cEntityComponent::PostConstruction, for example) into one
                    // address, but the binary still holds one vtable slot per
                    // class. Name the extra copies <base>_<addr> so they stay
                    // attributable instead of silently unnamed.
                    boolean named = false;
                    for (int k = 0; k < 3 && !named; k++) {
                        String alt = base + "_" + Long.toHexString(entry & 0xfffffL);
                        if (k == 1) alt = base + "_" + Long.toHexString(entry);
                        if (k == 2) alt = base + "_folded";
                        boolean taken = false;
                        for (Symbol s : symtab.getSymbols(alt, ns)) {
                            if (!s.getAddress().equals(a)) {
                                taken = true;
                                break;
                            }
                        }
                        if (taken) continue;
                        if (apply) {
                            try {
                                if (!func.getParentNamespace().equals(ns)) {
                                    func.setParentNamespace(ns);
                                }
                                func.setName(alt, SourceType.USER_DEFINED);
                                FunctionTag tag = tagMgr.getFunctionTag("sym:" + tier);
                                if (tag == null) tag = tagMgr.createFunctionTag("sym:" + tier, "cross-arch symbol migration");
                                func.addTag(tag.getName());
                                listing.setComment(a, ghidra.program.model.listing.CommentType.PLATE,
                                        "cross-arch: " + tier + " | folded copy of " + name + (note.isEmpty() ? "" : " | " + note));
                            } catch (Exception e) {
                                failed++;
                                break;
                            }
                        }
                        folded++;
                        named = true;
                    }
                    if (!named) {
                        conflict++;
                        if (samples.length() < 4000) samples.append("CONFLICT ").append(f[0]).append(' ').append(name).append('\n');
                    }
                    continue;
                }
                if (!apply) {
                    renamed++;
                    continue;
                }
                try {
                    if (!func.getParentNamespace().equals(ns)) {
                        func.setParentNamespace(ns);
                    }
                    func.setName(base, SourceType.USER_DEFINED);
                    FunctionTag tag = tagMgr.getFunctionTag("sym:" + tier);
                    if (tag == null) tag = tagMgr.createFunctionTag("sym:" + tier, "cross-arch symbol migration");
                    func.addTag(tag.getName());
                    String comment = "cross-arch: " + tier + (note.isEmpty() ? "" : " | " + note);
                    listing.setComment(a, ghidra.program.model.listing.CommentType.PLATE, comment);
                    renamed++;
                } catch (Exception e) {
                    failed++;
                    if (samples.length() < 4000) samples.append("FAILED ").append(f[0]).append(' ').append(name)
                            .append(" : ").append(e.getMessage()).append('\n');
                }
            }
        }

        println("apply mode=" + (apply ? "apply" : "dry") + " program=" + currentProgram.getName()
                + " rows=" + rows + " renamed=" + renamed + " skipped=" + skipped
                + " missing=" + missing + " conflict=" + conflict + " folded=" + folded + " failed=" + failed
                + " by_tier=" + byTier);
        if (samples.length() > 0) println("--- samples ---\n" + samples);
    }
}
