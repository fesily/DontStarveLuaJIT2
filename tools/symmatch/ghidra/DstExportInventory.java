// Export a per-function feature inventory for cross-architecture symbol matching.
// Usage: DstExportInventory.java <out.jsonl>
// One JSON object per line, no header. See tools/symmatch/README.md for the schema.
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class DstExportInventory extends GhidraScript {

    private static final int MAX_IMM_SEQ = 64;

    private long tailCallsTotal = 0;

    private static final int MAX_STRINGS = 256;
    private static final int MAX_IMMS = 48;
    private static final int MAX_DREFS = 64;
    private static final int MAX_STR_LEN = 160;
    private static final int MAX_EXTS = 32;
    // Linkage normalization counters (see README "Linkage normalization"):
    // raw = every call reference as Ghidra recorded it (may point at a PLT stub)
    // folded = raw target resolved through a thunk to a local function body
    // ext = call targets that are imports (no local body, identity only)
    // ind = indirect calls (COMPUTED_CALL / no reference) - deliberately NOT an edge

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DstExportInventory.java <out.jsonl>");
            return;
        }
        String outPath = args[0];

        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Memory memory = currentProgram.getMemory();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

        int total = 0, withStrings = 0, withImms = 0;
        long t0 = System.currentTimeMillis();

        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                if (func.isExternal() || func.isThunk()) continue;
                total++;

                int ninstr = 0;
                Set<String> strings = new LinkedHashSet<>();
                Set<Long> imms = new TreeSet<>();
                List<Long> immSeq = new ArrayList<>();   // in instruction order
                Set<Long> drefs = new TreeSet<>();
                Set<String> extNames = new TreeSet<>();
                List<Long> callees = new ArrayList<>();
                int rawCalls = 0, foldedThunks = 0, extCalls = 0, indirectCalls = 0;
                int tailCalls = 0;

                InstructionIterator ii = listing.getInstructions(func.getBody(), true);
                while (ii.hasNext()) {
                    Instruction ins = ii.next();
                    ninstr++;
                    for (int op = 0; op < ins.getNumOperands(); op++) {
                        Object[] objs = ins.getOpObjects(op);
                        for (Object o : objs) {
                            if (o instanceof Scalar) {
                                long v = ((Scalar) o).getUnsignedValue();
                                if (imms.size() < MAX_IMMS && !inMemory(memory, v)) {
                                    imms.add(v);
                                }
                                // ordered sequence for LCS-style comparison: an
                                // inlined callee inserts a contiguous chunk, so
                                // order survives where the set does not
                                if (immSeq.size() < MAX_IMM_SEQ && v != 0 && v != 1
                                        && !inMemory(memory, v)
                                        && (immSeq.isEmpty() || immSeq.get(immSeq.size() - 1) != v)) {
                                    immSeq.add(v);
                                }
                            }
                        }
                    }
                    if (ins.getFlowType().isCall()) {
                        Reference[] callRefs = refMgr.getReferencesFrom(ins.getAddress());
                        boolean anyRef = false;
                        for (Reference ref : callRefs) {
                            if (!ref.getReferenceType().isCall()) continue;
                            anyRef = true;
                            rawCalls++;
                            Function callee = currentProgram.getFunctionManager()
                                    .getFunctionAt(ref.getToAddress());
                            if (callee == null) continue;
                            // Linkage normalization: a PIC build routes internal calls
                            // through a PLT stub whose target is either a local body or
                            // an imported symbol. Fold to the body only when it is a
                            // defined, non-external function of this program; otherwise
                            // keep the identity only (never invent a local callee).
                            Function real = callee.isThunk() ? callee.getThunkedFunction(true) : callee;
                            if (real != null && !real.isExternal() && !real.isThunk()) {
                                if (callee.isThunk()) foldedThunks++;
                                callees.add(real.getEntryPoint().getOffset());
                            } else {
                                extCalls++;
                                String extName = (real != null ? real.getName() : callee.getName());
                                if (extName != null && !extName.isEmpty()
                                        && !extName.startsWith("FUN_") && extNames.size() < MAX_EXTS) {
                                    extNames.add(extName);
                                }
                            }
                        }
                        if (!anyRef) indirectCalls++;   // COMPUTED_CALL, target unknown
                        continue;
                    }
                    // Tail call: `jmp fn` where the target is a function entry.
                    // Without this the callee graph misses most of the code that
                    // is only reached through tail-call optimisation, which is
                    // exactly where .pdata-only functions live.
                    if (ins.getFlowType().isJump()) {
                        for (Reference ref : refMgr.getReferencesFrom(ins.getAddress())) {
                            if (!ref.getReferenceType().isJump()) continue;
                            Function target = currentProgram.getFunctionManager()
                                    .getFunctionAt(ref.getToAddress());
                            if (target == null || target.isExternal()) continue;
                            if (target.getEntryPoint().equals(func.getEntryPoint())) continue;
                            callees.add(target.getEntryPoint().getOffset());
                            tailCalls++;
                            tailCallsTotal++;
                        }
                    }
                    Reference[] refs = refMgr.getReferencesFrom(ins.getAddress());
                    for (Reference ref : refs) {
                        Address to = ref.getToAddress();
                        if (to == null) continue;
                        MemoryBlock blk = memory.getBlock(to);
                        if (blk == null) continue;
                        if (blk.isExecute()) continue;
                        if (drefs.size() < MAX_DREFS) drefs.add(to.getOffset());
                        if (strings.size() < MAX_STRINGS) {
                            String s = stringAt(to);
                            if (s != null) {
                                strings.add(s);
                            } else {
                                // one level of indirection: the reference target is
                                // a table of `char*` (luaL_Reg-like arrays, static
                                // name tables, command lists).  Without this the
                                // strings of table-driven code are never attributed
                                // to the function that owns the table.
                                for (int k = 0; k < 48 && strings.size() < MAX_STRINGS; k++) {
                                    long v;
                                    try {
                                        v = memory.getLong(to.add(k * 8L));
                                    } catch (Exception e) {
                                        break;
                                    }
                                    if (v == 0) break;
                                    Address sp2 = currentProgram.getAddressFactory()
                                            .getDefaultAddressSpace().getAddress(v);
                                    if (sp2 == null || !memory.contains(sp2)) break;
                                    MemoryBlock b2 = memory.getBlock(sp2);
                                    if (b2 == null || b2.isExecute()) break;
                                    String s2 = stringAt(sp2);
                                    if (s2 != null) strings.add(s2);
                                }
                            }
                        }
                    }
                }

                int nbb = 0;
                long nedges = 0;
                try {
                    CodeBlockIterator bIt = blockModel.getCodeBlocksContaining(func.getBody(), monitor);
                    while (bIt.hasNext()) {
                        CodeBlock bb = bIt.next();
                        nbb++;
                        CodeBlockReferenceIterator dIt = bb.getDestinations(monitor);
                        while (dIt.hasNext()) {
                            dIt.next();
                            nedges++;
                        }
                    }
                } catch (Exception e) {
                    if (nbb == 0) nbb = 1;
                }
                int cyclo = (int) Math.max(1, nedges - nbb + 2);

                if (!strings.isEmpty()) withStrings++;
                if (!imms.isEmpty()) withImms++;

                StringBuilder sb = new StringBuilder(256);
                sb.append("{\"e\":\"").append(hex(func.getEntryPoint().getOffset())).append('"');
                sb.append(",\"n\":\"").append(jsonEscape(func.getName())).append('"');
                sb.append(",\"q\":\"").append(jsonEscape(func.getName(true))).append('"');
                sb.append(",\"sz\":").append(func.getBody().getNumAddresses());
                sb.append(",\"ni\":").append(ninstr);
                sb.append(",\"nb\":").append(nbb);
                sb.append(",\"ne\":").append(nedges);
                sb.append(",\"cx\":").append(cyclo);
                sb.append(",\"str\":[");
                boolean first = true;
                for (String s : strings) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append(jsonQuote(s));
                }
                sb.append(']');
                sb.append(",\"imm\":[");
                first = true;
                for (Long v : imms) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append('"').append(hex(v)).append('"');
                }
                sb.append(']');
                sb.append(",\"imq\":[");
                first = true;
                for (Long v : immSeq) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append('"').append(hex(v)).append('"');
                }
                sb.append(']');
                sb.append(",\"dr\":[");
                first = true;
                for (Long v : drefs) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append('"').append(hex(v)).append('"');
                }
                sb.append(']');
                sb.append(",\"ln\":[").append(rawCalls).append(',').append(foldedThunks)
                  .append(',').append(extCalls).append(',').append(indirectCalls).append(']');
                sb.append(",\"ce\":[");
                first = true;
                for (String e : extNames) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append(jsonQuote(e));
                }
                sb.append(']');
                sb.append(",\"cal\":[");
                first = true;
                Set<Long> uniqCal = new TreeSet<>(callees);
                for (Long v : uniqCal) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append('"').append(hex(v)).append('"');
                }
                sb.append("]}");
                w.write(sb.toString());
                w.newLine();
            }
        }

        println("inventory: tailcalls=" + tailCallsTotal + " program=" + currentProgram.getName() + " functions=" + total
                + " with_strings=" + withStrings + " with_imms=" + withImms
                + " secs=" + ((System.currentTimeMillis() - t0) / 1000)
                + " out=" + outPath);
    }

    private boolean inMemory(Memory memory, long v) {
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            return memory.contains(a);
        } catch (Exception e) {
            return false;
        }
    }

    // Memory-based: ELF .rodata strings are frequently left undefined by analysis.
    private String stringAt(Address to) {
        Memory memory = currentProgram.getMemory();
        try {
            byte[] buf = new byte[MAX_STR_LEN + 1];
            int n = -1;
            for (int i = 0; i < buf.length; i++) {
                byte b = memory.getByte(to.add(i));
                if (b == 0) { n = i; break; }
                if (b < 0x20 || b > 0x7e) return null;
                buf[i] = b;
            }
            if (n < 3) return null;
            return new String(buf, 0, n, java.nio.charset.StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return null;
        }
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    private static String jsonQuote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
