// Export per-call-site argument fingerprints.
//
// Motivation: a callee frequently owns no literal of its own, but the *caller*
// passes the same literal or immediate at that call site on both builds
// (`SetParam("bloom", 0.4f)`).  Attributing the literal to the call site instead
// of the function makes such callees identifiable, which the function-level
// string channel cannot do.
//
// Output JSONL, one line per function:
//   {"e":<addr>,"n":<name>,"ni":<instr>,"sites":[{"i":<ordinal>,"t":<target>,
//     "ind":<0|1>,"imm":[...],"str":[...]}, ...]}
// A site's fingerprint is the immediates and string literals seen in the
// instruction window before the call, bounded by the previous call or by 16
// instructions, whichever comes first.
//
// Usage: DstExportCallSites.java <out.jsonl>
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
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

public class DstExportCallSites extends GhidraScript {

    private static final int WINDOW = 16;
    private static final int MAX_IMM = 6;
    private static final int MAX_STR = 4;

    private Memory memory;
    private ReferenceManager refMgr;

    private String stringAt(Address to) {
        try {
            byte[] buf = new byte[201];
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

    private static String esc(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(' ');
            else b.append(c);
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "/tmp/callsites.jsonl";
        memory = currentProgram.getMemory();
        refMgr = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        long funcs = 0, sites = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(out), StandardCharsets.UTF_8))) {
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext()) {
                if (monitor.isCancelled()) break;
                Function f = fit.next();
                if (f.isExternal() || f.isThunk()) continue;
                funcs++;
                StringBuilder sb = new StringBuilder();
                sb.append("{\"e\":\"").append(Long.toHexString(f.getEntryPoint().getOffset()))
                  .append("\",\"n\":\"").append(esc(f.getName())).append('"');

                List<String> siteJson = new ArrayList<>();
                InstructionIterator ii = listing.getInstructions(f.getBody(), true);
                List<Instruction> backlog = new ArrayList<>();
                int ordinal = 0;
                while (ii.hasNext()) {
                    Instruction ins = ii.next();
                    boolean isCall = ins.getFlowType().isCall();
                    if (isCall) {
                        Set<Long> imms = new LinkedHashSet<>();
                        Set<String> strs = new LinkedHashSet<>();
                        for (int k = backlog.size() - 1; k >= 0 && imms.size() < MAX_IMM; k--) {
                            Instruction b = backlog.get(k);
                            for (int op = 0; op < b.getNumOperands(); op++) {
                                for (Object o : b.getOpObjects(op)) {
                                    if (o instanceof Scalar) {
                                        long v = ((Scalar) o).getUnsignedValue();
                                        if (v > 1 && !inMemory(v) && imms.size() < MAX_IMM) imms.add(v);
                                    }
                                }
                            }
                            for (Reference r : refMgr.getReferencesFrom(b.getAddress())) {
                                Address to = r.getToAddress();
                                if (to == null) continue;
                                String s = stringAt(to);
                                if (s != null && strs.size() < MAX_STR) strs.add(s);
                            }
                        }
                        long target = 0;
                        boolean indirect = true;
                        for (Reference r : refMgr.getReferencesFrom(ins.getAddress())) {
                            if (!r.getReferenceType().isCall()) continue;
                            Function cf = currentProgram.getFunctionManager()
                                    .getFunctionAt(r.getToAddress());
                            if (cf == null) continue;
                            Function real = cf.isThunk() ? cf.getThunkedFunction(true) : cf;
                            if (real != null && !real.isExternal()) {
                                target = real.getEntryPoint().getOffset();
                                indirect = false;
                            }
                        }
                        StringBuilder sj = new StringBuilder();
                        sj.append("{\"i\":").append(ordinal++).append(",\"t\":\"")
                          .append(Long.toHexString(target)).append("\",\"ind\":")
                          .append(indirect ? 1 : 0).append(",\"imm\":[");
                        boolean first = true;
                        for (long v : imms) {
                            if (!first) sj.append(',');
                            sj.append('"').append(Long.toHexString(v)).append('"');
                            first = false;
                        }
                        sj.append("],\"str\":[");
                        first = true;
                        for (String s : strs) {
                            if (!first) sj.append(',');
                            sj.append('"').append(esc(s)).append('"');
                            first = false;
                        }
                        sj.append("]}");
                        siteJson.add(sj.toString());
                        sites++;
                        backlog.clear();
                        continue;
                    }
                    backlog.add(ins);
                    if (backlog.size() > WINDOW) backlog.remove(0);
                }
                sb.append(",\"sites\":[").append(String.join(",", siteJson)).append("]}");
                w.write(sb.toString());
                w.newLine();
            }
        }
        println("callsites: functions=" + funcs + " sites=" + sites + " -> " + out);
    }

    private boolean inMemory(long v) {
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
        if (a == null) return false;
        try {
            return memory.contains(a);
        } catch (Exception e) {
            return false;
        }
    }
}
