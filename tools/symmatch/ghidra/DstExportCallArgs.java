// Export call-site ARGUMENT signatures from the decompiler's high P-code.
//
// The instruction-window exporter (DstExportCallSites) only sees constants that
// are materialised in the caller's straight-line code.  Strings are usually
// passed as `std::string` temporaries, so the literal lives in the constructor
// call that fills the temporary, not next to the call.  This script walks the
// high P-code instead:
//
//   for each CALL op, for each argument varnode, resolve one or two levels of
//   definitions and collect
//     * constant values,
//     * string literals (a definition that loads from a constant address),
//     * the callee name when the argument is the result/parameter of another
//       call (e.g. std::string::string, operator+, c_str).
//
// Output JSONL, one line per function:
//   {"e":"<hex>","n":"<name>","sites":[{"i":0,"t":"<hex target>","ind":0,
//     "imm":["0x3"],"str":["bloom"],"via":["std::__ndk1::basic_string..."]}]}
//
// Usage: DstExportCallArgs.java <out.jsonl> [max_functions]
//@category DST
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DstExportCallArgs extends GhidraScript {

    private static final int MAX_IMM = 6;
    private static final int MAX_STR = 4;
    private static final int MAX_VIA = 3;
    private static final int DEPTH = 3;

    private Memory memory;

    private String stringAt(long v) {
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
        if (a == null) return null;
        try {
            if (!memory.contains(a)) return null;
            byte[] buf = new byte[201];
            int n = -1;
            for (int i = 0; i < buf.length; i++) {
                byte b = memory.getByte(a.add(i));
                if (b == 0) { n = i; break; }
                if (b < 0x20 || b > 0x7e) return null;
                buf[i] = b;
            }
            if (n < 3) return null;
            return new String(buf, 0, n, StandardCharsets.US_ASCII);
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

    /** Collect signature features reachable from `v` by following definitions. */
    private void trace(Varnode v, int depth, Set<Long> imms, Set<String> strs, Set<String> via) {
        if (v == null || depth < 0) return;
        if (v.isConstant()) {
            long val = v.getOffset();
            // A constant that lands inside the image is an address (string pointer,
            // table pointer).  It is meaningless across builds, so only its string
            // content is kept, never the numeric value.
            Address asAddr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(val);
            boolean isAddress = asAddr != null && memory.contains(asAddr);
            if (isAddress) {
                String s = stringAt(val);
                if (s != null && strs.size() < MAX_STR) strs.add(s);
            } else if (val > 1 && imms.size() < MAX_IMM) {
                imms.add(val);
            }
            return;
        }
        PcodeOp def = v.getDef();
        if (def == null) return;
        int op = def.getOpcode();
        if (op == PcodeOp.LOAD || op == PcodeOp.PTRSUB || op == PcodeOp.PTRADD) {
            for (int k = 0; k < def.getNumInputs(); k++) {
                trace(def.getInput(k), depth - 1, imms, strs, via);
            }
        } else if (op == PcodeOp.CALL || op == PcodeOp.CALLIND) {
            if (via.size() < MAX_VIA) {
                Varnode t = def.getInput(0);
                if (t != null && t.isAddress()) {
                    Function f = getFunctionAt(t.getAddress());
                    if (f != null) via.add(f.getName());
                }
            }
            // the ctor of a temporary carries the literal: look at its arguments
            for (int k = 1; k < def.getNumInputs() && k < 4; k++) {
                trace(def.getInput(k), depth - 1, imms, strs, via);
            }
        } else if (op == PcodeOp.CAST || op == PcodeOp.MULTIEQUAL || op == PcodeOp.COPY
                || op == PcodeOp.INT_ADD || op == PcodeOp.SUBPIECE || op == PcodeOp.PIECE) {
            for (int k = 0; k < def.getNumInputs(); k++) {
                trace(def.getInput(k), depth - 1, imms, strs, via);
            }
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "/tmp/callargs.jsonl";
        long maxFuncs = args.length > 1 ? Long.parseLong(args[1]) : Long.MAX_VALUE;
        long skipFuncs = args.length > 2 ? Long.parseLong(args[2]) : 0L;
        long budgetMs = args.length > 3 ? Long.parseLong(args[3]) * 1000L : 1500_000L;
        boolean append = args.length > 4 && args[4].equalsIgnoreCase("append");
        memory = currentProgram.getMemory();

        DecompInterface di = new DecompInterface();
        di.toggleCCode(false);
        di.toggleSyntaxTree(true);
        if (!di.openProgram(currentProgram)) {
            printerr("decompiler did not open the program");
            return;
        }

        long funcs = 0, sites = 0, failed = 0, iterated = 0;
        long t0 = System.currentTimeMillis();
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(out, append), StandardCharsets.UTF_8))) {
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext() && funcs < maxFuncs) {
                if (monitor.isCancelled()) break;
                Function f = fit.next();
                if (f.isExternal() || f.isThunk()) continue;
                if (iterated++ < skipFuncs) continue;
                DecompileResults dr = di.decompileFunction(f, 30, monitor);
                if (dr == null || !dr.decompileCompleted()) { failed++; continue; }
                HighFunction hf = dr.getHighFunction();
                if (hf == null) { failed++; continue; }
                funcs++;

                List<String> siteJson = new ArrayList<>();
                int ordinal = 0;
                Iterator<PcodeOpAST> ops = hf.getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOpAST o = ops.next();
                    int opc = o.getOpcode();
                    if (opc != PcodeOp.CALL && opc != PcodeOp.CALLIND) continue;
                    Varnode target = o.getInput(0);
                    long ta = 0;
                    boolean indirect = true;
                    if (target != null && target.isAddress()) {
                        Function cf = getFunctionAt(target.getAddress());
                        if (cf != null) {
                            Function real = cf.isThunk() ? cf.getThunkedFunction(true) : cf;
                            if (real != null && !real.isExternal()) {
                                ta = real.getEntryPoint().getOffset();
                                indirect = false;
                            }
                        }
                    }
                    Set<Long> imms = new LinkedHashSet<>();
                    Set<String> strs = new LinkedHashSet<>();
                    Set<String> via = new LinkedHashSet<>();
                    for (int k = 1; k < o.getNumInputs(); k++) {
                        trace(o.getInput(k), DEPTH, imms, strs, via);
                    }
                    if (imms.isEmpty() && strs.isEmpty()) { ordinal++; continue; }

                    StringBuilder sj = new StringBuilder();
                    sj.append("{\"i\":").append(ordinal++).append(",\"t\":\"")
                      .append(Long.toHexString(ta)).append("\",\"ind\":")
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
                    sj.append("],\"via\":[");
                    first = true;
                    for (String s : via) {
                        if (!first) sj.append(',');
                        sj.append('"').append(esc(s)).append('"');
                        first = false;
                    }
                    sj.append("]}");
                    siteJson.add(sj.toString());
                    sites++;
                }
                w.write("{\"e\":\"" + Long.toHexString(f.getEntryPoint().getOffset())
                        + "\",\"n\":\"" + esc(f.getName()) + "\",\"sites\":["
                        + String.join(",", siteJson) + "]}");
                w.newLine();
                if (funcs % 2000 == 0) {
                    long dt = System.currentTimeMillis() - t0;
                    println("progress functions=" + funcs + " sites=" + sites
                            + " failed=" + failed + " elapsed=" + (dt / 1000) + "s");
                    w.flush();
                    if (dt > budgetMs) { println("time budget reached"); break; }
                }
            }
        } finally {
            di.dispose();
        }
        println("callargs: functions=" + funcs + " sites=" + sites + " failed=" + failed
                + " -> " + out);
    }
}
