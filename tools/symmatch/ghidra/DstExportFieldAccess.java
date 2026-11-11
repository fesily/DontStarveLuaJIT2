// Export per-function field accesses off the *pointer parameters*.
//
// Motivation: a non-virtual member's identity is largely its field access
// pattern (`*(this+0x58)` read, `*(this+0x60) = v` write).  The inventories only
// carry the immediate set, which mixes field offsets with constants and
// therefore cannot be matched.  This script takes the offsets from the
// decompiler's high P-code: for every LOAD/STORE, trace the address operand back
// through CAST/INT_ADD/PTRSUB to (base varnode, constant); if the base is a
// function parameter, record (offset, access size, read/write).
//
// Output JSONL: {"e":"<hex>","n":"<name>","ni":<count>,
//                "f":[{"o":88,"s":4,"w":0}, ...]}
//
// Usage: DstExportFieldAccess.java <out.jsonl> [addr-list-file]
//        (addr-list: one hex address per line; omit to process every function)
//@category DST
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DstExportFieldAccess extends GhidraScript {

    private static final int MAX_FIELDS = 12;

    private static boolean isParam(Varnode v) {
        // In high P-code a function parameter has no defining op and is an input.
        return v != null && !v.isConstant() && v.isInput() && v.getDef() == null;
    }

    /** Walk back from an address operand to (param varnode, constant offset). */
    private static long[] baseAndOffset(Varnode v, int depth, Varnode[] baseOut) {
        if (v == null || depth < 0) return null;
        if (isParam(v)) { baseOut[0] = v; return new long[]{0}; }
        PcodeOp def = v.getDef();
        if (def == null) return null;
        int op = def.getOpcode();
        if (op == PcodeOp.CAST || op == PcodeOp.COPY) {
            return baseAndOffset(def.getInput(0), depth - 1, baseOut);
        }
        if (op == PcodeOp.INT_ADD || op == PcodeOp.PTRSUB || op == PcodeOp.PTRADD) {
            Varnode a = def.getInput(0), b = def.getNumInputs() > 1 ? def.getInput(1) : null;
            Varnode[] inner = new Varnode[1];
            long[] base;
            if (b != null && b.isConstant()) {
                base = baseAndOffset(a, depth - 1, inner);
                if (base != null) { baseOut[0] = inner[0]; base[0] += b.getOffset(); return base; }
            }
            if (a.isConstant() && b != null) {
                base = baseAndOffset(b, depth - 1, inner);
                if (base != null) { baseOut[0] = inner[0]; base[0] += a.getOffset(); return base; }
            }
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "/tmp/fields.jsonl";
        Set<Long> only = null;
        if (args.length > 1 && !args[1].isEmpty()) {
            only = new HashSet<>();
            try (BufferedReader r = new BufferedReader(new FileReader(args[1]))) {
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    only.add(Long.parseUnsignedLong(line.replace("0x", ""), 16));
                }
            }
        }

        DecompInterface di = new DecompInterface();
        di.toggleCCode(false);
        di.toggleSyntaxTree(true);
        if (!di.openProgram(currentProgram)) { printerr("decompiler did not open"); return; }

        long funcs = 0, fields = 0, failed = 0;
        long t0 = System.currentTimeMillis();
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(out), StandardCharsets.UTF_8))) {
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext()) {
                if (monitor.isCancelled()) break;
                Function f = fit.next();
                if (f.isExternal() || f.isThunk()) continue;
                if (only != null && !only.contains(f.getEntryPoint().getOffset())) continue;
                DecompileResults dr = di.decompileFunction(f, 30, monitor);
                if (dr == null || !dr.decompileCompleted()) { failed++; continue; }
                HighFunction hf = dr.getHighFunction();
                if (hf == null) { failed++; continue; }
                funcs++;

                Set<String> seen = new LinkedHashSet<>();
                Iterator<PcodeOpAST> ops = hf.getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOpAST o = ops.next();
                    int opc = o.getOpcode();
                    if (opc != PcodeOp.LOAD && opc != PcodeOp.STORE) continue;
                    // STORE: [0]=space, [1]=addr, [2]=value ; LOAD: [0]=space,[1]=addr
                    Varnode addrV = o.getInput(1);
                    int size = (opc == PcodeOp.STORE)
                            ? o.getInput(2).getSize()
                            : o.getOutput().getSize();
                    Varnode[] base = new Varnode[1];
                    long[] off = baseAndOffset(addrV, 6, base);
                    if (off == null || off[0] < 0 || off[0] > 0x2000) continue;
                    int wr = opc == PcodeOp.STORE ? 1 : 0;
                    String key = Long.toHexString(off[0]) + ":" + size + ":" + wr;
                    if (seen.size() < MAX_FIELDS) seen.add(key);
                    fields++;
                }
                if (seen.isEmpty()) continue;
                StringBuilder sb = new StringBuilder();
                sb.append("{\"e\":\"").append(Long.toHexString(f.getEntryPoint().getOffset()))
                  .append("\",\"n\":\"").append(f.getName().replace("\"", "\\\"")).append('"');
                sb.append(",\"f\":[");
                boolean first = true;
                for (String key : seen) {
                    String[] p = key.split(":");
                    if (!first) sb.append(',');
                    sb.append("{\"o\":").append(Long.parseLong(p[0], 16))
                      .append(",\"s\":").append(p[1]).append(",\"w\":").append(p[2]).append('}');
                    first = false;
                }
                sb.append("]}");
                w.write(sb.toString());
                w.newLine();
                if (funcs % 500 == 0) {
                    println("progress functions=" + funcs + " fields=" + fields
                            + " failed=" + failed + " elapsed=" + ((System.currentTimeMillis() - t0) / 1000) + "s");
                    w.flush();
                }
            }
        } finally {
            di.dispose();
        }
        println("fieldaccess: functions=" + funcs + " fields=" + fields + " failed=" + failed + " -> " + out);
    }
}
