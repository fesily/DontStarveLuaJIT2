// Emit the constant returned by tiny functions (`mov eax,imm; ret` /
// `movz w0,#imm; ret`). Component ids, flags and enum getters all take this
// shape, and the value is stable across builds and architectures.
//
// Usage: DstExportReturnConstants.java <out.tsv>
// Output: entry_va \t hex_value
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class DstExportReturnConstants extends GhidraScript {

    private boolean writesReturnRegister(Instruction ins, String[] names) {
        for (int op = 0; op < ins.getNumOperands(); op++) {
            Object[] objs = ins.getOpObjects(op);
            for (Object o : objs) {
                if (o instanceof Register) {
                    String n = ((Register) o).getName();
                    for (String want : names) {
                        if (n.equalsIgnoreCase(want)) return true;
                    }
                }
            }
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FunctionManager fm = currentProgram.getFunctionManager();
        String[] retRegs = {"EAX", "RAX", "W0", "X0"};
        long hits = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (Function f : fm.getFunctions(true)) {
                if (monitor.isCancelled()) break;
                long size = f.getBody().getNumAddresses();
                if (size <= 0 || size > 24) continue;
                Instruction last = null;
                long value = 0;
                boolean have = false;
                boolean movk = false;
                for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                    last = ins;
                    String mn = ins.getMnemonicString().toUpperCase();
                    java.util.List<Long> scalars = new java.util.ArrayList<>();
                    for (int op = 0; op < ins.getNumOperands(); op++) {
                        for (Object o : ins.getOpObjects(op)) {
                            if (o instanceof Scalar) scalars.add(((Scalar) o).getUnsignedValue());
                        }
                    }
                    if (scalars.isEmpty()) continue;
                    if (mn.startsWith("MOVK")) {
                        // movk w0,#hi, LSL #16  -> the second scalar is the shift
                        long imm = scalars.get(0);
                        long shift = scalars.size() > 1 ? scalars.get(1) : 16;
                        value |= imm << shift;
                        have = true;
                        movk = true;
                    } else if (mn.startsWith("MOV") || mn.startsWith("MOVZ") || mn.startsWith("MOVN")) {
                        value = scalars.get(0);
                        have = true;
                    }
                }
                if (last == null || !last.getMnemonicString().toUpperCase().startsWith("RET")) continue;
                if (!have) continue;
                if (value == 0 || (value >>> 32) != 0) continue;
                // a plain truncated constant with no movk is usually a flag, not
                // an id; keep it, the caller decides
                w.write("0x" + Long.toHexString(f.getEntryPoint().getOffset()) + "\t"
                        + Long.toHexString(value) + "\t" + ((movk || value > 0xffffL) ? "id" : "flag"));
                w.newLine();
                hits++;
            }
        }
        println("return-constant functions=" + hits + " -> " + args[0]);
    }
}
