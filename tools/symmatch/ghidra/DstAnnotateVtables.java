// Annotate vtable slots for cross-architecture (Android Itanium -> MSVC) matching.
//
// Input:  a TSV produced by DstExportVtablesViaRefs (start \t count \t slot,slot,...)
// Output: start \t count \t slot:size:kind:str, ...
//   kind = E (empty body <= 6 bytes), P (jmp thunk / purecall), N (implementation)
//   str  = first string literal referenced by the slot function (may be empty)
//
// Vtable slot targets are function entries by construction, so missing ones are
// created before measuring.  This matters: Ghidra's auto-analysis leaves many
// tiny virtuals (10-byte getters, empty stubs) undefined, which silently breaks
// every shape/fingerprint comparison downstream.
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class DstAnnotateVtables extends GhidraScript {

    private boolean isExec(long a) {
        Memory mem = currentProgram.getMemory();
        MemoryBlock b = mem.getBlock(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a));
        return b != null && b.isExecute();
    }

    private String stringAt(Address a) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 96; i++) {
                int c = currentProgram.getMemory().getByte(a.add(i)) & 0xff;
                if (c == 0) break;
                if (c < 9 || (c > 13 && c < 32) || c > 126) return null;
                sb.append((char) c);
            }
            return sb.length() >= 3 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Nearest NUL-terminated source path in front of a run. TU strings
     * (`..\\source\\game\\components\\GroundCreep.cpp`) are emitted by assert
     * macros right next to the vtables of that translation unit, which gives a
     * class hint for tables that carry no name getter.
     */
    private String precedingFile(Address start) {
        Memory mem = currentProgram.getMemory();
        for (int back = 0; back < 0x800; back += 1) {
            Address a = start.subtract(back);
            if (!mem.contains(a)) return "";
            try {
                if ((mem.getByte(a) & 0xff) != 0) continue;
            } catch (Exception e) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            try {
                for (int i = 1; i <= 160; i++) {
                    int c = mem.getByte(a.add(i)) & 0xff;
                    if (c == 0) break;
                    if (c < 9 || (c > 13 && c < 32) || c > 126) { sb.setLength(0); break; }
                    sb.append((char) c);
                }
            } catch (Exception e) {
                return "";
            }
            String t = sb.toString();
            if (t.contains(".cpp") || t.endsWith(".h") || t.contains(".hpp")) return t;
        }
        return "";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String in = args[0];
        String out = args[1];
        int created = 0;
        int slots = 0;
        try (BufferedReader r = new BufferedReader(new FileReader(in));
             BufferedWriter w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\t");
                if (parts.length < 3) continue;
                String[] sa = parts[parts.length - 1].split(",");
                long runStart = Long.parseUnsignedLong(parts[0].replace("ptr_", "").replace("0x", ""), 16);
                String fileHint = precedingFile(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(runStart));
                StringBuilder sb = new StringBuilder(parts[0]).append('\t').append(sa.length).append('\t');
                for (int k = 0; k < sa.length; k++) {
                    String s = sa[k].trim();
                    if (s.isEmpty()) continue;
                    if ("0x0".equals(s) || "0".equals(s)) {
                        sb.append("0:0:Z::").append(k + 1 < sa.length ? "," : "");
                        continue;
                    }
                    long a = Long.parseUnsignedLong(s.replace("0x", ""), 16);
                    Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
                    String kind = "?";
                    String str = "";
                    long size = 0;
                    if (isExec(a)) {
                        slots++;
                        Function f = getFunctionAt(addr);
                        if (f == null) {
                            try {
                                f = createFunction(addr, null);
                                if (f != null) created++;
                            } catch (Exception e) {
                                f = null;
                            }
                        }
                        if (f != null) {
                            size = f.getBody().getNumAddresses();
                            Instruction ins = getInstructionAt(addr);
                            if (ins != null) {
                                String mn = ins.getMnemonicString();
                                if ("JMP".equals(mn) || "RET".equals(mn) || "RETN".equals(mn)) {
                                    boolean memOperand = false;
                                    for (int op = 0; op < ins.getNumOperands(); op++) {
                                        for (Object o : ins.getOpObjects(op)) {
                                            if (o instanceof ghidra.program.model.address.Address) {
                                                memOperand = true;
                                            }
                                        }
                                    }
                                    kind = ("JMP".equals(mn) && memOperand) ? "P" : "E";
                                } else {
                                    // tiny body that only loads an address and returns
                                    kind = size <= 6 ? "E" : "N";
                                }
                                if ("N".equals(kind) || "?".equals(kind)) {
                                    for (Instruction it : currentProgram.getListing().getInstructions(addr, true)) {
                                        for (int op = 0; op < it.getNumOperands(); op++) {
                                            for (Object o : it.getOpObjects(op)) {
                                                Address target = null;
                                                if (o instanceof Scalar) {
                                                    long v = ((Scalar) o).getUnsignedValue();
                                                    target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
                                                } else if (o instanceof Address) {
                                                    target = (Address) o;
                                                }
                                                if (target == null) continue;
                                                MemoryBlock b = currentProgram.getMemory().getBlock(target);
                                                if (b == null || b.isExecute()) continue;
                                                String s2 = stringAt(target);
                                                if (s2 != null) {
                                                    str = s2;
                                                    break;
                                                }
                                            }
                                            if (!str.isEmpty()) break;
                                        }
                                        if (!str.isEmpty()) break;
                                    }
                                }
                            }
                        }
                    }
                    // `mov eax, imm32; ret` (MSVC) / `mov w0, #imm; ret` (arm64):
                    // GetComponentName-style ID getters and bool flags. The value
                    // is stable across builds and unique per component id.
                    String konst = "";
                    if (size > 0 && size <= 16) {
                        Instruction first = getInstructionAt(addr);
                        if (first != null && "MOV".equals(first.getMnemonicString())) {
                            for (int op = 0; op < first.getNumOperands(); op++) {
                                for (Object o : first.getOpObjects(op)) {
                                    if (o instanceof Scalar) {
                                        long v = ((Scalar) o).getUnsignedValue();
                                        if (v > 0 && v < 0x100000L) konst = Long.toHexString(v);
                                    }
                                }
                            }
                        }
                    }
                    // addr:size:kind:const:str  -- const before str, because the
                    // literal itself may contain ':'
                    String token = Long.toHexString(a) + ":" + size + ":" + kind + ":" + konst + ":"
                            + str.replace("\t", " ").replace("\r", " ")
                                 .replace("\n", " ").replace(",", ";").replace(":", ";");
                    sb.append(token);
                    if (k + 1 < sa.length) sb.append(',');
                }
                w.write(sb.toString());
                w.write('\t');
                w.write(fileHint.replace('\t', ' '));
                w.newLine();
            }
        }
        println("annotated slots=" + slots + " functions_created=" + created + " -> " + out);
    }
}
