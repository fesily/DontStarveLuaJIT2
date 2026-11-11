// Export the recorded provenance of every symbol written by symmatch.
//
// Each applied name carries a plate comment of the form
//   cross-arch: <tier> | <method> A=0x<android> score=...
// which is the only authoritative record of *why* a Windows function has that
// name.  Auditing the live table requires it: the TSV files are append-only
// history and later stages overwrite earlier pairings.
//
// Usage: DstExportProvenance.java <out.tsv>
// Output: va \t plate_comment
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class DstExportProvenance extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        int rows = 0;
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (Function f : fm.getFunctions(true)) {
                if (monitor.isCancelled()) break;
                String c = listing.getComment(CommentType.EOL, f.getEntryPoint());
                if (c == null || !c.contains("cross-arch:")) {
                    c = listing.getComment(CommentType.PRE, f.getEntryPoint());
                }
                if (c == null || !c.contains("cross-arch:")) {
                    // DstApplyNames writes a PLATE comment; Ghidra exposes it
                    // through the comment API with CommentType.PLATE in newer
                    // versions and through getPlateComment in older ones
                    c = f.getComment();
                }
                if (c == null || !c.contains("cross-arch:")) continue;
                w.write("0x" + Long.toHexString(f.getEntryPoint().getOffset()) + "\t"
                        + c.replace('\n', ' ').replace('\t', ' '));
                w.newLine();
                rows++;
            }
        }
        println("provenance rows=" + rows + " -> " + args[0]);
    }
}
