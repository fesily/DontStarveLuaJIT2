// Query an H2 BSim database for every function of the current program and dump the
// top-N neighbours to TSV. Source side = currentProgram (Windows), targets = database.
// Usage: DstBsimQuery.java <dbPathWithoutExtension> <out.tsv> [minInstr] [maxPerFunc] [thresh]
// Output columns: source_entry \t source_name \t target_entry \t target_name \t similarity \t significance
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DstBsimQuery extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = String.join(",", getScriptArgs()).split(",");
        if (args.length < 2) {
            printerr("usage: DstBsimQuery.java <dbPathWithoutExtension> <out.tsv> [minInstr] [maxPerFunc] [thresh]");
            return;
        }
        File dbFile = new File(args[0]).getAbsoluteFile();
        String outPath = args[1];
        int minInstr = args.length > 2 ? Integer.parseInt(args[2]) : 8;
        int maxPerFunc = args.length > 3 ? Integer.parseInt(args[3]) : 5;
        double thresh = args.length > 4 ? Double.parseDouble(args[4]) : 0.5;

        BSimServerInfo serverInfo = new BSimServerInfo(dbFile.getAbsolutePath());
        try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, false)) {
            if (!db.initialize()) {
                printerr("init failed: " + db.getLastError().message);
                return;
            }
            DatabaseInformation info = db.getInfo();
            GenSignatures gensig = new GenSignatures(info.trackcallgraph);
            int rows = 0, matched = 0;
            try {
                gensig.setVectorFactory(db.getLSHVectorFactory());
                gensig.openProgram(currentProgram, null, null, null, null, null);

                List<Function> keep = new ArrayList<>();
                FunctionManager fman = currentProgram.getFunctionManager();
                for (Function f : fman.getFunctions(true)) {
                    if (monitor.isCancelled()) break;
                    if (f.isExternal() || f.isThunk()) continue;
                    if (instructionCount(f) < minInstr) continue;
                    keep.add(f);
                }
                println("scanning " + keep.size() + " source functions");
                Iterator<Function> iter = keep.iterator();
                gensig.scanFunctions(iter, keep.size(), monitor);

                DescriptionManager manager = gensig.getDescriptionManager();
                QueryNearest query = new QueryNearest();
                query.manage = manager;
                query.max = maxPerFunc;
                query.thresh = thresh;
                query.signifthresh = 0.0;

                ResponseNearest resp = query.execute(db);
                if (resp == null) {
                    printerr("query failed: " + db.getLastError().message);
                    return;
                }

                try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
                    Iterator<SimilarityResult> results = resp.result.iterator();
                    while (results.hasNext()) {
                        SimilarityResult result = results.next();
                        FunctionDescription base = result.getBase();
                        String srcEntry = hex(base.getAddress());
                        String srcName = base.getFunctionName();
                        boolean any = false;
                        Iterator<SimilarityNote> notes = result.iterator();
                        while (notes.hasNext()) {
                            SimilarityNote note = notes.next();
                            FunctionDescription tgt = note.getFunctionDescription();
                            ExecutableRecord exe = tgt.getExecutableRecord();
                            w.write(srcEntry + "\t" + safe(srcName) + "\t" + hex(tgt.getAddress()) + "\t"
                                    + safe(tgt.getFunctionName()) + "\t"
                                    + String.format("%.4f", note.getSimilarity()) + "\t"
                                    + String.format("%.4f", note.getSignificance()) + "\t"
                                    + safe(exe.getNameExec()));
                            w.newLine();
                            rows++;
                            any = true;
                        }
                        if (any) matched++;
                    }
                }
                println("query done: source_functions=" + manager.numFunctions() + " matched=" + matched
                        + " rows=" + rows + " out=" + outPath);
            }
            finally {
                gensig.dispose();
            }
        }
    }

    private int instructionCount(Function f) {
        int n = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins != null) n++;
        }
        return n;
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    private static String safe(String s) {
        return s == null ? "" : s.replace('\t', ' ').replace('\n', ' ');
    }
}
