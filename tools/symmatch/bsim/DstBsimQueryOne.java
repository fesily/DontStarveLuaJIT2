// Query one function against an H2 BSim database and print the top matches.
// Usage: DstBsimQueryOne.java <dbPath> <address> [max]
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.File;
import java.util.Iterator;

public class DstBsimQueryOne extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = String.join(",", getScriptArgs()).split(",");
        if (args.length < 2) {
            printerr("usage: DstBsimQueryOne.java <dbPath> <address> [max]");
            return;
        }
        File dbFile = new File(args[0]).getAbsoluteFile();
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(args[1].replace("0x", ""), 16));
        int max = args.length > 2 ? Integer.parseInt(args[2]) : 8;
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            printerr("no function at " + args[1]);
            return;
        }
        BSimServerInfo serverInfo = new BSimServerInfo(dbFile.getAbsolutePath());
        try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, false)) {
            if (!db.initialize()) {
                printerr("init failed: " + db.getLastError().message);
                return;
            }
            GenSignatures gensig = new GenSignatures(false);
            try {
                gensig.setVectorFactory(db.getLSHVectorFactory());
                gensig.openProgram(currentProgram, null, null, null, null, null);
                gensig.scanFunction(func);
                DescriptionManager manager = gensig.getDescriptionManager();
                QueryNearest query = new QueryNearest();
                query.manage = manager;
                query.max = max;
                query.thresh = 0.0;
                query.signifthresh = 0.0;
                ResponseNearest resp = query.execute(db);
                if (resp == null) {
                    printerr("query failed: " + db.getLastError().message);
                    return;
                }
                int ninstr = 0;
                for (ghidra.program.model.listing.Instruction ins : currentProgram.getListing()
                        .getInstructions(func.getBody(), true)) {
                    if (ins != null) ninstr++;
                }
                println("SOURCE " + func.getName() + " @" + addr + " instrs=" + ninstr);
                Iterator<SimilarityResult> results = resp.result.iterator();
                while (results.hasNext()) {
                    SimilarityResult r = results.next();
                    Iterator<SimilarityNote> notes = r.iterator();
                    while (notes.hasNext()) {
                        SimilarityNote n = notes.next();
                        FunctionDescription t = n.getFunctionDescription();
                        println(String.format("  %-46s @0x%x sim=%.3f sig=%.1f",
                                t.getFunctionName(), t.getAddress(), n.getSimilarity(), n.getSignificance()));
                    }
                }
            }
            finally {
                gensig.dispose();
            }
        }
    }
}
