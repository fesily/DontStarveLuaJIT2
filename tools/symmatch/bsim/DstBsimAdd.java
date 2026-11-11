// Generate BSim signatures for the current program and insert them into an H2 database.
// Usage: DstBsimAdd.java <dbPathWithoutExtension> <minInstructions>
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.ResponseInsert;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DstBsimAdd extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = String.join(",", getScriptArgs()).split(",");
        if (args.length < 1) {
            printerr("usage: DstBsimAdd.java <dbPathWithoutExtension> [minInstructions]");
            return;
        }
        File dbFile = new File(args[0]).getAbsoluteFile();
        int minInstr = args.length > 1 ? Integer.parseInt(args[1]) : 8;

        BSimServerInfo serverInfo = new BSimServerInfo(dbFile.getAbsolutePath());
        try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, false)) {
            if (!db.initialize()) {
                printerr("init failed: " + db.getLastError().message);
                return;
            }
            DatabaseInformation info = db.getInfo();
            GenSignatures gensig = new GenSignatures(info.trackcallgraph);
            try {
                gensig.setVectorFactory(db.getLSHVectorFactory());
                gensig.addExecutableCategories(info.execats);
                gensig.addFunctionTags(info.functionTags);
                gensig.addDateColumnName(info.dateColumnName);

                String repo = null;
                String path = null;
                DomainFile dFile = currentProgram.getDomainFile();
                if (dFile != null) {
                    URL url = dFile.getLocalProjectURL(null);
                    if (url != null) {
                        String p = GhidraURL.getProjectPathname(url);
                        int slash = p.lastIndexOf('/');
                        path = slash <= 0 ? "/" : p.substring(0, slash);
                        repo = GhidraURL.getProjectURL(url).toExternalForm();
                    }
                }
                gensig.openProgram(currentProgram, null, null, null, repo, path);

                List<Function> keep = new ArrayList<>();
                FunctionManager fman = currentProgram.getFunctionManager();
                for (Function f : fman.getFunctions(true)) {
                    if (monitor.isCancelled()) break;
                    if (f.isExternal() || f.isThunk()) continue;
                    if (instructionCount(f) < minInstr) continue;
                    keep.add(f);
                }
                println("scanning " + keep.size() + " functions (minInstr=" + minInstr + ")");
                Iterator<Function> iter = keep.iterator();
                gensig.scanFunctions(iter, keep.size(), monitor);

                DescriptionManager manager = gensig.getDescriptionManager();
                if (manager.numFunctions() == 0) {
                    printerr("no signatures generated");
                    return;
                }
                manager.listAllFunctions().forEachRemaining(FunctionDescription::sortCallgraph);

                InsertRequest req = new InsertRequest();
                req.manage = manager;
                ResponseInsert resp = req.execute(db);
                if (resp == null) {
                    printerr("insert failed: " + db.getLastError().message);
                    return;
                }
                println("inserted " + manager.numFunctions() + " functions from " + currentProgram.getName());
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
}
