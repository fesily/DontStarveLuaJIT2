// Create an H2 file-backed BSim database (headless-safe).
// Usage: DstBsimCreate.java <dbPathWithoutExtension> <template>
//@category DST
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import ghidra.features.bsim.query.protocol.ResponseInfo;

import java.io.File;

public class DstBsimCreate extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = String.join(",", getScriptArgs()).split(",");
        if (args.length < 1) {
            printerr("usage: DstBsimCreate.java <dbPathWithoutExtension> [template]");
            return;
        }
        File dbFile = new File(args[0]).getAbsoluteFile();
        String template = args.length > 1 ? args[1] : "medium_nosize";
        BSimServerInfo serverInfo = new BSimServerInfo(dbFile.getAbsolutePath());

        try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, false)) {
            CreateDatabase cmd = new CreateDatabase();
            cmd.info = new DatabaseInformation();
            cmd.info.databasename = dbFile.getName();
            cmd.config_template = template;
            cmd.info.trackcallgraph = true;
            ResponseInfo resp = cmd.execute(db);
            if (resp == null) {
                printerr("create failed: " + db.getLastError().message);
                return;
            }
            println("created " + dbFile.getAbsolutePath() + " template=" + template);
        }
    }
}
