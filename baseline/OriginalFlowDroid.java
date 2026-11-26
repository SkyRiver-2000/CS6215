import java.io.PrintWriter;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import soot.jimple.infoflow.InfoflowResults;
import soot.jimple.infoflow.InfoflowResults.SinkInfo;
import soot.jimple.infoflow.InfoflowResults.SourceInfo;
import soot.jimple.infoflow.android.test.droidBench.JUnitTests;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;

/** Export the original artifact's results without changing its analysis. */
public class OriginalFlowDroid {
    private static String encode(String value) throws Exception {
        return Base64.getEncoder().encodeToString(value.getBytes("UTF-8"));
    }

    public static void main(String[] args) throws Exception {
        InfoflowResults results = new JUnitTests().analyzeAPKFile(args[0]);
        PrintWriter output = new PrintWriter(args[1], "UTF-8");
        if (results == null) {
            output.println("NULL");
        } else {
            output.println("COUNT\t" + results.size());
            JimpleBasedInterproceduralCFG cfg = new JimpleBasedInterproceduralCFG();
            for (Map.Entry<SinkInfo, Set<SourceInfo>> entry : results.getResults().entrySet()) {
                SinkInfo sink = entry.getKey();
                output.println("SINK\t"
                    + encode(cfg.getMethodOf(sink.getContext()).getSignature()) + "\t"
                    + sink.getContext().getJavaSourceStartLineNumber() + "\t"
                    + encode(sink.getSink().toString()) + "\t"
                    + encode(sink.getContext().toString()));
                for (SourceInfo source : entry.getValue()) {
                    output.println("SOURCE\t"
                        + encode(cfg.getMethodOf(source.getContext()).getSignature()) + "\t"
                        + source.getContext().getJavaSourceStartLineNumber() + "\t"
                        + encode(source.getContext().toString()));
                }
            }
        }
        output.close();
    }
}
