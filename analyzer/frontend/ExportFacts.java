import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import soot.Body;
import soot.G;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InterfaceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import soot.options.Options;
import soot.tagkit.IntegerConstantValueTag;
import soot.tagkit.Tag;

/**
 * Symbolic front end of the neuro-symbolic analyzer.
 *
 * Loads one APK with the Soot bundled in the original PLDI 2014 FlowDroid jar
 * and dumps facts as JSON: application classes, Jimple statements of every
 * concrete method, invoke targets with their supertype signatures (for
 * source/sink matching) and R constants. Manifest and layouts are parsed
 * by axml.py.
 * It performs no taint analysis.
 *
 * Usage: ExportFacts <apk> <android-platforms-dir> <out.json>
 */
public class ExportFacts {
    private static final StringBuilder out = new StringBuilder();

    public static void main(String[] args) throws Exception {
        String apk = args[0];
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(apk));
        Options.v().set_android_jars(args[1]);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_soot_classpath(args[1] + "/android-17/android.jar");
        Options.v().set_prepend_classpath(false);
        Options.v().set_output_format(Options.output_format_none);
        Scene.v().loadNecessaryClasses();

        out.append("{\"apk\":").append(q(apk)).append(",\"classes\":[");
        boolean firstClass = true;
        List<SootClass> classes = new ArrayList<SootClass>(Scene.v().getApplicationClasses());
        Collections.sort(classes, (a, b) -> a.getName().compareTo(b.getName()));
        StringBuilder resources = new StringBuilder();
        for (SootClass sc : classes) {
            String name = sc.getName();
            if (name.startsWith("android.support.")) continue;
            String simple = name.substring(name.lastIndexOf('.') + 1);
            if (simple.startsWith("R$")) {
                appendResources(resources, simple.substring(2), sc);
                continue;
            }
            if (simple.equals("R") || simple.equals("BuildConfig")) continue;
            if (!firstClass) out.append(",");
            firstClass = false;
            writeClass(sc);
        }
        out.append("],\"resources\":{").append(resources).append("}");
        out.append("}");
        PrintWriter w = new PrintWriter(args[2], "UTF-8");
        w.print(out);
        w.close();
    }

    private static void appendResources(StringBuilder sb, String kind, SootClass sc) {
        if (!(kind.equals("layout") || kind.equals("id"))) return;
        if (sb.length() > 0) sb.append(",");
        sb.append(q(kind)).append(":{");
        boolean first = true;
        for (SootField f : sc.getFields()) {
            for (Tag t : f.getTags()) {
                if (t instanceof IntegerConstantValueTag) {
                    if (!first) sb.append(",");
                    first = false;
                    sb.append(q(f.getName())).append(":")
                      .append(((IntegerConstantValueTag) t).getIntValue());
                }
            }
        }
        sb.append("}");
    }

    private static void writeClass(SootClass sc) {
        out.append("{\"name\":").append(q(sc.getName()));
        out.append(",\"super\":").append(sc.hasSuperclass() ? q(sc.getSuperclass().getName()) : "null");
        out.append(",\"interfaces\":[");
        boolean first = true;
        for (SootClass i : sc.getInterfaces()) {
            if (!first) out.append(",");
            first = false;
            out.append(q(i.getName()));
        }
        out.append("],\"is_interface\":").append(sc.isInterface());
        out.append(",\"supertypes\":").append(list(supertypes(sc)));
        out.append(",\"fields\":[");
        first = true;
        for (SootField f : sc.getFields()) {
            if (!first) out.append(",");
            first = false;
            out.append("{\"sig\":").append(q(f.getSignature()))
               .append(",\"static\":").append(f.isStatic()).append("}");
        }
        out.append("],\"methods\":[");
        first = true;
        for (SootMethod m : new ArrayList<SootMethod>(sc.getMethods())) {
            if (!first) out.append(",");
            first = false;
            writeMethod(m);
        }
        out.append("]}");
    }

    private static void writeMethod(SootMethod m) {
        out.append("{\"sig\":").append(q(m.getSignature()))
           .append(",\"subsig\":").append(q(m.getSubSignature()))
           .append(",\"static\":").append(m.isStatic())
           .append(",\"concrete\":").append(m.isConcrete())
           .append(",\"overrides\":").append(list(overriddenLibraryTypes(m)))
           .append(",\"stmts\":[");
        if (m.isConcrete()) {
            Body body;
            try {
                body = m.retrieveActiveBody();
            } catch (RuntimeException e) {
                out.append("]}");
                return;
            }
            java.util.Map<Unit, Integer> index = new java.util.HashMap<Unit, Integer>();
            for (Unit u : body.getUnits()) index.put(u, index.size());
            boolean first = true;
            for (Unit u : body.getUnits()) {
                if (!first) out.append(",");
                first = false;
                Stmt s = (Stmt) u;
                out.append("{\"text\":").append(q(s.toString()));
                int line = s.getJavaSourceStartLineNumber();
                if (line > 0) out.append(",\"line\":").append(line);
                // Branch targets as statement indices (Jimple's toString hides them).
                List<String> targets = new ArrayList<String>();
                for (soot.UnitBox ub : s.getUnitBoxes()) {
                    Integer t = index.get(ub.getUnit());
                    if (t != null) targets.add(Integer.toString(t));
                }
                if (!targets.isEmpty()) out.append(",\"targets\":[").append(String.join(",", targets)).append("]");
                // Field references resolved to the declaring class (refs may name a subclass).
                if (s.containsFieldRef()) {
                    soot.jimple.FieldRef fr = s.getFieldRef();
                    String declared;
                    try {
                        declared = fr.getField().getSignature();
                    } catch (RuntimeException e) {
                        declared = fr.getFieldRef().getSignature();
                    }
                    out.append(",\"field\":{\"ref\":").append(q(fr.getFieldRef().getSignature()))
                       .append(",\"declared\":").append(q(declared)).append("}");
                }
                if (s.containsInvokeExpr()) {
                    InvokeExpr ie = s.getInvokeExpr();
                    String kind = ie instanceof StaticInvokeExpr ? "static"
                        : ie instanceof SpecialInvokeExpr ? "special"
                        : ie instanceof InterfaceInvokeExpr ? "interface" : "virtual";
                    String subsig = ie.getMethodRef().getSubSignature().getString();
                    SootClass decl = ie.getMethodRef().declaringClass();
                    List<String> sigs = new ArrayList<String>();
                    for (String k : supertypes(decl)) sigs.add("<" + k + ": " + subsig + ">");
                    out.append(",\"invoke\":{\"kind\":").append(q(kind))
                       .append(",\"callee\":").append(q(ie.getMethodRef().getSignature()))
                       .append(",\"subsig\":").append(q(subsig))
                       .append(",\"hierarchy_sigs\":").append(list(sigs))
                       .append(",\"base\":")
                       .append(ie instanceof InstanceInvokeExpr ? q(((InstanceInvokeExpr) ie).getBase().toString()) : "null")
                       .append("}");
                }
                out.append("}");
            }
        }
        out.append("]}");
    }

    /** Library (non-application) supertypes that declare the same subsignature. */
    private static List<String> overriddenLibraryTypes(SootMethod m) {
        List<String> result = new ArrayList<String>();
        if (m.isStatic() || m.isConstructor() || m.getName().equals("<clinit>")) return result;
        for (String k : supertypes(m.getDeclaringClass())) {
            SootClass c = Scene.v().getSootClass(k);
            if (c.isApplicationClass()) continue;
            try {
                if (c.declaresMethod(m.getSubSignature())) result.add(k);
            } catch (RuntimeException e) {
                // unresolved library class: no information
            }
        }
        return result;
    }

    /** The class itself, all superclasses and all transitively implemented interfaces. */
    private static List<String> supertypes(SootClass sc) {
        Set<String> seen = new LinkedHashSet<String>();
        List<SootClass> work = new ArrayList<SootClass>();
        work.add(sc);
        while (!work.isEmpty()) {
            SootClass c = work.remove(0);
            if (!seen.add(c.getName())) continue;
            if (c.hasSuperclass()) work.add(c.getSuperclass());
            work.addAll(c.getInterfaces());
        }
        return new ArrayList<String>(seen);
    }

    private static String list(List<String> xs) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < xs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(q(xs.get(i)));
        }
        return sb.append("]").toString();
    }

    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }
}
