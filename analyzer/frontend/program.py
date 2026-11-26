"""Symbolic program model built from the front-end facts.

Provides the indices used by the agent tools and by the checker:
spec-based source/sink candidates, a CHA call graph over application code,
field read/write sites, class-initialisation triggers, framework entry points
and a symbolic reachability fixpoint. No taint propagation happens here.
"""

import json
import re
from collections import defaultdict
from pathlib import Path

from ..benchmarks import FLOWDROID_DIR as SPEC_DIR

# Framework calls that hand an Intent back to the platform although they are
# not in the PLDI sink list. Only used in the "extended" configuration.
ESCAPE_SUBSIGS = {
    "void setResult(int,android.content.Intent)",
}

FIELD_RE = re.compile(r"<([\w.$]+): ([\w.$\[\]]+) ([\w$]+)>(?!\()")
NEW_RE = re.compile(r"= new ([\w.$]+)\s*$")
PARAM_RE = re.compile(r"^(\$?[\w]+) := @parameter(\d+): ([\w.$\[\]]+)$")


def _norm_sig(sig: str) -> str:
    sig = sig.strip()
    sig = re.sub(r",\s+", ",", sig)
    if not sig.startswith("<"):
        sig = "<" + sig
    if not sig.endswith(">"):
        sig = sig + ">"
    return sig


def load_spec(path=SPEC_DIR / "SourcesAndSinks.txt"):
    sources, sinks = set(), set()
    for line in path.read_text(encoding="latin-1").splitlines():
        line = line.strip()
        if not line or line.startswith("%") or "->" not in line:
            continue
        m = re.match(r"(<.*?\)>)", line)
        if not m:
            continue
        sig = _norm_sig(m.group(1))
        if line.endswith("_SOURCE_"):
            sources.add(sig)
        elif "_SINK_" in line:
            sinks.add(sig)
    return sources, sinks


def load_callback_types(path=SPEC_DIR / "AndroidCallbacks.txt"):
    lines = path.read_text(encoding="latin-1").splitlines()
    return {line.strip() for line in lines if line.strip()}


class Program:
    def __init__(self, facts_path, extended=False, spec_file=None):
        self.facts = json.loads(Path(facts_path).read_text())
        self.case = Path(facts_path).stem
        self.extended = extended
        self.spec_sources, self.spec_sinks = (
            load_spec(Path(spec_file)) if spec_file else load_spec()
        )
        self.callback_types = load_callback_types()
        self.classes = {c["name"]: c for c in self.facts["classes"]}
        self.methods = {}
        for c in self.facts["classes"]:
            for m in c["methods"]:
                m["class"] = c["name"]
                self.methods[m["sig"]] = m
        self.package = next(
            (n["attrs"].get("package") for n in self.facts["manifest"] if n["tag"] == "manifest"),
            "",
        )
        self._index()

    # ------------------------------------------------------------------ index
    def _index(self):
        self.callers = defaultdict(list)  # callee -> [(caller, idx)]
        self.callees = defaultdict(list)  # caller -> [(idx, callee)]
        self.field_sites = defaultdict(list)  # field sig -> [(method, idx, 'read'|'write')]
        self.class_refs = defaultdict(list)  # class -> [(method, idx, how)]
        for sig, m in self.methods.items():
            for i, s in enumerate(m["stmts"]):
                text = s["text"]
                inv = s.get("invoke")
                if inv:
                    for t in self.resolve(inv):
                        self.callers[t].append((sig, i))
                        self.callees[sig].append((i, t))
                    owner = inv["callee"][1:].split(":")[0]
                    if inv["kind"] == "static" and owner in self.classes:
                        self.class_refs[owner].append((sig, i, "static call"))
                lhs = text.split(" = ", 1)[0] if " = " in text else ""
                for fm in FIELD_RE.finditer(text):
                    fsig = fm.group(0)
                    kind = "write" if fsig in lhs else "read"
                    self.field_sites[self.declared_field(s, fsig)].append((sig, i, kind))
                    owner = fm.group(1)
                    if owner in self.classes and fm.start() > 0 and text[fm.start() - 1] != ".":
                        self.class_refs[owner].append((sig, i, f"static field {kind}"))
                nm = NEW_RE.search(text)
                if nm and nm.group(1) in self.classes:
                    self.class_refs[nm.group(1)].append((sig, i, "new"))

    ANNOTATE = True  # ablation 'no-annotations': no branch-target / field-resolution annotations

    @staticmethod
    def declared_field(stmt, fsig):
        """Field signature resolved to its declaring class (a ref may name a subclass)."""
        f = stmt.get("field")
        if Program.ANNOTATE and f and f["ref"] == fsig:
            return f["declared"]
        return fsig

    def stmt_fields(self, sig, i):
        s = self.methods[sig]["stmts"][i]
        return {self.declared_field(s, m.group(0)) for m in FIELD_RE.finditer(s["text"])}

    def resolve(self, inv):
        """CHA targets of an invoke inside application code."""
        owner = inv["callee"][1:].split(":")[0]
        subsig = inv["subsig"]
        targets = []
        if inv["kind"] in ("static", "special"):
            k = owner
            while k in self.classes:
                sig = f"<{k}: {subsig}>"
                if sig in self.methods:
                    return [sig]
                k = self.classes[k]["super"]
            return []
        for name, c in self.classes.items():
            if owner in c["supertypes"]:
                sig = f"<{name}: {subsig}>"
                if sig in self.methods and self.methods[sig]["concrete"]:
                    targets.append(sig)
        # inherited implementation in an application superclass
        k = owner
        while k in self.classes:
            sig = f"<{k}: {subsig}>"
            if sig in self.methods and self.methods[sig]["concrete"]:
                if sig not in targets:
                    targets.append(sig)
                break
            k = self.classes[k]["super"]
        return targets

    # -------------------------------------------------------- sources / sinks
    def _match(self, inv, spec):
        for s in inv["hierarchy_sigs"]:
            if s in spec:
                return s
        return None

    def candidate_sinks(self):
        out = []
        for sig, m in self.methods.items():
            for i, s in enumerate(m["stmts"]):
                inv = s.get("invoke")
                if not inv:
                    continue
                hit = self._match(inv, self.spec_sinks)
                if hit:
                    out.append(
                        {
                            "method": sig,
                            "index": i,
                            "statement": s["text"],
                            "spec": hit,
                            "kind": "spec",
                        }
                    )
                elif self.extended and inv["subsig"] in ESCAPE_SUBSIGS:
                    out.append(
                        {
                            "method": sig,
                            "index": i,
                            "statement": s["text"],
                            "spec": inv["callee"],
                            "kind": "escape",
                        }
                    )
                else:
                    continue
                # original identity (differs only for renamed facts); used for scoring
                out[-1]["orig_method"] = m.get("orig_sig", sig)
                out[-1]["orig_statement"] = s.get("orig_text", s["text"])
        return out

    def password_ids(self):
        ids = set()
        for nodes in self.facts["layouts"].values():
            for n in nodes:
                a = n["attrs"]
                it = a.get("inputType", "")
                pw = a.get("password") == "true"
                try:
                    variation = int(it) & 0xFFF
                    pw = pw or variation in (0x81, 0x91, 0xE1, 0x12)
                except ValueError:
                    pass
                if pw and a.get("id", "").startswith("@"):
                    ids.add(int(a["id"][1:]))
        return ids

    def sources(self):
        """Known sources: spec calls, password UI fields, sensitive callback params."""
        out = []
        pw_ids = self.password_ids()
        for sig, m in self.methods.items():
            is_callback = bool(set(m["overrides"]) & self.callback_types)
            for i, s in enumerate(m["stmts"]):
                inv = s.get("invoke")
                if inv:
                    hit = self._match(inv, self.spec_sources)
                    if hit:
                        out.append(
                            {
                                "method": sig,
                                "index": i,
                                "statement": s["text"],
                                "kind": "spec",
                                "spec": hit,
                            }
                        )
                    elif inv["subsig"] == "android.view.View findViewById(int)":
                        arg = re.search(r"\((-?\d+)\)$", s["text"])
                        if arg and int(arg.group(1)) in pw_ids:
                            out.append(
                                {
                                    "method": sig,
                                    "index": i,
                                    "statement": s["text"],
                                    "kind": "password-field",
                                    "spec": inv["callee"],
                                }
                            )
                pm = PARAM_RE.match(s["text"])
                if pm and is_callback and pm.group(3) == "android.location.Location":
                    out.append(
                        {
                            "method": sig,
                            "index": i,
                            "statement": s["text"],
                            "kind": "callback-parameter",
                            "spec": pm.group(3),
                        }
                    )
        return out

    # ------------------------------------------------------ entry points
    def components(self):
        comps = {}
        for n in self.facts["manifest"]:
            if n["tag"] in ("activity", "service", "receiver", "provider"):
                name = n["attrs"].get("name", "")
                if name.startswith("."):
                    name = self.package + name
                elif "." not in name:
                    name = self.package + "." + name
                comps[name] = {"kind": n["tag"], "enabled": n["attrs"].get("enabled") != "false"}
        return comps

    def layout_callbacks(self):
        """Activity -> [(layout file, onClick method name)] via setContentView ids."""
        res = self.facts["resources"].get("layout", {})
        by_id = {v: k for k, v in res.items()}
        out = defaultdict(list)
        for sig, m in self.methods.items():
            for s in m["stmts"]:
                inv = s.get("invoke")
                if inv and inv["subsig"] == "void setContentView(int)":
                    arg = re.search(r"\((-?\d+)\)$", s["text"])
                    name = by_id.get(int(arg.group(1))) if arg else None
                    nodes = self.facts["layouts"].get(f"res/layout/{name}.xml", []) if name else []
                    for n in nodes:
                        if "onClick" in n["attrs"]:
                            out[m["class"]].append(
                                (f"res/layout/{name}.xml", n["attrs"]["onClick"])
                            )
        return out

    def reachability(self):
        """Symbolic fixpoint: methods the framework or reachable code can invoke.

        Returns {method: reason} where reason explains the first way it became
        reachable (entry kind or caller).
        """
        reach = {}
        work = []

        def add(sig, why):
            if sig in self.methods and sig not in reach:
                reach[sig] = why
                work.append(sig)

        live_classes = set()

        def activate(cls, why):
            if cls in live_classes or cls not in self.classes:
                return
            live_classes.add(cls)
            seen_subsigs = set()
            k = cls
            while k in self.classes:  # own and inherited application methods
                for sig, m in self.methods.items():
                    if m["class"] == k and m["overrides"] and m["subsig"] not in seen_subsigs:
                        seen_subsigs.add(m["subsig"])
                        add(
                            sig,
                            f"framework callback on live object of {cls} ({why}); "
                            f"overrides {', '.join(m['overrides'])}",
                        )
                k = self.classes[k]["super"]
            add(f"<{cls}: void <init>()>", f"framework instantiates {cls}")

        layout_cb = self.layout_callbacks()
        for cls, info in self.components().items():
            if info["enabled"]:
                activate(cls, f"manifest {info['kind']}")
        while work:
            sig = work.pop()
            m = self.methods[sig]
            if m["class"] in layout_cb:
                for layout, name in layout_cb[m["class"]]:
                    for cand, cm in self.methods.items():
                        if cm["class"] == m["class"] and cand.split(" ")[-1].startswith(
                            name + "("
                        ):
                            add(cand, f'android:onClick="{name}" in {layout}')
            for i, callee in self.callees.get(sig, []):
                add(callee, f"called from {sig}")
            for i, s in enumerate(m["stmts"]):
                nm = NEW_RE.search(s["text"])
                if nm:
                    activate(nm.group(1), f"allocated in {sig}")
            for cls, refs in self.class_refs.items():
                if any(r[0] == sig for r in refs):
                    add(f"<{cls}: void <clinit>()>", f"class initialisation triggered in {sig}")
        return reach

    # ------------------------------------------------------ helpers for tools
    def find(self, sig):
        """Exact or fuzzy method lookup; returns (sig or None, candidates)."""
        s = _norm_sig(sig)
        if s in self.methods:
            return s, []
        name = re.sub(r"[<>]", "", sig).strip()
        cands = [
            k for k in self.methods if name in k or name.split("(")[0].split(" ")[-1] + "(" in k
        ]
        if len(cands) == 1:
            return cands[0], []
        return None, cands[:15]

    def listing(self, sig):
        m = self.methods[sig]
        lines = [
            f"method {sig}"
            + (f"  // overrides {', '.join(m['overrides'])}" if m["overrides"] else "")
        ]
        for i, s in enumerate(m["stmts"]):
            notes = []
            if not Program.ANNOTATE:
                pass
            elif s.get("targets"):
                notes.append("branch target " + ", ".join(f"[{t}]" for t in s["targets"]))
            f = s.get("field")
            if Program.ANNOTATE and f and f["ref"] != f["declared"]:
                notes.append(f"field resolves to {f['declared']}")
            lines.append(f"  [{i}] {s['text']}" + (f"    // {'; '.join(notes)}" if notes else ""))
        return "\n".join(lines)

    def stmt_index(self, sig, text):
        want = text.strip().rstrip(";").strip()
        for i, s in enumerate(self.methods[sig]["stmts"]):
            if s["text"] == want:
                return i
        return None

    def app_overview(self, focus_class=None, limit=20000):
        """Class/method listing for the prompt. Small apps: everything (DroidBench). Large apps:
        full listing only for manifest components and the package of focus_class (the sink's
        class); other packages are summarised.
        """
        comps = self.components()

        def block(name, c, with_methods=True):
            comp = comps.get(name)
            tag = (
                f" [manifest {comp['kind']}{'' if comp['enabled'] else ', enabled=false'}]"
                if comp
                else ""
            )
            out = [
                f"- {name} extends {c['super']}"
                + (f" implements {', '.join(c['interfaces'])}" if c["interfaces"] else "")
                + tag
            ]
            if with_methods:
                out += [f"    {m['sig']}" for m in c["methods"]]
            return out

        full = ["Application classes:"]
        for name, c in self.classes.items():
            full += block(name, c)
        text = "\n".join(full)
        if len(text) <= limit:
            return text

        def pkg(name):
            return name.rsplit(".", 1)[0] if "." in name else ""

        focus = {pkg(focus_class)} if focus_class else set()
        focus |= {pkg(n) for n in comps}
        lines = [
            "Application classes (large app: methods listed only for manifest components and "
            f"packages {', '.join(sorted(focus))}; use the tools to inspect other classes):"
        ]
        others = {}
        for name, c in self.classes.items():
            if name in comps or pkg(name) in focus:
                lines += block(name, c)
            else:
                others[pkg(name)] = others.get(pkg(name), 0) + 1
        lines.append(
            "Other packages (class counts): "
            + ", ".join(f"{k} ({v})" for k, v in sorted(others.items()))
        )
        return "\n".join(lines)
