"""Identifier-renaming transform for the memorisation experiment.

Rewrites a front-end facts file so that it carries no benchmark-specific names:
  - application classes -> app.C1, app.C2, ... (inner classes keep their $suffix numbering),
    e.g. de.ecspride.ArrayAccess1 -> app.C1;
  - application methods that override nothing in the framework (including layout onClick
    handlers) -> m1, m2, ...;
  - application fields -> f1, f2, ...;
  - string literals -> "s1", "s2", ... (consistently, so equality is preserved; literals naming a
    renamed class or method map to the new name; getSystemService arguments are kept);
  - layout file names and R.id / R.layout names -> layout1, id1, ...
Statement indices, local names, library types, framework overrides and source/sink calls are
unchanged, so the program semantics and the candidate sinks are identical. Each method keeps
`orig_sig` and each statement `orig_text`, so reported sinks are mapped back to the original Jimple
and scored with the unchanged scorer.

Usage: python -m analyzer.frontend.rename <facts dir> <out dir>
"""

import json
import re
import sys
from pathlib import Path

STR_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
KEEP_STRING_CALLS = ("getSystemService(java.lang.String)",)


def build_maps(facts):
    classes = [c["name"] for c in facts["classes"]]
    cmap, top = {}, 0
    for name in sorted(classes, key=lambda n: (n.count("$"), n)):
        outer, _, inner = name.partition("$")
        if not inner:
            top += 1
            cmap[name] = f"app.C{top}"
        elif outer in cmap:
            parent = name.rsplit("$", 1)[0]
            last = name.rsplit("$", 1)[1]
            base = cmap.get(parent, cmap[outer])
            # anonymous classes keep their number; named inner classes get a neutral one
            cmap[name] = (
                base
                + "$"
                + (last if last.isdigit() else f"I{sum(1 for v in cmap if '$' in v) + 1}")
            )
        else:
            top += 1
            cmap[name] = f"app.C{top}"
    mmap, fmap = {}, {}
    for c in facts["classes"]:
        for m in c["methods"]:
            name = m["sig"].split(" ")[-1].split("(")[0]
            if (
                m["overrides"]
                or name.startswith("<")
                or name.startswith("access$")
                or name in mmap
            ):
                continue
            if name in ("main",):
                continue
            mmap[name] = f"m{len(mmap) + 1}"
        for f in c["fields"]:
            name = f["sig"].rstrip(">").split(" ")[-1]
            if name not in fmap and name != "this$0" and name != "serialVersionUID":
                fmap[name] = f"f{len(fmap) + 1}"
    return cmap, mmap, fmap


class Renamer:
    def __init__(self, facts):
        self.cmap, self.mmap, self.fmap = build_maps(facts)
        self.app = set(self.cmap)
        self.smap = {}
        pkg = next(
            (n["attrs"].get("package") for n in facts["manifest"] if n["tag"] == "manifest"), None
        )
        self.pkg = pkg
        cls_alt = "|".join(re.escape(c) for c in sorted(self.app, key=len, reverse=True))
        self.class_re = re.compile(rf"(?<![\w$.])({cls_alt})(?![\w$])") if cls_alt else None
        self.member_re = re.compile(rf"<({cls_alt}): ([^ >]+) ([\w$]+)(\(|>)") if cls_alt else None
        res = facts.get("resources", {})
        self.rmap = {}
        for kind in ("layout", "id"):
            for k, name in enumerate(sorted(res.get(kind, {})), 1):
                self.rmap[(kind, name)] = f"{kind}{k}"

    def string(self, lit):
        body = lit[1:-1]
        if body in self.cmap:
            return f'"{self.cmap[body]}"'
        if body in self.mmap:
            return f'"{self.mmap[body]}"'
        if body in self.fmap:
            return f'"{self.fmap[body]}"'
        if lit not in self.smap:
            self.smap[lit] = f'"s{len(self.smap) + 1}"'
        return self.smap[lit]

    def text(self, t):
        if not t or not self.class_re:
            return t
        if not any(k in t for k in KEEP_STRING_CALLS):
            t = STR_RE.sub(lambda m: self.string(m.group(0)), t)

        def member(m):
            cls, typ, name, tail = m.groups()
            table = self.mmap if tail == "(" else self.fmap
            return f"<{cls}: {typ} {table.get(name, name)}{tail}"

        t = self.member_re.sub(member, t)
        t = self.class_re.sub(lambda m: self.cmap[m.group(1)], t)
        return t

    def apply(self, facts):
        for c in facts["classes"]:
            for key in ("name", "super"):
                if c.get(key):
                    c[key] = self.text(c[key])
            c["interfaces"] = [self.text(i) for i in c["interfaces"]]
            c["supertypes"] = [self.text(i) for i in c["supertypes"]]
            for f in c["fields"]:
                f["sig"] = self.text(f["sig"])
            for m in c["methods"]:
                m["orig_sig"] = m["sig"]
                m["sig"] = self.text(m["sig"])
                m["subsig"] = m["sig"].split(": ", 1)[1][:-1]
                for s in m["stmts"]:
                    s["orig_text"] = s["text"]
                    s["text"] = self.text(s["text"])
                    s.pop("line", None)
                    if "field" in s:
                        s["field"] = {k: self.text(v) for k, v in s["field"].items()}
                    inv = s.get("invoke")
                    if inv:
                        inv["callee"] = self.text(inv["callee"])
                        inv["subsig"] = inv["callee"].split(": ", 1)[1][:-1]
                        inv["hierarchy_sigs"] = [
                            f"<{self.text(h[1:].split(': ', 1)[0])}: {inv['subsig']}>"
                            for h in inv["hierarchy_sigs"]
                        ]
        for n in facts["manifest"]:
            a = n["attrs"]
            if n["tag"] == "manifest" and "package" in a:
                a["package"] = "app"
            if "name" in a and n["tag"] in (
                "activity",
                "service",
                "receiver",
                "provider",
                "application",
            ):
                full = a["name"]
                if full.startswith(".") and self.pkg:
                    full = self.pkg + full
                elif "." not in full and self.pkg:
                    full = self.pkg + "." + full
                a["name"] = self.cmap.get(full, a["name"])
            for k, v in list(a.items()):
                if self.pkg and isinstance(v, str) and self.pkg in v:
                    a[k] = self.class_re.sub(lambda m: self.cmap[m.group(1)], v).replace(
                        self.pkg, "app"
                    )
        layouts = {}
        for path, nodes in facts["layouts"].items():
            stem = Path(path).stem
            new = self.rmap.get(("layout", stem), stem)
            for n in nodes:
                if "onClick" in n["attrs"]:
                    n["attrs"]["onClick"] = self.mmap.get(
                        n["attrs"]["onClick"], n["attrs"]["onClick"]
                    )
                for k in ("text", "hint", "contentDescription"):
                    if k in n["attrs"] and not n["attrs"][k].startswith("@"):
                        n["attrs"][k] = self.string(f'"{n["attrs"][k]}"')[1:-1]
            layouts[f"res/layout/{new}.xml"] = nodes
        facts["layouts"] = layouts
        facts["resources"] = {
            kind: {self.rmap.get((kind, k), k): v for k, v in table.items()}
            for kind, table in facts.get("resources", {}).items()
        }
        facts["apk"] = "renamed"
        facts["rename_map"] = {
            "classes": self.cmap,
            "methods": self.mmap,
            "fields": self.fmap,
            "strings": self.smap,
        }
        return facts


def main():
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.mkdir(parents=True, exist_ok=True)
    for f in sorted(src.glob("*.json")):
        facts = json.loads(f.read_text())
        out = Renamer(facts).apply(facts)
        (dst / f.name).write_text(json.dumps(out, indent=1))
    print("renamed", len(list(dst.glob("*.json"))), "apps ->", dst)


if __name__ == "__main__":
    main()
