"""Symbolic query tools exposed to the LLM agent (function calling)."""

import json
import re

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "get_method",
            "description": "Return the numbered Jimple body of an application method.",
            "parameters": {
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "Soot method signature, e.g. <a.B: void m(int)>",
                    }
                },
                "required": ["signature"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_callers",
            "description": "List call sites (method, statement index, statement) that may invoke "
            "the given application method, "
            "plus how the framework can reach it.",
            "parameters": {
                "type": "object",
                "properties": {"signature": {"type": "string"}},
                "required": ["signature"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "field_accesses",
            "description": "List every statement that reads or writes a field. Accepts a field "
            "signature "
            "<a.B: java.lang.String f> or a field name.",
            "parameters": {
                "type": "object",
                "properties": {"field": {"type": "string"}},
                "required": ["field"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "class_init_triggers",
            "description": "For a class with a static initializer <clinit>, list the statements "
            "whose execution first "
            "triggers its initialization (new, static field access, static call).",
            "parameters": {
                "type": "object",
                "properties": {"class_name": {"type": "string"}},
                "required": ["class_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "entry_info",
            "description": "Explain how a method becomes reachable: the chain of callers back to "
            "a framework entry point "
            "(lifecycle method, UI/listener callback, layout onClick, class initialisation).",
            "parameters": {
                "type": "object",
                "properties": {"signature": {"type": "string"}},
                "required": ["signature"],
            },
        },
    },
]


class Tools:
    def __init__(self, program):
        self.p = program
        self.reach = program.reachability()

    def call(self, name, raw_args):
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
        except json.JSONDecodeError:
            return "error: arguments are not valid JSON"
        fn = getattr(self, "t_" + name, None)
        if fn is None:
            return f"error: unknown tool {name}"
        try:
            return fn(**args)
        except TypeError as e:
            return f"error: bad arguments: {e}"

    def _method(self, signature):
        sig, cands = self.p.find(signature)
        if sig is None:
            msg = f"no application method matches {signature!r}."
            if cands:
                msg += " Candidates:\n" + "\n".join(cands)
            else:
                msg += (
                    " It may be a framework/library method (no body available); reason about "
                    "its documented semantics."
                )
            return None, msg
        return sig, None

    def t_get_method(self, signature):
        sig, err = self._method(signature)
        return err or self.p.listing(sig)

    def t_find_callers(self, signature):
        sig, err = self._method(signature)
        if err:
            return err
        lines = [f"callers of {sig}:"]
        for caller, i in self.p.callers.get(sig, []):
            lines.append(f"- {caller} [{i}] {self.p.methods[caller]['stmts'][i]['text']}")
        if len(lines) == 1:
            lines.append("- (no direct call sites in application code)")
        unreachable = (
            "not reachable in the symbolic call graph "
            "(reflection and framework-mediated dispatch are not modelled)"
        )
        lines.append(f"reachability: {self.reach.get(sig, unreachable)}")
        return "\n".join(lines)

    def t_field_accesses(self, field):
        f = field.strip()
        keys = [
            k for k in self.p.field_sites if k == f or k.endswith(" " + f + ">") or k == f"<{f}>"
        ]
        if not keys:
            name = f.split(".")[-1].strip("<> ")
            keys = [k for k in self.p.field_sites if k.endswith(" " + name + ">")]
        if not keys:
            return f"no accesses found for field {field!r}"
        lines = []
        for k in keys:
            lines.append(f"field {k}:")
            for m, i, kind in self.p.field_sites[k]:
                lines.append(f"- {kind:5s} {m} [{i}] {self.p.methods[m]['stmts'][i]['text']}")
        return "\n".join(lines)

    def t_class_init_triggers(self, class_name):
        cls = class_name.strip("<> ")
        if cls not in self.p.classes:
            hits = [c for c in self.p.classes if c.endswith(cls)]
            if len(hits) != 1:
                return f"unknown class {class_name!r}; classes: {', '.join(self.p.classes)}"
            cls = hits[0]
        lines = [
            f"<clinit> present: {f'<{cls}: void <clinit>()>' in self.p.methods}",
            "JVM rule: <clinit> runs once, immediately before the first of these statements "
            "executes:",
        ]
        for m, i, how in self.p.class_refs.get(cls, []):
            if self.p.methods[m]["class"] == cls:
                continue
            lines.append(f"- {how}: {m} [{i}] {self.p.methods[m]['stmts'][i]['text']}")
        return "\n".join(lines)

    def t_entry_info(self, signature):
        sig, err = self._method(signature)
        if err:
            return err
        chain, cur, seen = [], sig, set()
        while cur in self.reach and cur not in seen:
            seen.add(cur)
            why = self.reach[cur]
            chain.append(f"{cur}: {why}")
            m = re.match(r"called from (<.*>)$", why) or re.match(
                r"class initialisation triggered in (<.*>)$", why
            )
            if not m:
                break
            cur = m.group(1)
        if not chain:
            return (
                f"{sig} is not reachable in the symbolic call graph (enabled manifest "
                f"components, lifecycle, "
                f"registered callbacks, layout onClick, direct calls, class init). Reflection and "
                f"framework-mediated dispatch (AsyncTask, Handler, Executor, Thread, Timer) are "
                f"not modelled."
            )
        return "\n".join(chain)
