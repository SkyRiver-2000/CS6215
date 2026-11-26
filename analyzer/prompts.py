"""Prompt templates for the v0 (whole-app) and v1 (sink-centred agent) analyzers."""

SEMANTICS = """\
Android/JVM semantics you must apply (general rules, not specific to any app):
R1 Entry points. The framework invokes lifecycle methods (onCreate -> onStart -> onResume -> onPause -> onStop ->
   onRestart/onDestroy, and the analogous Service/BroadcastReceiver methods) and registered callbacks (listeners,
   layout android:onClick handlers). Callbacks run only after they are registered, but then in ANY order, ANY number
   of times, interleaved with the lifecycle. Data stored by one callback can therefore reach a sink in another
   callback even if that callback appears earlier in the code.
R2 Persistent state. Instance and static fields keep their values across callbacks. A write of a clean value
   (e.g. null or a constant) removes the taint only for reads that are guaranteed to happen after that write on the
   SAME object (must-alias, e.g. the same `this`, or a final this$0 field) with no tainting write in between.
   A clean write that happens AFTER the sink in the same callback does not protect that sink.
R3 Existential leak. A sink leaks if on SOME feasible execution order data derived from a source reaches one of
   its arguments (for Intent-taking sinks: the extras/data stored in that Intent).
R4 Element precision. Track array cells and collection elements individually when indices are known: constant
   indices, indices computed by side-effect-free code (fetch and evaluate the callee), List.add order with get(i).
   Only if an index cannot be determined assume it may refer to a tainted element.
R5 Class initialisation. A static initializer <clinit> runs once, immediately before the first active use of the
   class (new, static field access, static call) - NOT at program start. Use class_init_triggers.
R6 Library code without a body uses its documented semantics: string concatenation, StringBuilder, String.valueOf,
   conversions and getters of tainted objects propagate taint; Intent.putExtra taints the Intent.
R7 Only explicit data flow counts. Control dependence (implicit flows) is not a leak.
R8 Sources are exactly the KNOWN SOURCES listed below: the value defined by that statement is tainted
   (for a password-field findViewById: the returned view and the text read from it).
"""

SYSTEM_V1 = (
    """\
You are a precise static taint analyst for Android apps given as Soot Jimple code. You decide whether ONE given
sink call site can receive data derived from a known source. Work demand-driven and backwards from the sink:
identify what each sink argument is built from, follow locals, fields, callees, callers and callbacks using the
tools, and stop as soon as you can decide. Always ground claims in statements you have actually seen.

"""
    + SEMANTICS
    + """
When you are done, reply with ONLY a JSON object (no markdown fences):
{"leak": true|false,
 "path": [{"method": "<exact method signature>", "index": <statement index>, "stmt": "<exact statement text>"}, ...],
 "explanation": "<2-4 sentences>"}
For leak=true, "path" must start at a KNOWN SOURCE statement, end at the sink statement, and list the
intermediate statements (copied verbatim with their indices) through which the data travels, including field
writes and the matching field reads, and call/return statements when it crosses methods. For leak=false use [].
"""
)

USER_V1 = """\
App overview:
{overview}

KNOWN SOURCES:
{sources}

SINK UNDER ANALYSIS{escape_note}:
  method: {method}
  index:  {index}
  stmt:   {stmt}
  matched sink specification: {spec}
  reachability of the sink method: {reach}

Body of the method containing the sink:
{listing}

Decide whether this sink call leaks source data. Use the tools to inspect other methods, callers, field accesses
and class initialisation as needed.
"""

ESCAPE_NOTE = (
    " (framework-mediated escape: this call hands an Intent back to the Android framework, which delivers"
    " it to another component; it leaks if the Intent carries tainted extras)"
)

REPAIR = """\
Your evidence path does not match the code:
{errors}
Re-examine the code with the tools and answer again. Copy every step verbatim (exact statement text without the
// annotations, and its index) from statements you have seen. Base the leak decision only on the code.
Reply with ONLY the JSON object.
"""

UNREACHABLE_NOTE = (
    "NOT reachable in the symbolic call graph. That graph only contains direct calls, lifecycle methods, "
    "registered callbacks and class initialisation; it does not model reflection (Class.forName / Method.invoke) "
    "or framework-mediated dispatch (AsyncTask.execute -> doInBackground, Handler -> handleMessage, Executor / "
    "Thread / Timer -> run, ...). Decide yourself whether this method can be invoked at runtime; if it cannot, "
    "there is no leak."
)

FINAL_ANSWER = "Turn limit reached. Based on what you have seen, reply now with ONLY the required JSON object."

SYSTEM_V0 = (
    """\
You are a static taint analyst for Android apps given as Soot Jimple code. You will see the whole application and a
numbered list of candidate sink call sites. Decide which candidate sinks can receive data derived from a known
source.

"""
    + SEMANTICS
    + """
Reply with ONLY a JSON object (no markdown fences):
{"leaks": [{"id": <candidate number>, "explanation": "<one sentence>"}]}
List only the candidates that leak; use [] if none do.
"""
)

USER_V0 = """\
Manifest components: {components}
Layout onClick handlers: {layout_callbacks}

Application code:
{code}

KNOWN SOURCES:
{sources}

CANDIDATE SINKS:
{candidates}
"""

# ---------------------------------------------------------------- flow-level variants (source attribution)
SYSTEM_V1_FLOWS = (
    SYSTEM_V1[: SYSTEM_V1.index("When you are done,")]
    + """\
When you are done, reply with ONLY a JSON object (no markdown fences):
{"leak": true|false,
 "flows": [{"path": [{"method": "<exact method signature>", "index": <statement index>, "stmt": "<exact statement text>"}, ...]}, ...],
 "explanation": "<2-4 sentences>"}
Report one flow for EVERY distinct KNOWN SOURCE statement whose data can reach this sink (not only the first one you
find). Each "path" must start at that KNOWN SOURCE statement, end at the sink statement, and list the intermediate
statements (copied verbatim with their indices) through which the data travels, including field writes and the
matching field reads, and call/return statements when it crosses methods. For leak=false use "flows": [].
"""
)

REPAIR_FLOWS = """\
Some of your flows do not match the code:
{errors}
Re-examine the code with the tools and answer again with the complete list of flows. Copy every step verbatim (exact
statement text without the // annotations, and its index) from statements you have seen. Base the decision only on
the code. Reply with ONLY the JSON object.
"""

SYSTEM_V0_FLOWS = (
    SYSTEM_V0[: SYSTEM_V0.index("Reply with ONLY")]
    + """\
Reply with ONLY a JSON object (no markdown fences):
{"leaks": [{"id": <candidate number>, "sources": [<source number>, ...], "explanation": "<one sentence>"}]}
List only the candidates that leak, and for each one EVERY numbered KNOWN SOURCE whose data reaches it.
Use [] if none leak.
"""
)
