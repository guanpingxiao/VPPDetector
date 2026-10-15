# Analysis coverage and limits

[Project overview](../README.md) · [API reference](api.md) · [Design](design.md)

## Interpreting scan results

A positive finding records an API's variadic container reaching an expansion
into a downstream signature without the corresponding variadic parameter.
`has_vpp` is true when the findings collection is nonempty.

`boundaries` separately records unresolved targets, unsupported effects and
other analysis limits. An empty findings collection means no VPP was detected
within the supported analysis; inspect the boundaries to understand coverage.

`coverage` summarizes findings and recorded limits for each root `*args` or
`**kwargs` channel. Its status is `unavailable` for a root analysis failure,
`limited` when a boundary is recorded, or `no_known_boundary` when none is
recorded. No status certifies complete coverage. A finding and a limitation
can coexist; neither the absence of findings nor the absence of recorded
boundaries proves that no propagation exists.

Channel-specific scan boundaries identify `root_function`, `parameter_name`
and `parameter_kind`, while `function` and `callsite` identify the stopping
point, which may be in a downstream helper. Source-scope failures apply to
all considered channels. Missing source/API entries remain report-level
boundaries without fabricated coverage records.

Findings and forwarding steps retain `target_status`. A source candidate
identifies a potential implementation rather than confirmed runtime dispatch.
Structural findings therefore describe forwarding patterns, not the failure
of every call to that API. A fixed downstream signature may accept a particular
argument name, or the library may consume it before forwarding the remainder.
Use parameter-level assessment to examine that argument under a supplied call.

## Scan coverage

Supported analysis includes:

- Functions, methods and `async def`.
- Cross-file imports, aliases, public class re-exports and inherited methods.
- Source constructor entries using `__init__`, otherwise `__new__`.
- Bounded multi-hop forwarding through ordinary mapping or sequence parameters.
- Source-resolved helpers returning a whole container, including selection
  through exact nonnegative tuple return slots.
- Incoming receiver and callable contexts supplied by PCResolve for supported
  exact call edges.
- Proven returned-object aliases and complete finite constant-key removal
  facts that preserve an open remainder.
- Bounded builtin dict copies and dict/list/tuple conversions, when PCResolve
  supplies matching copy effects, object identity and current contents.
- Immediately invoked synchronous source closures with exact call-time captured
  container shapes and current open contents; nested named scopes can relay
  the same capture within the forwarding depth limit.
- Source-selected lambdas, indexed by their lexical owner and exact line/column
  identity. Their expression body is exposed as a return-statement view, without
  compiling or executing it; same-line lambdas remain distinct.

Passing a container as an ordinary argument is a propagation hop, not a
finding by itself. A finding requires an eventual expansion into a signature
without the corresponding variadic parameter. Selected input elements and
finite contents are distinguished from an open variadic container.

### Returns and mutation

For a proven returned-object alias, the scanner uses separately materialized
current contents rather than old input dependencies. Removing modeled finite
keys retains the open remainder; clearing an alias does not restore its
original contents. Object identity alone is insufficient to establish
variadic propagation.

Copy proofs are checked against the producing call, its indexed source witness,
the exact input/output objects and normal-completion effects. The scanner reads
current contents at the expansion; it does not restore a cleared copy from old
input dependencies. Copies can retain an independent open remainder after the
original is cleared. Paths record builtin copy/conversion steps under `builtins`
with `target_status="local_container_protocol"`; each step counts toward depth.
Missing, conflicting or effect-uncertain facts remain boundaries.

Complete ordinary-parameter constant-key removal facts can preserve propagation
through an existing alias. Normal-return effects describe that return path,
rather than unconditional removal on exception paths.
Complete same-module helper effects can also preserve returned-object identity
through bounded finite-key deletion wrappers. Unused direct helper calls must
resolve to stable undecorated functions with fully bound ordinary-name inputs;
unknown keys, shadowed targets, unsupported effects and recursive/budget-limited
composition retain boundaries. This does not infer general helper purity.

### Dispatch and decoration

Classmethod and `__new__` helper forwarding retains source-proven incoming
receiver contexts. Ordinary helpers retain incoming source-callable bindings
when PCResolve provides an exact call-edge context.

Missing or mixed incoming contexts remain boundaries. Mutable configuration
attributes and class-context container returns are not inferred. Callable
targets are not inferred from names or strings. Ambiguous constructor
definitions are not replaced with a guessed entry.

When a decorated callable has a proven identity but unmodeled effects, the
scanner does not use its body to prove container returns or further
forwarding. A direct expansion against its nominal signature can still produce
a structural finding, retaining the effects diagnostic.

### Unresolved propagation

Unknown effects on returned containers and transformations without open-shape
facts remain boundaries. Examples include comprehensions, copies and slices
when the required shape facts are unavailable.

Carrier receiver operations preserve PCResolve's specific effect diagnostics
even when no ordinary argument flow was produced. Locally resolved callables
with captured channel dependencies report `closure_capture_not_followed` when
their current capture facts, synchronous execution or unique call context
cannot be established. Proven immediate captures are followed using isolated
edge expansion, retaining call-time rebinding and modeled mutations. Generator
and async callable bodies are not inferred to execute merely from a call.
Unmodeled writes or effects retain boundaries;
returned local callables with lexical captures report
`deferred_callable_not_followed`. These diagnostics describe unmodeled
propagation, not newly established forwarding paths. Lexical capture does
not prove the current captured value, and returned-callable execution is
outside the immediate scan path. Shadowed local parameters are not captures.

Unresolved targets, unsupported propagation, recursion and depth limits also
remain visible diagnostics. The default depth limit is five hops;
source-resolved return-producing calls count toward the limit.

Recorded flow conditions contradicted by matching constant source syntax are
excluded from findings, including literal truth values, `not` and decisive
`and`/`or` expressions. Other conditions remain potential paths. This does not
solve general path feasibility, infer caller values or change a structural
finding into a parameter-level compatibility decision.
If joined contents cannot be separated from an impossible object context,
the scanner retains `return_object_unproven` rather than treating the object's
materialized input dependencies as independent propagation.

## Source-scope boundaries

Module names follow the source context's import roots. File/name/line conflicts
and unavailable implementations remain unresolved rather than guessed.
Definitions in conditional statement blocks, including class methods in an
exception handler, retain their lexical source identity. PCResolve records
`conditional_definition_unconfirmed` with activation conditions; a located
entry does not prove the branch is active at runtime. Duplicate conditional
names require an exact location, and constant-inactive definition conditions
cannot supply a forwarding path.

API-scoped preparation follows explicit imports within the source root.
Dynamic dependencies are not inferred, so an import closure describes a
bounded source scope rather than complete runtime coverage.

Reuse an analysis context only within its fixed file set and unchanged source
snapshot. An API-scoped context cannot be used for whole-package scanning.
See [source identities and contexts](api.md#source-identities-and-contexts)
for scope selection and context construction.

## Assessment states

Each assessment describes one selected changed argument under the supplied
call conditions and any recorded normal-path preconditions.

| State | Meaning |
| --- | --- |
| `HANDLED` | The argument's value or presence is used, or its value binds to a downstream explicit parameter. |
| `REJECTED` | Supported conditions lead to a parameter-specific binding rejection or an explicit captured-key rejection. |
| `IGNORED` | Supported executed paths do not use the argument's value or presence. |
| `UNKNOWN` | Binding, control flow, dispatch or effects prevent a definite result. |

These are argument-handling states. Behavioral equivalence between library
versions and code modification are outside this analysis. In particular,
unused arguments and unresolved analysis do not establish that a deletion or
rename is safe, and rejection evidence does not establish that a proposed
modification succeeds.

### Assessment coverage

Current assessment covers changed keywords captured by `**kwargs` and selected
positional elements captured by `*args`, regardless of the container's name.
Supported cases include direct/alias forwarding, finite expansions, bounded
`pop` effects, simple literal/default-value guards and source-resolved
downstream binding.

Finite string-key dictionary displays can merge known mappings. Later keys
overwrite earlier values, while duplicate keys in a call's keyword expansions
retain Python's binding rejection. Unknown mappings remain unresolved. Passing
the resulting carrier as an ordinary dictionary parameter does not by itself
prove that a downstream validator accepts its contents.

Finite dictionaries and sequences can pass through ordinary helper parameters
when the call target and exact parameter binding are supported by PCResolve.
Assessment follows the helper body with the same selected contents and depth
budget; merely accepting the container is not acceptance of its contents.
Unresolved callable-instance candidates and dynamic override boundaries are
not promoted to confirmed targets.

For finite string-key dictionaries, assessment supports unshadowed built-in
`set(mapping)`, key-set difference and singleton `list(keys)` projection.
The selected key is tracked separately from other keys. An established
key-presence rejection branch can report `proven_guard_rejection` for a built-in
exception constructed from finite primitive arguments or a simple finite
formatted message. Unknown keys, ambiguous set iteration order, shadowed
protocols, exception recovery and arbitrary value-constraint failures remain
unresolved. Disjunctions and rejection in the opposite branch are outside this
narrow proof. A shallow dictionary copy requires a matching bounded PCResolve
copy fact; other mutations still require their own effect evidence.

For a single decorated entry/body, an exact PCResolve `decorator_effects` fact
can permit analysis of the original body when both identity and body/binding
are preserved. The fact must match the source definition, decoration span and
source hashes, with no unresolved or conflicting effects. Its normal-completion
scope and source assumptions are recorded as `source_decorator_binding`
evidence. Identity alone, missing facts, code/default changes and unsupported
decorator composition remain unresolved; independent call boundaries still apply.

A closed proof may include source-helper calls, documentation-cache construction,
conditional `setdefault` effects and mapping lookups alongside `__doc__` writes.
These records support the overall preservation proof; they do not independently
prove that a helper or cache is harmless. Partial records in an unresolved proof
do not permit body analysis, and input-function writes other than `__doc__`
remain unsupported.

Finite guards support `isinstance()` against unshadowed built-in `str`, `bytes`,
`int`, `float`, `bool` and `object` types, and `startswith()` / `endswith()` on
known strings with one known string argument. Unknown values, shadowed built-ins
and unsupported predicate arguments remain unresolved; source code is not run.

Positional assessment preserves finite sequence order through constant indices,
slices, same-kind concatenation and expansion. Rejection requires the selected
value to reach a slot beyond a callee's positional capacity or another supported
parameter-specific binding conflict. An error caused only by another supplied
element does not license rejecting the selected one. Unknown-length expansions,
sequence unpacking, unproven ordinary-container calls and unsupported mutations
remain boundaries rather than assumptions about argument acceptance.

### Normal-path preconditions

An unknown simple guard that only raises an unrelated exception need not stop
parameter analysis. The analyzer records a `normal_path_precondition` in
`evidence` and continues along the normal path, without assigning a value to
the guard or the receiver attribute. This applies only to supported plain
reads, a single unshadowed built-in exception construction with constant
arguments, and an empty or `pass`-only alternative branch.

An available guard value still selects the actual supported branch. Parameter
consumption, early returns, exception recovery, calls in the condition or
message, and source-known custom receiver getters are not bypassed. Results
with preconditions describe argument handling on the normal path, not proof
that a particular invocation reaches it.

Exception recovery, unknown mutation, deferred execution and unsupported
transformations remain explicit boundaries. An absent selected argument or one
not captured by the target's corresponding variadic parameter also yields an
unresolved assessment.

### Supplied call facts

Additional facts must describe the supplied call and source version. A nominal
PCResolve candidate does not independently confirm a runtime target; uncertain
class dispatch remains `UNKNOWN` without supporting binding evidence.

For a built-in classmethod, a PCResolve `source_bound` fact can establish static
signature binding under its source-snapshot assumptions. The target, implicit
receiver and all incoming analysis contexts must agree, with no binding issues
or remaining dispatch uncertainty. The assessment records those assumptions as
`source_classmethod_binding` evidence; this is not runtime target confirmation.
Visible rebinding, incomplete mutation analysis and conflicting contexts remain
unresolved. This does not authorize bypassing decorated helper bodies.

A directly constructed module-level callable can be assessed when PCResolve
supplies a matching `source_bound` callable-instance binding and finite
constructor state. The target, receiver, source definition, snapshot hashes,
assumption boundaries and incoming contexts must agree. The assessment records
`source_callable_instance_binding`; it does not confirm runtime dispatch.
Custom construction/lookup, visible writes, escapes and incomplete state retain
uncertainty. Known constructor attributes can select finite conditional
expressions, but unproved writes or untracked helper effects on that state stop
assessment. An exact ordinary dict binding can support a bounded copy before
unproved prior uses; it does not generally enable ordinary-container mutation.

The analyzer does not execute client argument expressions or load runtime
object graphs. Context caches retain program facts, while each assessment
uses its own call conditions.
