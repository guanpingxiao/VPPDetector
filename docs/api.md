# API reference

[Project overview and installation](../README.md) ·
[Design](design.md) · [Analysis coverage and limits](analysis-limits.md)

The examples use the source layout and three functions from the
[quick start](../README.md#quick-start). Run them from the directory containing
`example_lib/`.

## Whole-package CLI

```shell
python vppdetector.py example_lib
python vppdetector.py example_lib --output report.json
```

| Argument | Meaning |
| --- | --- |
| `package_root` | Source directory or Python source file to scan. |
| `--import-root` | Directory used to form Python module names; may be repeated. |
| `--max-depth` | Positive forwarding-hop limit, default five. Source-resolved return-producing calls also count as hops. |
| `--output` | JSON destination in an existing directory. Without it, the report is printed to standard output. |

Run `python vppdetector.py --help` for the option list.

## Python interfaces

`scan_package()`, `scan_api()` and `assess_change()` accept a source path
(`str` or `pathlib.Path`) or a `SourceContext`. All three accept keyword-only
`import_roots`, `max_depth` and `context` arguments. `max_depth` defaults to
five and must be a positive integer.

### Whole-library scan

`scan_package(package_root, *, import_roots=None, max_depth=5, context=None)`
returns a `ScanReport`.

```python
from vppdetector import scan_package

report = scan_package("example_lib")
print(report.has_vpp)
for finding in report.findings:
    print(finding.function, finding.parameter_kind, finding.target)
    for step in finding.path:
        print(step.function, step.callee_expression, step.callsite)
```

### On-demand API scan

`scan_api(package_root, target_api, *, import_roots=None, max_depth=5, context=None)`
returns a `ScanReport` for the selected `FunctionIdentity`.

```python
from pathlib import Path

from vppdetector import AnalysisContext, FunctionIdentity, SourceContext, scan_api

source = SourceContext(Path("example_lib"))
context = AnalysisContext.from_source(source)
report = scan_api(
    source,
    FunctionIdentity("example.api", "wrapper"),
    context=context,
)
print(report.has_vpp)
```

On-demand scans resolve the requested API to its source implementation.
Findings retain the requested API identity, while path steps identify the
implementations along the forwarding path.

### Scan report

Python callers receive a `ScanReport`; the standalone CLI serializes it to
JSON.

| Field | Meaning |
| --- | --- |
| `source` | Source scope and import roots used by the scan. |
| `has_vpp` | Whether at least one structural finding was detected. |
| `functions_scanned` | Indexed, non-overload function entries considered in this scope. |
| `variadic_functions` | Variadic entries with their parameter names and `VariadicKind` channels. |
| `findings` | Root API, variadic channel, downstream target, source locations and forwarding path. |
| `boundaries` | Unresolved targets, unsupported effects and other analysis limits. |
| `coverage` | One `VariadicCoverage` record per root variadic channel: observed status, finding count and boundary codes. |
| `target_api` / `resolved_api` | Requested and resolved implementation identities for an on-demand scan; absent for a whole-package scan. |
| `analyzer_schema_version` | PCResolve program-fact schema version. |

Each `ForwardingFinding` retains the root function, variadic parameter name and
kind, callee expression, callsite, target, reason code and path.
`ForwardingStep` records a source or proven builtin-protocol hop. Findings and steps retain
`target_status`; findings can also retain target candidates and receiver-type
evidence.

Paths may include source-proven builtin copy/conversion steps. These steps use
the `builtins` module, omit unavailable source locations and retain
`target_status="local_container_protocol"`. Each copy/conversion consumes one
forwarding hop, including copies composed with source-return and closure paths.

Scan boundaries retain the implementation owner in `function` and, when a
root channel is known, its `root_function`, `parameter_name` and
`parameter_kind`. API scans use the requested identity for the root and the
actual implementation for the diagnostic owner. Source-scope boundaries and
assessment boundaries need not have a root channel.

`VariadicCoverage.status` is `unavailable` when the root flow analysis fails,
`limited` when relevant or source-scope boundaries are recorded, and
`no_known_boundary` otherwise. The last status means no limitation was
recorded by the supported analysis; it does not establish complete coverage
or prove a negative. Findings can coexist with either of the other recorded
limits. Each record also retains `finding_count`, unique `boundary_codes`
and, for an API alias, its `implementation`. Missing API identities have no
invented channels: `coverage` is empty and the entry boundary explains why.

Enums serialize to lowercase strings, such as `var_keyword`; paths serialize
to strings and tuples to arrays. See
[result interpretation](analysis-limits.md#interpreting-scan-results) for the
difference between findings and analysis boundaries.

## Source identities and contexts

`SourceContext.package_root` selects the source scope. An import root is the
directory relative to which Python module names are formed, not necessarily
the package directory itself.

In the quick-start example, the module is `example.api`, the function's
`qualname` is `wrapper`, and its file is `example_lib/example/api.py`.
For methods, use a qualified name such as `Client.fetch`.

| Source scope | Default import root |
| --- | --- |
| Package directory containing `__init__.py` | Its parent directory. |
| Project directory containing `src/` | The `src/` directory. |
| Other source directory | The directory itself. |
| One source file | Its parent directory. |

Supply `SourceContext(..., import_roots=(Path(...),))` or CLI `--import-root`
when these defaults do not match the source layout. A `FunctionIdentity` can
include `file_path` and `lineno`: the file must lie within the source scope,
and the line must match the indexed definition. The file identifies library
implementation code, not a client file.

### Reusable analysis context

`AnalysisContext.from_source(source)` prepares a full-source context for
whole-package scanning or multiple on-demand analyses in the same source
version.

When the implementation file is known, prepare a smaller context:

```python
from pathlib import Path

from vppdetector import AnalysisContext, FunctionIdentity, SourceContext, scan_api

source = SourceContext(Path("example_lib"))
target = FunctionIdentity(
    "example.api", "wrapper", file_path=source.package_root / "example" / "api.py"
)
context = AnalysisContext.for_api(source, target)
report = scan_api(source, target, context=context)
print(report.has_vpp)
```

`for_api()` indexes the located file, package initializers and explicit imports
within the source root. It also works with `assess_change()`. Without a file
hint it uses full-source preparation.

A context must use the requested source root and import roots. Reuse it only
for definitions and dependencies already in its fixed file set and while the
source snapshot is unchanged. An entry outside that set needs a new context
or a full-source context. Whole-package scanning requires a full-source context.

## Parameter-level assessment

`assess_change(source, target_api, change, call, *, import_roots=None, max_depth=5, context=None)`
returns a `ParameterAssessment`.

| Input | Meaning |
| --- | --- |
| `source` | New source snapshot as a path or `SourceContext`. |
| `target_api` | Selected API as a `FunctionIdentity`. |
| `change` | One supplied `ParameterChange`: `ChangeKind.DELETE` or `ChangeKind.RENAME`. |
| `call` | Original call expression, `ast.Call` or `CallContext`. |

A `ParameterChange` includes `old_name`; a rename also requires `new_name`.
Its optional `old_position` selects a zero-based position in the original
call's expanded positional argument list. An implicit method receiver is not
part of that list; an explicitly supplied receiver in an unbound call is.
The caller supplies this position; assessment does not infer it from versions
or parameter names.

An explicitly supplied `old_name` selects keyword assessment through
`**kwargs`, even when position metadata is present. Otherwise, `old_position`
selects an element captured by the new implementation's `*args`. A position
still bound to an explicit new parameter, an absent position or an unknown
expansion remains unresolved.

Finite tuple/list expansions, aliases, constant indices and slices, and
same-kind sequence concatenation retain element order. For example, with
`forward(*args)` calling `target(first=0)`, `forward(7)` handles element zero;
`forward(7, 9)` rejects element one. The structural forwarding pattern alone
does not determine either result.

```python
from pathlib import Path

from vppdetector import (
    AnalysisContext,
    ChangeKind,
    FunctionIdentity,
    ParameterChange,
    SourceContext,
    assess_change,
)

source = SourceContext(Path("example_lib"))
target = FunctionIdentity(
    "example.api", "wrapper", file_path=source.package_root / "example" / "api.py"
)
context = AnalysisContext.for_api(source, target)

assessment = assess_change(
    source,
    target,
    ParameterChange(ChangeKind.DELETE, "obsolete"),
    "wrapper(obsolete=7)",
    context=context,
)
print(assessment.state.value)  # rejected
```

For the same source, `wrapper(allowed=7)` with a supplied change for `allowed`
is `handled`, as is `consumed(obsolete=7)` with a change for `obsolete`.
Assessment can run directly, without a structural scan first.

### Assessment result

`ParameterAssessment` retains `target_api`, `resolved_api`, `change`, the
normalized original `call_text` and an optional `callsite`. Its `state` is a
`ParameterState` enum with serialized values `handled`, `rejected`, `ignored`
and `unknown`. `reason` explains the outcome; `evidence` records supporting
bindings, uses and paths, and `boundaries` records analysis limits.

Evidence with reason `normal_path_precondition` retains a condition required
to proceed past a supported unrelated error-only guard. It is not an observed
guard value. The result then describes parameter handling on that normal path;
see [normal-path preconditions](analysis-limits.md#normal-path-preconditions).

Evidence with reason `source_classmethod_binding` records PCResolve's
source-snapshot assumptions for static classmethod signature binding. It does
not represent an observed runtime target; see
[binding evidence](analysis-limits.md#supplied-call-facts).

Evidence with reason `ordinary_container_forwarding` records a supported helper
hop carrying the selected finite dictionary or sequence contents. It is not a
rejection or acceptance by itself. `proven_guard_rejection` records an explicit
exception on a supported captured-key rejection branch; it does not establish
that a proposed parameter deletion makes the entire program run successfully.

See [assessment states](analysis-limits.md#assessment-states) for the meaning
of each result.

### Additional call facts

`CallContext` can carry finite facts specific to the supplied call:

- `bound_receiver`: overrides the indexed method convention for an unbound call.
- `known_values`: trusted primitive constants under source parameter names or
  receiver attribute paths, such as `(("self.closed", False),)`.
- `known_targets`: exact library `SourceSpan` locations paired with confirmed
  `FunctionIdentity` implementations.
- `callsite`: optional location of the original call.

Known values accept `str`, `bytes`, `int`, `float`, `bool` and `None`;
`None` is distinct from an unknown value. Names and known-target locations
must be unique. The facts must describe this call and this source version.
The analyzer reads expressions statically rather than executing their values.
