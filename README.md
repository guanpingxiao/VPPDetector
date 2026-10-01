# VPPDetector

VPPDetector detects potential variadic-parameter pitfalls in Python library
source. A VPP occurs when a library API's `*args` or `**kwargs` propagates to
a downstream expansion whose signature lacks the corresponding variadic
parameter. Findings identify the root API, parameter channel, forwarding
path and source locations.

Two scan scopes share the same detection core:

- `scan_package()` scans a whole library version for VPPs.
- `scan_api()` scans one API and its downstream forwarding paths on demand.

Both return a `ScanReport` with positive findings and `has_vpp`. Analysis
limits are recorded separately in `boundaries`; an empty findings collection
means no VPP was detected within the supported analysis, rather than proof
that all dynamic Python behavior is compatible.

VPPDetector uses PCResolve for program facts and call resolution. API matching,
parameter-change detection, repair selection and repair verification belong
to PCART. The repository remains a research scanner and an incubation area
for later PCART integration, without a separate PyPI release.

## Requirements

- Python 3.9 or newer
- PCResolve 1.0.6 or newer, below 2.0

Install the package in editable mode during development:

```shell
python -m pip install -e .
```

## Whole-package scan

Scan one source version and print a JSON report:

```shell
python vppdetector.py /sources/example
```

Write the report to a file:

```shell
python vppdetector.py /sources/example --output report.json
```

Use repeated `--import-root` options when module names cannot be derived from
the package root. The root script remains a thin whole-package scan entry
point, with optional JSON output for standalone use.

## Python API

### Whole-library scan

```python
from vppdetector import scan_package

report = scan_package("/sources/example")
print(report.has_vpp)
for finding in report.findings:
    print(finding.function, finding.parameter_kind, finding.target)
    for step in finding.path:
        print(step.function, step.callee_expression, step.callsite)
```

### On-demand API scan

```python
from pathlib import Path

from vppdetector import AnalysisContext, FunctionIdentity, SourceContext, scan_api

source = SourceContext(Path("/sources/example"))
context = AnalysisContext.from_source(source)
report = scan_api(
    source,
    FunctionIdentity("example.api", "wrapper"),
    context=context,
)
print(report.has_vpp)
```

Reusing an `AnalysisContext` retains the source index and analysis caches for
multiple APIs from the same library version. Both scan functions accept
`max_depth` (default five) and optional `import_roots`. On-demand scans resolve
the requested API to its source implementation; findings retain the requested
API identity and the path retains implementation identities.

The scanner supports functions, methods, `async def`, cross-file imports,
aliases and bounded multi-hop propagation covered by PCResolve. Passing a
mapping or sequence as an ordinary parameter is a propagation hop, not a VPP
by itself; a finding requires an eventual `**mapping` or `*sequence` expansion
into a signature without the matching variadic parameter. Unresolved targets,
unsupported propagation, recursion and depth limits remain visible diagnostics.
Source-candidate paths retain their target status: a finding does not establish
exact runtime dispatch or prove that a particular client call will fail.

For future PCART integration, an on-demand VPP result can determine whether
the existing variadic-parameter preservation rule applies. The returned
Python objects do not select a deletion or rename and do not assess a concrete
client call's compatibility.

## Version 1.0 research scanner

The original implementation is retained in `legacy_vppdetector.py`; it
depends on PCART internals and contains dataset-specific paths. It is no longer
the default `vppdetector.py` entry point.

Historical outputs under `APIDefWithVariadicPara/` and
`VariadicParaPitfalls/` are unchanged.

## Publication

```bibtex
@inproceedings{zhang2024coding,
  title={Coding Pitfalls: Demystifying the Potential API Compatibility Risk of Variadic Parameters in Python},
  author={Zhang, Shuai and He, Gangqiang and Xiao, Guanping},
  booktitle={2024 IEEE 35th International Symposium on Software Reliability Engineering Workshops (ISSREW)},
  pages={105--106},
  year={2024},
  organization={IEEE}
}
```

## License

VPPDetector is licensed under GNU AGPLv3. PCResolve is an MIT-licensed
dependency; see `THIRD_PARTY_NOTICES.md`.
