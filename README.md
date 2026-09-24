# VPPDetector

VPPDetector analyzes propagation of Python variadic parameters. The current
repository is a research scanner and an incubation area for analysis that may
later be integrated into PCART. It is not positioned as an
independently published PyPI product.

The code has two responsibilities:

1. `scan_package()` scans one library version for latent variadic-parameter
   forwarding mismatches.
2. The internal `assess_change()` prototype analyzes one already-detected
   parameter deletion or rename against the target implementation.

VPPDetector does not compare every API in two library versions. API matching
and parameter-change detection remain the responsibility of clients such as
PCART. The scanner is the standalone workflow. Change-conditioned assessment
is an internal analysis boundary intended to refine PCART's existing
compatibility and repair pipeline rather than become another user-facing
command.

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
the package root. On Windows, use the corresponding PowerShell line
continuation syntax or enter the command on one line.

The root script is intentionally a thin scan entry point. The original
dataset-oriented implementation remains in `legacy_vppdetector.py` for
research reproducibility.

## Analysis API

### Single-version scan

```python
from vppdetector import scan_package

report = scan_package("/sources/example")
for finding in report.potential_pitfalls:
    print(finding.function, finding.target, finding.callsite)
```

The scanner uses PCResolve for exact cross-file call targets and records every
forwarding call site independently. It supports functions, methods,
`async def`, imports, and aliases covered by PCResolve.

### Internal change refinement

```python
from pathlib import Path

from vppdetector import (
    ChangeKind,
    FunctionIdentity,
    ParameterChange,
    SourceContext,
    VPPRequest,
    VariadicKind,
    assess_change,
)

request = VPPRequest(
    source=SourceContext(Path("/sources/example")),
    target_api=FunctionIdentity("example.api", "wrapper"),
    change=ParameterChange(
        kind=ChangeKind.DELETE,
        old_name="callback",
        captured_by="kwargs",
        capture_kind=VariadicKind.KEYWORD,
    ),
)

assessment = assess_change(request)
print(assessment.verdict, assessment.argument_effect)
```

The assessment returns propagation effects, downstream evidence, and analysis
boundaries. It deliberately does not select a delete, rename, or preserve
repair action; that policy belongs to PCART.

When PCResolve reports constructor-backed chained receivers, assessment and
scan findings retain the bounded source target candidates and receiver-type
evidence. A candidate is not treated as certain runtime dispatch: dynamic
accessor and method overrides remain explicit uncertainty, and a rejecting
candidate can establish at most a possible failure.

Current assessment support intentionally starts with direct `**kwargs`
propagation and follows resolved `**kwargs` forwarding across multiple local
functions. For a concrete call site, a narrow guard proof can also identify
when the changed keyword is the sole captured key and a known `None` argument
causes an uncaught, first-statement `if ... and kwargs: raise` branch. It
supports direct calls and side-effect-free direct forwarding; uncertain values,
other captured keys, and dynamic or conditional forwarding remain conservative.
Unresolved targets, unsupported transformations, recursion/depth exhaustion,
and most element-level `*args` tracking produce explicit `unknown` results and
analysis boundaries. The default forwarding depth is five and can be set on
`VPPRequest.max_depth`. `assess_changes()` reuses analysis state for requests
against the same source version.

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
