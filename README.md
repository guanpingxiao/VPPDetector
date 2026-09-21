# VPPDetector

VPPDetector analyzes propagation of Python variadic parameters. Version 1.1
introduces two core responsibilities:

1. `scan_package()` scans one library version for latent variadic-parameter
   forwarding mismatches.
2. `assess_change()` evaluates one already-detected parameter deletion or
   rename against the target implementation.

VPPDetector does not compare every API in two library versions. API matching
and parameter-change detection remain the responsibility of clients such as
PCART. VPPDetector refines whether a change hidden by `*args` or `**kwargs`
will be accepted by downstream calls.

## Requirements

- Python 3.9 or newer
- PCResolve 1.0.6 or newer, below 2.0

Install the package in editable mode during development:

```shell
python -m pip install -e .
```

## Python API

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

### Targeted change assessment

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
print(assessment.verdict, assessment.recommended_action)
```

All in-process communication uses typed Python objects. JSON is only a CLI
and report boundary.

Current assessment support intentionally starts with direct `**kwargs`
propagation and follows resolved `**kwargs` forwarding across multiple local
functions. Mutation of a propagated mapping, unresolved targets, indirect
transformations, recursion/depth exhaustion, and element-level `*args`
tracking produce explicit `unknown` results and analysis boundaries. The
default forwarding depth is five and can be set on `VPPRequest.max_depth`.

## Command line

Scan one source version and print a JSON report:

```shell
vppdetector scan /sources/example
```

Write the report to a file:

```shell
vppdetector scan /sources/example --output report.json
```

Assess one known deletion:

```shell
vppdetector assess /sources/example \
  --module example.api \
  --qualname wrapper \
  --change delete \
  --old-name callback \
  --captured-by kwargs \
  --capture-kind var_keyword
```

Use repeated `--import-root` options when module names cannot be derived from
the package root. On Windows, use the corresponding PowerShell line
continuation syntax or enter the command on one line.

## Version 1.0 research scanner

`python vppdetector.py` remains a compatibility entry point for the original
dataset-oriented scanner. Its implementation is retained in
`legacy_vppdetector.py`; it depends on PCART internals and contains
dataset-specific paths. New integrations should use the package API.

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
