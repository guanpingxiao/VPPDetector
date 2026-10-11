## What is VPPDetector?

VPPDetector detects potential variadic-parameter pitfalls in Python library
source. A VPP occurs when a library API's `*args` or `**kwargs` propagates to
a downstream expansion whose signature lacks the corresponding variadic
parameter. Findings identify the root API, parameter channel, forwarding
path and source locations.

VPPDetector provides three Python interfaces:

- `scan_package()` scans a whole library version for VPPs.
- `scan_api()` scans one API and its downstream forwarding paths on demand.
- `assess_change()` analyzes how one supplied parameter deletion or rename is
  handled for a specific call.

Scan results contain findings and analysis boundaries. An empty findings
collection means no VPP was detected within the supported analysis.
The `coverage` collection summarizes recorded limits separately for each
variadic channel; `no_known_boundary` does not certify complete coverage.

## Requirements

- Python 3.9 or newer
- PCResolve newer than 1.0.7 (`pcresolve>1.0.7`)

From this checkout, install the package in editable mode:

```shell
python -m pip install -e .
```

This installs PCResolve and the other declared dependencies. PCResolve supplies
program facts and call resolution in the analyzer's Python environment; the
analyzed library does not need to be installed or imported.

## Quick start

Create the following source layout, with an empty `__init__.py`:

```text
example_lib/
└── example/
    ├── __init__.py
    └── api.py
```

Put this code in `example_lib/example/api.py`:

```python
def target(allowed=0):
    return allowed


def wrapper(**kwargs):
    return target(**kwargs)


def consumed(**kwargs):
    return kwargs.pop("obsolete", 0)
```

Scan the source and print a JSON report:

```shell
python vppdetector.py example_lib
```

The report includes a finding for `wrapper` forwarding `**kwargs` to the fixed
signature of `target`, with `has_vpp: true`.

Write the report to a file:

```shell
python vppdetector.py example_lib --output report.json
```

Run `python vppdetector.py --help` for all options. The default forwarding depth
is five hops; use `--import-root` when the library needs an explicit module root.

## Python API

Python callers receive result objects directly:

```python
from vppdetector import scan_package

report = scan_package("example_lib")
print(report.has_vpp)  # True
```

Use `scan_api()` for one API or `assess_change()` for a selected changed argument
and original call. See the [API reference](docs/api.md) for complete examples,
source identities and result fields.

## Documentation

- [API reference](docs/api.md): CLI options, Python interfaces, source location,
  analysis contexts and returned objects.
- [Design](docs/design.md): detection rules, shared analysis core, module
  responsibilities and the original research scanner.
- [Analysis coverage and limits](docs/analysis-limits.md): supported propagation,
  assessment states and unresolved analysis boundaries.

The original scanner and historical outputs are retained; see
[Version 1.0 research scanner](docs/design.md#version-10-research-scanner).

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
