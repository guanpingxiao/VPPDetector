# Changelog

## 1.1.0 - Unreleased

### Added

- Importable `scan_package()`, `assess_change()`, and `assess_changes()` APIs.
- Typed request, result, finding, boundary, and repair-recommendation models.
- PCResolve-backed cross-file call-target and variadic value-flow analysis.
- Multi-hop `**kwargs` propagation with configurable depth and recursion guards.
- Standalone `scan` and `assess` CLI commands with JSON output.
- Verified source-encoding detection with a legacy-compatible `getEncoding()`
  alias.
- Explicit `safe`, `must_fail`, `may_fail`, `unknown`, and `not_applicable`
  verdicts.
- Tests for aliases, re-exports, async functions, overloads, receivers,
  repeated call sites, mutation, branching, and unresolved dynamic targets.

### Changed

- The original 1.0 dataset script is retained in `legacy_vppdetector.py`.
  Running `python vppdetector.py` remains its compatibility entry point.
- Findings no longer collapse multiple calls to the same callee name.
- Parse and resolution uncertainty is reported rather than silently ignored.

### Known boundaries

- Element-level `*args` compatibility assessment is not implemented yet.
- Complex mapping mutation and indirect parameter transformations return
  `unknown`.
- Constructor calls that PCResolve cannot resolve exactly remain `unknown`;
  VPPDetector does not fall back to class-name matching.
- API evolution detection and whole-version comparison remain outside
  VPPDetector.
