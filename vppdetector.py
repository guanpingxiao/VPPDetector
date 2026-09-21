"""Compatibility entry point for the VPPDetector 1.0 research script.

Importing ``vppdetector`` selects the package API. Executing this file keeps
the original dataset-oriented command available for reproducibility.
"""

import runpy


if __name__ == "__main__":
    runpy.run_module("legacy_vppdetector", run_name="__main__")
