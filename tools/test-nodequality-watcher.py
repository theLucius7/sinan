#!/usr/bin/env python3
"""Exercise the retained wrapper collector with the shared ownership suite."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "nodequality_retained_watcher_tests", ROOT / "tools/test-nodequality-native-watcher.py")
suite = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = suite
spec.loader.exec_module(suite)
suite.REPORT = ROOT / "plugins/nodequality/report.py"
# Actual owners must execute this entrypoint, so their collectors use the same
# selected implementation as the assertions and readiness observations.
suite.__file__ = str(Path(__file__).resolve())

if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--owner":
        suite.owner_main(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] == "ignore")
    else:
        unittest.main(module=suite)
