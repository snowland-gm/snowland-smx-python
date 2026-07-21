#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run all SMx standard conformance tests via auto-discovery and report results."""

import sys
import unittest
import os

# Add project root to path (this file lives in scripts/, so go up one level)
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TEST_DIR = os.path.join(ROOT, 'pysmx', 'test')


def main():
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=TEST_DIR,
        pattern='test_*.py',
        top_level_dir=ROOT,
    )
    runner = unittest.TextTestRunner(verbosity=1, stream=sys.stderr)
    result = runner.run(suite)

    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  TOTAL: {total} tests, {failures} failures, {errors} errors",
          file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    if failures or errors:
        for test, tb in result.failures + result.errors:
            print(f"\n--- FAILURE/ERROR: {test} ---", file=sys.stderr)
            print(tb, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
