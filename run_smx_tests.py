#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run all SMx standard conformance tests and report results."""

import sys
import unittest
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import test modules
from pysmx.test.test_sm2 import TestSM2Standard
from pysmx.test.test_sm3 import TestSM3Standard
from pysmx.test.test_sm4 import TestSM4Standard
from pysmx.test.test_sm9 import TestSM9Standard
from pysmx.test.test_zuc import TestZUCStandard, TestZUCAlgorithm


def run_suite(name, test_class):
    suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stderr)
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  {name}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    result = runner.run(suite)
    return result


def main():
    results = {}

    results['SM3'] = run_suite("SM3 (GB/T 32905-2016)", TestSM3Standard)
    results['SM4'] = run_suite("SM4 (GB/T 32907-2016)", TestSM4Standard)
    results['SM2'] = run_suite("SM2 (GB/T 32918-2016)", TestSM2Standard)
    results['SM9'] = run_suite("SM9 (GMT 0044-2016)", TestSM9Standard)
    results['ZUC'] = run_suite("ZUC (GB/T 33133-2016)", TestZUCStandard)
    results['ZUC_Alg'] = run_suite("ZUC Algorithm", TestZUCAlgorithm)

    # Summary
    total = 0
    failures = 0
    errors = 0
    for name, r in results.items():
        t = r.testsRun
        f = len(r.failures)
        e = len(r.errors)
        total += t
        failures += f
        errors += e
        status = "PASS" if (f == 0 and e == 0) else "FAIL"
        print(f"  {name:15s}: {t:3d} tests, {f:2d} fail, {e:2d} errors  [{status}]",
              file=sys.stderr)

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  TOTAL: {total} tests, {failures} failures, {errors} errors", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    if failures or errors:
        # Print failure details
        for name, r in results.items():
            for test, traceback in r.failures + r.errors:
                print(f"\n--- {name} FAILURE/ERROR ---", file=sys.stderr)
                print(traceback, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
