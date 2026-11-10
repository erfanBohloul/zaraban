#!/usr/bin/env python3
"""Automated Matrix Runner for Zaraban.

Validates all 4 patch scenarios across both Target 1 (token_parser) and Target 2 (cJSON):
1. Target 1 - Correct Patch     -> Expected Exit Code: 0 (PASS)
2. Target 1 - Incomplete Patch  -> Expected Exit Code: 10 (VULN_OR_NEW_ISSUE)
3. Target 1 - Regression Patch  -> Expected Exit Code: 20 (FUNC_REGRESSION)
4. Target 2 - Correct Patch     -> Expected Exit Code: 0 (PASS)
5. Target 2 - Incomplete Patch  -> Expected Exit Code: 10 (VULN_OR_NEW_ISSUE)
6. Target 2 - Regression Patch  -> Expected Exit Code: 20 (FUNC_REGRESSION)
"""

import subprocess
import sys
from pathlib import Path

SCENARIOS = [
    {
        "name": "Target 1 (token_parser) - Correct Patch",
        "config": "targets/target1_sample/zaraban.yaml",
        "base_dir": "targets/target1_sample",
        "patch_dir": "targets/target1_sample/versions/patch_correct",
        "diff": "targets/target1_sample/patches/correct.patch",
        "expected_code": 0
    },
    {
        "name": "Target 1 (token_parser) - Incomplete Patch",
        "config": "targets/target1_sample/zaraban.yaml",
        "base_dir": "targets/target1_sample",
        "patch_dir": "targets/target1_sample/versions/patch_incomplete",
        "diff": "targets/target1_sample/patches/incomplete.patch",
        "expected_code": 10
    },
    {
        "name": "Target 1 (token_parser) - Regression Patch",
        "config": "targets/target1_sample/zaraban.yaml",
        "base_dir": "targets/target1_sample",
        "patch_dir": "targets/target1_sample/versions/patch_regression",
        "diff": "targets/target1_sample/patches/regression.patch",
        "expected_code": 20
    },
    {
        "name": "Target 2 (cjson_parser) - Correct Patch",
        "config": "targets/target2_cjson/zaraban.yaml",
        "base_dir": "targets/target2_cjson",
        "patch_dir": "targets/target2_cjson/versions/patch_correct",
        "diff": "targets/target2_cjson/patches/correct.patch",
        "expected_code": 0
    },
    {
        "name": "Target 2 (cjson_parser) - Incomplete Patch",
        "config": "targets/target2_cjson/zaraban.yaml",
        "base_dir": "targets/target2_cjson",
        "patch_dir": "targets/target2_cjson/versions/patch_incomplete",
        "diff": "targets/target2_cjson/patches/incomplete.patch",
        "expected_code": 10
    },
    {
        "name": "Target 2 (cjson_parser) - Regression Patch",
        "config": "targets/target2_cjson/zaraban.yaml",
        "base_dir": "targets/target2_cjson",
        "patch_dir": "targets/target2_cjson/versions/patch_regression",
        "diff": "targets/target2_cjson/patches/regression.patch",
        "expected_code": 20
    }
]


def main():
    print("=" * 72)
    print("   ZARABAN - Full Evaluation Matrix across Targets 1 & 2")
    print("=" * 72)

    all_passed = True
    results = []

    for sc in SCENARIOS:
        print(f"\n[*] Running: {sc['name']}...")
        cmd = [
            sys.executable, "-m", "zaraban.cli",
            "-c", sc["config"],
            "--base-dir", sc["base_dir"],
            "--patch-dir", sc["patch_dir"],
            "--diff", sc["diff"],
            "--report", f"artifacts/report_{sc['name'].replace(' ', '_').replace('(', '').replace(')', '')}.json"
        ]

        res = subprocess.run(cmd, capture_output=True, text=True)
        actual = res.returncode
        expected = sc["expected_code"]
        is_match = (actual == expected)

        if not is_match:
            all_passed = False

        status_str = "MATCH" if is_match else f"MISMATCH (expected {expected}, got {actual})"
        results.append((sc["name"], expected, actual, is_match))
        print(f"    Verdict: {status_str}")

    print("\n" + "=" * 72)
    print("   Evaluation Matrix Summary")
    print("=" * 72)
    for name, exp, act, ok in results:
        mark = "✓" if ok else "✗"
        print(f"  [{mark}] {name}: Expected {exp}, Got {act}")

    print("=" * 72)
    if all_passed:
        print(">>> ALL 6 SCENARIOS SUCCEEDED AND MATCHED SPECIFICATION EXIT CODES! <<<")
        sys.exit(0)
    else:
        print(">>> SOME SCENARIOS DID NOT MATCH EXPECTED EXIT CODES <<<")
        sys.exit(1)


if __name__ == "__main__":
    main()
