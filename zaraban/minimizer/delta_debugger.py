"""Automated Testcase Minimizer (Delta Debugging) for Zaraban (Section 3.3).

Minimizes crashing inputs automatically using Delta Debugging (ddmin)
while ensuring the reduced testcase reproduces the EXACT same crash signature:
"به گونه‌ای که ورودی کوچک‌شده همچنان همان نوع خطا را در محل مرتبط ایجاد کند...
هر کد خروج غیرصفر، معیار حفظ همان خطا نیست."
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional
import os
import tempfile


@dataclass
class MinimizationResult:
    original_data: bytes
    minimized_data: bytes
    original_size: int
    minimized_size: int
    reduction_percent: float
    iterations: int
    preserved_error_type: str
    is_success: bool


class DeltaDebugger:
    """Implements ddmin delta debugging algorithm for binary/text inputs."""

    @classmethod
    def minimize(
        cls,
        initial_input: bytes,
        oracle: Callable[[bytes], bool],
        max_iterations: int = 150
    ) -> MinimizationResult:
        """Minimize input bytes such that oracle(candidate) returns True.
        
        oracle must return True ONLY if candidate triggers the SAME crash type and signature.
        """
        # Step 0: Verify initial input triggers the oracle
        if not oracle(initial_input):
            return MinimizationResult(
                original_data=initial_input,
                minimized_data=initial_input,
                original_size=len(initial_input),
                minimized_size=len(initial_input),
                reduction_percent=0.0,
                iterations=0,
                preserved_error_type="None",
                is_success=False
            )

        data = initial_input
        n = 2
        iterations = 0

        # Hierarchical ddmin loop
        while len(data) >= 2 and n <= len(data) and iterations < max_iterations:
            iterations += 1
            chunk_size = len(data) // n
            if chunk_size == 0:
                break

            chunks = []
            for i in range(n):
                start = i * chunk_size
                end = len(data) if i == n - 1 else (i + 1) * chunk_size
                chunks.append((start, end))

            reduced = False

            # 1. Try removing each chunk c_i
            for start, end in chunks:
                candidate = data[:start] + data[end:]
                if len(candidate) > 0 and oracle(candidate):
                    data = candidate
                    n = max(n - 1, 2)
                    reduced = True
                    break

            if reduced:
                continue

            # 2. Try keeping only chunk c_i
            for start, end in chunks:
                candidate = data[start:end]
                if len(candidate) > 0 and oracle(candidate):
                    data = candidate
                    n = 2
                    reduced = True
                    break

            if reduced:
                continue

            # 3. Increase granularity
            if n == len(data):
                break
            n = min(n * 2, len(data))

        # Fine-tuning pass: Try single byte deletions on the boundary/payload
        if len(data) > 4 and iterations < max_iterations:
            idx = len(data) - 1
            while idx >= 0 and iterations < max_iterations:
                iterations += 1
                candidate = data[:idx] + data[idx + 1:]
                if oracle(candidate):
                    data = candidate
                    idx = min(idx, len(data) - 1)
                else:
                    idx -= 1

        reduction = ((len(initial_input) - len(data)) / max(1, len(initial_input))) * 100.0

        return MinimizationResult(
            original_data=initial_input,
            minimized_data=data,
            original_size=len(initial_input),
            minimized_size=len(data),
            reduction_percent=round(reduction, 2),
            iterations=iterations,
            preserved_error_type="VerifiedByOracle",
            is_success=len(data) < len(initial_input)
        )
