"""
Lightweight in-process metrics for the anomaly detection service.
"""

from __future__ import annotations

from collections import defaultdict
from threading import Lock
from typing import Dict, List


class RuntimeMetrics:
    def __init__(self) -> None:
        self._counters: Dict[str, int] = defaultdict(int)
        self._observations: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()

    def increment(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self._observations[name].append(float(value))
            if len(self._observations[name]) > 2048:
                self._observations[name] = self._observations[name][-2048:]

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            observations = {}
            for name, values in self._observations.items():
                if not values:
                    continue
                sorted_values = sorted(values)
                count = len(sorted_values)
                observations[name] = {
                    "count": count,
                    "min": round(sorted_values[0], 4),
                    "max": round(sorted_values[-1], 4),
                    "avg": round(sum(sorted_values) / count, 4),
                    "p50": round(sorted_values[count // 2], 4),
                    "p95": round(sorted_values[min(count - 1, int(count * 0.95))], 4),
                    "p99": round(sorted_values[min(count - 1, int(count * 0.99))], 4),
                }
            return {
                "counters": dict(self._counters),
                "observations": observations,
            }


runtime_metrics = RuntimeMetrics()
