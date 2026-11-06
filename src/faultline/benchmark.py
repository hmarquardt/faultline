"""Packaged benchmark suites; definitions are data, never code."""

from importlib.resources import files

from faultline.documents import load_json
from faultline.domain import BenchmarkSuite

BENCHMARK_PACKAGE = "benchmarks.v1.json"


def suites() -> dict[str, BenchmarkSuite]:
    raw = files("faultline.data").joinpath(BENCHMARK_PACKAGE).read_text()
    loaded = [BenchmarkSuite.model_validate(item) for item in load_json(raw)]
    if len({suite.id for suite in loaded}) != len(loaded):
        raise ValueError("Duplicate benchmark suite ID")
    return {suite.id: suite for suite in loaded}


def suite(identifier: str) -> BenchmarkSuite:
    registry = suites()
    if identifier not in registry:
        raise ValueError("Unknown benchmark suite ID")
    return registry[identifier]
