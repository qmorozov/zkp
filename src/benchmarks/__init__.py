"""
Benchmarks module for ZK protocol comparison.

Usage:
    from src.benchmarks import ProtocolBenchmark

    benchmark = ProtocolBenchmark(iterations=100)
    benchmark.run_all()
    benchmark.print_results()
"""

from .protocol_comparison import (
    ProtocolBenchmark,
    BenchmarkResult,
    run_quick_benchmark,
    run_full_benchmark,
)

__all__ = [
    'ProtocolBenchmark',
    'BenchmarkResult',
    'run_quick_benchmark',
    'run_full_benchmark',
]