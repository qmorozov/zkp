#!/usr/bin/env python3
"""
ZK Protocol Benchmark Demo

Demonstration of ZK protocol efficiency comparison:
- Schnorr Sigma Protocol
- Groth16 zk-SNARK
- PLONK zk-SNARK

Usage:
    python benchmark_demo.py              # Quick test (10 iterations)
    python benchmark_demo.py --full       # Full test (100 iterations)
    python benchmark_demo.py -n 50        # 50 iterations
    python benchmark_demo.py --csv results.csv    # Export to CSV
    python benchmark_demo.py --latex table.tex    # Export to LaTeX
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.benchmarks import ProtocolBenchmark
from src.colors import Colors, success, error, info, highlight, bold, warning

C = Colors


def print_header():
    """Print benchmark header."""
    print()
    print(f"{C.BOLD_CYAN}╔{'═' * 68}╗{C.RESET}")
    print(f"{C.BOLD_CYAN}║{C.BOLD_WHITE}{' ZK PROTOCOL COMPARISON ANALYSIS '.center(68)}{C.BOLD_CYAN}║{C.RESET}")
    print(f"{C.BOLD_CYAN}║{C.BOLD_WHITE}{' Zero-Knowledge Proof Benchmarks '.center(68)}{C.BOLD_CYAN}║{C.RESET}")
    print(f"{C.BOLD_CYAN}╚{'═' * 68}╝{C.RESET}")
    print()
    print(f"{C.BOLD_WHITE}Protocols for comparison:{C.RESET}")
    print(f"  {C.BOLD_GREEN}1.{C.RESET} {C.CYAN}Schnorr Sigma Protocol{C.RESET} - interactive proof on ECC")
    print(f"  {C.BOLD_GREEN}2.{C.RESET} {C.CYAN}Groth16 zk-SNARK{C.RESET} - smallest proof size")
    print(f"  {C.BOLD_GREEN}3.{C.RESET} {C.CYAN}PLONK zk-SNARK{C.RESET} - universal trusted setup")
    print()
    print(f"{C.BOLD_WHITE}Test scenario:{C.RESET} Age verification (age >= 18)")
    print(f"{C.DIM}{'-' * 70}{C.RESET}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='ZK Protocol Benchmark Demo',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmark_demo.py              # Quick test (10 iterations)
  python benchmark_demo.py --full       # Full test (100 iterations)
  python benchmark_demo.py -n 50        # 50 iterations
  python benchmark_demo.py --csv out.csv --latex out.tex
        """
    )

    parser.add_argument(
        '--iterations', '-n',
        type=int,
        default=10,
        help='Number of iterations (default: 10)'
    )

    parser.add_argument(
        '--quick', '-q',
        action='store_true',
        help='Quick test (5 iterations)'
    )

    parser.add_argument(
        '--full', '-f',
        action='store_true',
        help='Full test (100 iterations)'
    )

    parser.add_argument(
        '--csv',
        type=str,
        metavar='FILE',
        help='Export results to CSV file'
    )

    parser.add_argument(
        '--latex',
        type=str,
        metavar='FILE',
        help='Export results to LaTeX table'
    )

    parser.add_argument(
        '--age',
        type=int,
        default=25,
        help='Test age (private input, default: 25)'
    )

    parser.add_argument(
        '--required-age',
        type=int,
        default=18,
        help='Required age (public input, default: 18)'
    )

    args = parser.parse_args()

    # Determine iterations
    if args.quick:
        iterations = 5
    elif args.full:
        iterations = 100
    else:
        iterations = args.iterations

    print_header()

    # Run benchmark
    benchmark = ProtocolBenchmark(
        iterations=iterations,
        age=args.age,
        required_age=args.required_age
    )

    try:
        benchmark.run_all()
    except KeyboardInterrupt:
        print(f"\n\n{C.BOLD_YELLOW}Benchmark interrupted by user.{C.RESET}")
        sys.exit(1)

    # Print results
    benchmark.print_results()
    benchmark.print_detailed_stats()

    # Export if requested
    if args.csv:
        benchmark.export_to_csv(args.csv)

    if args.latex:
        benchmark.export_to_latex(args.latex)

    # Print summary
    print()
    print(f"{C.BOLD_CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD_WHITE}SUMMARY:{C.RESET}")
    print(f"{C.BOLD_CYAN}{'=' * 70}{C.RESET}")

    results = benchmark.get_summary_dict()

    if 'schnorr' in results and results['schnorr']['iterations'] > 0:
        print(f"\n{C.BOLD_GREEN}1. Schnorr Protocol:{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} {C.BOLD_WHITE}Fastest setup{C.RESET} (no trusted setup)")
        print(f"   {C.CYAN}•{C.RESET} Prove: {C.BOLD_YELLOW}{results['schnorr']['prove_ms']['mean']:.2f} ms{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Verify: {C.BOLD_YELLOW}{results['schnorr']['verify_ms']['mean']:.2f} ms{C.RESET}")

    if 'groth16' in results and results['groth16']['iterations'] > 0:
        print(f"\n{C.BOLD_GREEN}2. Groth16:{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} {C.BOLD_WHITE}Smallest proof:{C.RESET} {C.BOLD_MAGENTA}{results['groth16']['proof_size_bytes']:.0f} bytes{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Prove: {C.BOLD_YELLOW}{results['groth16']['prove_ms']['mean']:.2f} ms{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Verify: {C.BOLD_YELLOW}{results['groth16']['verify_ms']['mean']:.2f} ms{C.RESET}")

    if 'plonk' in results and results['plonk']['iterations'] > 0:
        print(f"\n{C.BOLD_GREEN}3. PLONK:{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} {C.BOLD_WHITE}Universal trusted setup{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Prove: {C.BOLD_YELLOW}{results['plonk']['prove_ms']['mean']:.2f} ms{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Verify: {C.BOLD_YELLOW}{results['plonk']['verify_ms']['mean']:.2f} ms{C.RESET}")
        print(f"   {C.CYAN}•{C.RESET} Proof size: {C.BOLD_MAGENTA}{results['plonk']['proof_size_bytes']:.0f} bytes{C.RESET}")

    print()
    print(f"{C.BOLD_CYAN}{'=' * 70}{C.RESET}")


if __name__ == "__main__":
    main()
