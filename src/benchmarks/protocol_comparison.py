"""
Protocol Comparison Benchmarks for Zero-Knowledge Proofs

Benchmarking module for comparing ZK protocols:
- Schnorr Sigma Protocol
- Groth16 zk-SNARK
- PLONK zk-SNARK

Metrics collected:
- Setup time (ms)
- Proof generation time (ms)
- Verification time (ms)
- Proof size (bytes)

Used for thesis Section 3.4.1: "ZK Protocol Efficiency Research"
"""

import json
import os
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Callable

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.crypto_library_zkp import CryptographyLibraryZKP
from src.colors import Colors

C = Colors


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run."""
    protocol_name: str
    setup_times: List[float] = field(default_factory=list)
    prove_times: List[float] = field(default_factory=list)
    verify_times: List[float] = field(default_factory=list)
    proof_sizes: List[int] = field(default_factory=list)
    iterations: int = 0
    all_valid: bool = True

    @property
    def setup_mean(self) -> float:
        return statistics.mean(self.setup_times) if self.setup_times else 0

    @property
    def setup_std(self) -> float:
        return statistics.stdev(self.setup_times) if len(self.setup_times) > 1 else 0

    @property
    def prove_mean(self) -> float:
        return statistics.mean(self.prove_times) if self.prove_times else 0

    @property
    def prove_std(self) -> float:
        return statistics.stdev(self.prove_times) if len(self.prove_times) > 1 else 0

    @property
    def verify_mean(self) -> float:
        return statistics.mean(self.verify_times) if self.verify_times else 0

    @property
    def verify_std(self) -> float:
        return statistics.stdev(self.verify_times) if len(self.verify_times) > 1 else 0

    @property
    def proof_size_mean(self) -> float:
        return statistics.mean(self.proof_sizes) if self.proof_sizes else 0


class ProtocolBenchmark:
    """
    Benchmark suite for comparing ZK protocols.

    Usage:
        benchmark = ProtocolBenchmark(iterations=100)
        benchmark.run_all()
        benchmark.print_results()
        benchmark.export_to_csv('results.csv')
    """

    def __init__(self, iterations: int = 100, age: int = 25, required_age: int = 18):
        """
        Initialize benchmark suite.

        Args:
            iterations: Number of iterations for each benchmark
            age: Test age value (private input)
            required_age: Required age threshold (public input)
        """
        self.iterations = iterations
        self.age = age
        self.required_age = required_age
        self.results: Dict[str, BenchmarkResult] = {}

        # Paths
        self.base_path = Path(__file__).parent.parent.parent
        self.circuits_path = self.base_path / "circuits" / "compiled"

    def _run_command(self, cmd: list, timeout: int = 30) -> tuple:
        """Run shell command and return (success, stdout, time_ms)."""
        start = time.perf_counter()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            elapsed = (time.perf_counter() - start) * 1000
            return result.returncode == 0, result.stdout, elapsed
        except subprocess.TimeoutExpired:
            return False, "Timeout", 0

    def benchmark_schnorr(self) -> BenchmarkResult:
        """Benchmark Schnorr Sigma Protocol."""
        print(f"\n  Benchmarking Schnorr Protocol ({self.iterations} iterations)...")

        result = BenchmarkResult(protocol_name="Schnorr")
        zkp = CryptographyLibraryZKP()

        for i in range(self.iterations):
            # Setup (creating commitment) - included in setup time
            setup_start = time.perf_counter()
            commitment, _ = zkp.create_age_commitment(self.age)
            setup_time = (time.perf_counter() - setup_start) * 1000
            result.setup_times.append(setup_time)

            # Prove
            prove_start = time.perf_counter()
            proof, prove_metrics = zkp.schnorr_prove(self.age, self.required_age, commitment)
            prove_time = (time.perf_counter() - prove_start) * 1000
            result.prove_times.append(prove_time)

            # Calculate proof size
            proof_json = json.dumps({
                'R': str(proof['R']),
                'c': proof['c'],
                's': proof['s']
            })
            result.proof_sizes.append(len(proof_json.encode('utf-8')))

            # Verify
            verify_start = time.perf_counter()
            is_valid, verify_metrics = zkp.schnorr_verify(commitment, self.required_age, proof)
            verify_time = (time.perf_counter() - verify_start) * 1000
            result.verify_times.append(verify_time)

            if not is_valid:
                result.all_valid = False

            if (i + 1) % 20 == 0:
                print(f"    Progress: {i + 1}/{self.iterations}")

        result.iterations = self.iterations
        return result

    def benchmark_groth16(self) -> BenchmarkResult:
        """Benchmark Groth16 zk-SNARK."""
        print(f"\n  Benchmarking Groth16 ({self.iterations} iterations)...")

        result = BenchmarkResult(protocol_name="Groth16")

        # Check if setup files exist
        zkey_path = self.circuits_path / "age_check_groth16.zkey"
        vkey_path = self.circuits_path / "verification_key_groth16.json"
        wasm_path = self.circuits_path / "age_check_js" / "age_check.wasm"
        witness_gen = self.circuits_path / "age_check_js" / "generate_witness.js"

        if not all(p.exists() for p in [zkey_path, vkey_path, wasm_path]):
            print("    ERROR: Groth16 setup files not found. Run setup first.")
            return result

        # Setup is already done, so setup time is 0 for runtime benchmarks
        # (setup is one-time cost)

        for i in range(self.iterations):
            result.setup_times.append(0)  # Setup already done

            # Create input file
            input_data = {"age": str(self.age), "requiredAge": str(self.required_age)}
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(input_data, f)
                input_path = f.name

            witness_path = tempfile.mktemp(suffix='.wtns')
            proof_path = tempfile.mktemp(suffix='.json')
            public_path = tempfile.mktemp(suffix='.json')

            try:
                # Generate witness + prove (combined as "prove" time)
                prove_start = time.perf_counter()

                # Witness generation
                self._run_command([
                    "node", str(witness_gen), str(wasm_path),
                    input_path, witness_path
                ])

                # Proof generation
                self._run_command([
                    "npx", "snarkjs", "groth16", "prove",
                    str(zkey_path), witness_path, proof_path, public_path
                ])

                prove_time = (time.perf_counter() - prove_start) * 1000
                result.prove_times.append(prove_time)

                # Get proof size
                if os.path.exists(proof_path):
                    result.proof_sizes.append(os.path.getsize(proof_path))
                else:
                    result.proof_sizes.append(0)

                # Verify
                verify_start = time.perf_counter()
                success, output, _ = self._run_command([
                    "npx", "snarkjs", "groth16", "verify",
                    str(vkey_path), public_path, proof_path
                ])
                verify_time = (time.perf_counter() - verify_start) * 1000
                result.verify_times.append(verify_time)

                if not success or "OK" not in output:
                    result.all_valid = False

            finally:
                # Cleanup
                for p in [input_path, witness_path, proof_path, public_path]:
                    if os.path.exists(p):
                        os.unlink(p)

            if (i + 1) % 20 == 0:
                print(f"    Progress: {i + 1}/{self.iterations}")

        result.iterations = self.iterations
        return result

    def benchmark_plonk(self) -> BenchmarkResult:
        """Benchmark PLONK zk-SNARK."""
        print(f"\n  Benchmarking PLONK ({self.iterations} iterations)...")

        result = BenchmarkResult(protocol_name="PLONK")

        # Check if setup files exist
        zkey_path = self.circuits_path / "age_check_plonk.zkey"
        vkey_path = self.circuits_path / "verification_key_plonk.json"
        wasm_path = self.circuits_path / "age_check_js" / "age_check.wasm"
        witness_gen = self.circuits_path / "age_check_js" / "generate_witness.js"

        if not all(p.exists() for p in [zkey_path, vkey_path, wasm_path]):
            print("    ERROR: PLONK setup files not found. Run setup first.")
            return result

        for i in range(self.iterations):
            result.setup_times.append(0)  # Setup already done

            # Create input file
            input_data = {"age": str(self.age), "requiredAge": str(self.required_age)}
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(input_data, f)
                input_path = f.name

            witness_path = tempfile.mktemp(suffix='.wtns')
            proof_path = tempfile.mktemp(suffix='.json')
            public_path = tempfile.mktemp(suffix='.json')

            try:
                # Generate witness + prove
                prove_start = time.perf_counter()

                self._run_command([
                    "node", str(witness_gen), str(wasm_path),
                    input_path, witness_path
                ])

                self._run_command([
                    "npx", "snarkjs", "plonk", "prove",
                    str(zkey_path), witness_path, proof_path, public_path
                ])

                prove_time = (time.perf_counter() - prove_start) * 1000
                result.prove_times.append(prove_time)

                # Get proof size
                if os.path.exists(proof_path):
                    result.proof_sizes.append(os.path.getsize(proof_path))
                else:
                    result.proof_sizes.append(0)

                # Verify
                verify_start = time.perf_counter()
                success, output, _ = self._run_command([
                    "npx", "snarkjs", "plonk", "verify",
                    str(vkey_path), public_path, proof_path
                ])
                verify_time = (time.perf_counter() - verify_start) * 1000
                result.verify_times.append(verify_time)

                if not success or "OK" not in output:
                    result.all_valid = False

            finally:
                for p in [input_path, witness_path, proof_path, public_path]:
                    if os.path.exists(p):
                        os.unlink(p)

            if (i + 1) % 20 == 0:
                print(f"    Progress: {i + 1}/{self.iterations}")

        result.iterations = self.iterations
        return result

    def run_all(self) -> Dict[str, BenchmarkResult]:
        """Run all benchmarks."""
        print("=" * 70)
        print("ZERO-KNOWLEDGE PROOF PROTOCOL BENCHMARKS")
        print("=" * 70)
        print(f"Iterations: {self.iterations}")
        print(f"Test case: age={self.age}, required_age={self.required_age}")

        self.results['schnorr'] = self.benchmark_schnorr()
        self.results['groth16'] = self.benchmark_groth16()
        self.results['plonk'] = self.benchmark_plonk()

        return self.results

    def print_results(self):
        """Print benchmark results in a formatted table."""
        print("\n")
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")
        print(f"{C.BOLD_WHITE}ZK PROTOCOL COMPARISON RESULTS{C.RESET}")
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")
        print(f"{C.BOLD_WHITE}{'Protocol':<12} {'Setup (ms)':<14} {'Prove (ms)':<14} {'Verify (ms)':<14} {'Proof (B)':<12} {'Valid':<8}{C.RESET}")
        print(f"{C.DIM}{'-' * 80}{C.RESET}")

        for name, result in self.results.items():
            if result.iterations == 0:
                print(f"{C.DIM}{result.protocol_name:<12} {'N/A':<14} {'N/A':<14} {'N/A':<14} {'N/A':<12} {'N/A':<8}{C.RESET}")
            else:
                setup_str = f"{result.setup_mean:.2f} ± {result.setup_std:.2f}"
                prove_str = f"{result.prove_mean:.2f} ± {result.prove_std:.2f}"
                verify_str = f"{result.verify_mean:.2f} ± {result.verify_std:.2f}"
                size_str = f"{result.proof_size_mean:.0f}"
                valid_str = f"{C.BOLD_GREEN}OK{C.RESET}" if result.all_valid else f"{C.BOLD_RED}FAIL{C.RESET}"

                print(f"{C.BOLD_CYAN}{result.protocol_name:<12}{C.RESET} {C.YELLOW}{setup_str:<14}{C.RESET} {C.YELLOW}{prove_str:<14}{C.RESET} {C.YELLOW}{verify_str:<14}{C.RESET} {C.BOLD_MAGENTA}{size_str:<12}{C.RESET} {valid_str}")

        print(f"{C.DIM}{'-' * 80}{C.RESET}")
        print(f"Iterations: {C.BOLD_WHITE}{self.iterations}{C.RESET}")
        print()

    def print_detailed_stats(self):
        """Print detailed statistics for each protocol."""
        print("\n")
        print(f"{C.BOLD_CYAN}{'=' * 70}{C.RESET}")
        print(f"{C.BOLD_WHITE}DETAILED STATISTICS{C.RESET}")
        print(f"{C.BOLD_CYAN}{'=' * 70}{C.RESET}")

        for name, result in self.results.items():
            if result.iterations == 0:
                continue

            print(f"\n{C.BOLD_GREEN}{result.protocol_name}:{C.RESET}")
            print(f"  {C.CYAN}Setup time:{C.RESET}")
            print(f"    Mean: {C.BOLD_YELLOW}{result.setup_mean:.3f} ms{C.RESET}")
            print(f"    Std:  {result.setup_std:.3f} ms")
            print(f"    Min:  {min(result.setup_times):.3f} ms")
            print(f"    Max:  {max(result.setup_times):.3f} ms")

            print(f"  {C.CYAN}Prove time:{C.RESET}")
            print(f"    Mean: {C.BOLD_YELLOW}{result.prove_mean:.3f} ms{C.RESET}")
            print(f"    Std:  {result.prove_std:.3f} ms")
            print(f"    Min:  {min(result.prove_times):.3f} ms")
            print(f"    Max:  {max(result.prove_times):.3f} ms")

            print(f"  {C.CYAN}Verify time:{C.RESET}")
            print(f"    Mean: {C.BOLD_YELLOW}{result.verify_mean:.3f} ms{C.RESET}")
            print(f"    Std:  {result.verify_std:.3f} ms")
            print(f"    Min:  {min(result.verify_times):.3f} ms")
            print(f"    Max:  {max(result.verify_times):.3f} ms")

            print(f"  {C.CYAN}Proof size:{C.RESET} {C.BOLD_MAGENTA}{result.proof_size_mean:.0f} bytes{C.RESET}")

    def export_to_csv(self, filename: str):
        """Export results to CSV file."""
        import csv

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'Protocol', 'Iterations',
                'Setup Mean (ms)', 'Setup Std (ms)',
                'Prove Mean (ms)', 'Prove Std (ms)',
                'Verify Mean (ms)', 'Verify Std (ms)',
                'Proof Size (bytes)', 'All Valid'
            ])

            # Data
            for name, result in self.results.items():
                writer.writerow([
                    result.protocol_name,
                    result.iterations,
                    f"{result.setup_mean:.3f}",
                    f"{result.setup_std:.3f}",
                    f"{result.prove_mean:.3f}",
                    f"{result.prove_std:.3f}",
                    f"{result.verify_mean:.3f}",
                    f"{result.verify_std:.3f}",
                    f"{result.proof_size_mean:.0f}",
                    result.all_valid
                ])

        print(f"\nResults exported to: {filename}")

    def export_to_latex(self, filename: str):
        """Export results to LaTeX table format for thesis."""
        latex = r"""
\begin{table}[h]
\centering
\caption{ZK Protocol Efficiency Comparison}
\label{tab:protocol-comparison}
\begin{tabular}{|l|c|c|c|c|}
\hline
\textbf{Protocol} & \textbf{Setup (ms)} & \textbf{Prove (ms)} & \textbf{Verify (ms)} & \textbf{Proof (B)} \\
\hline
"""
        for name, result in self.results.items():
            if result.iterations > 0:
                latex += f"{result.protocol_name} & "
                latex += f"{result.setup_mean:.2f} $\\pm$ {result.setup_std:.2f} & "
                latex += f"{result.prove_mean:.2f} $\\pm$ {result.prove_std:.2f} & "
                latex += f"{result.verify_mean:.2f} $\\pm$ {result.verify_std:.2f} & "
                latex += f"{result.proof_size_mean:.0f} \\\\\n\\hline\n"

        latex += r"""
\end{tabular}
\end{table}
"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(latex)

        print(f"LaTeX table exported to: {filename}")

    def get_summary_dict(self) -> Dict:
        """Get results as a dictionary for programmatic use."""
        summary = {}
        for name, result in self.results.items():
            summary[name] = {
                'protocol': result.protocol_name,
                'iterations': result.iterations,
                'setup_ms': {'mean': result.setup_mean, 'std': result.setup_std},
                'prove_ms': {'mean': result.prove_mean, 'std': result.prove_std},
                'verify_ms': {'mean': result.verify_mean, 'std': result.verify_std},
                'proof_size_bytes': result.proof_size_mean,
                'all_valid': result.all_valid
            }
        return summary


def run_quick_benchmark():
    """Run a quick benchmark with fewer iterations."""
    benchmark = ProtocolBenchmark(iterations=10)
    benchmark.run_all()
    benchmark.print_results()
    return benchmark


def run_full_benchmark():
    """Run a full benchmark with 100 iterations."""
    benchmark = ProtocolBenchmark(iterations=100)
    benchmark.run_all()
    benchmark.print_results()
    benchmark.print_detailed_stats()
    return benchmark


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='ZK Protocol Benchmarks')
    parser.add_argument('--iterations', '-n', type=int, default=20,
                        help='Number of iterations (default: 20)')
    parser.add_argument('--quick', '-q', action='store_true',
                        help='Quick benchmark (10 iterations)')
    parser.add_argument('--full', '-f', action='store_true',
                        help='Full benchmark (100 iterations)')
    parser.add_argument('--csv', type=str, help='Export to CSV file')
    parser.add_argument('--latex', type=str, help='Export to LaTeX file')

    args = parser.parse_args()

    if args.quick:
        benchmark = run_quick_benchmark()
    elif args.full:
        benchmark = run_full_benchmark()
    else:
        benchmark = ProtocolBenchmark(iterations=args.iterations)
        benchmark.run_all()
        benchmark.print_results()
        benchmark.print_detailed_stats()

    if args.csv:
        benchmark.export_to_csv(args.csv)
    if args.latex:
        benchmark.export_to_latex(args.latex)