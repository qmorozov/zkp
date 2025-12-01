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

    def _print_progress(self, current: int, total: int, protocol: str, width: int = 30):
        """Print a progress bar."""
        percent = current / total
        filled = int(width * percent)
        bar = "█" * filled + "░" * (width - filled)
        print(f"\r  {C.CYAN}{protocol:<10}{C.RESET} [{C.GREEN}{bar}{C.RESET}] {current}/{total} ({percent*100:.0f}%)", end="", flush=True)
        if current == total:
            print()  # New line when done

    def benchmark_schnorr(self) -> BenchmarkResult:
        """Бенчмарк Schnorr Sigma Protocol."""
        print(f"\n{C.BOLD_WHITE}▶ Schnorr Sigma Protocol{C.RESET}")

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

            self._print_progress(i + 1, self.iterations, "Schnorr")

        result.iterations = self.iterations
        print(f"  {C.GREEN}✓{C.RESET} Завершено: {C.BOLD_YELLOW}{result.prove_mean:.2f} мс{C.RESET} prove, {C.BOLD_YELLOW}{result.verify_mean:.2f} мс{C.RESET} verify")
        return result

    def benchmark_groth16(self) -> BenchmarkResult:
        """Бенчмарк Groth16 zk-SNARK."""
        print(f"\n{C.BOLD_WHITE}▶ Groth16 zk-SNARK{C.RESET}")

        result = BenchmarkResult(protocol_name="Groth16")

        # Check if setup files exist
        zkey_path = self.circuits_path / "age_check_groth16.zkey"
        vkey_path = self.circuits_path / "verification_key_groth16.json"
        wasm_path = self.circuits_path / "age_check_js" / "age_check.wasm"
        witness_gen = self.circuits_path / "age_check_js" / "generate_witness.js"

        if not all(p.exists() for p in [zkey_path, vkey_path, wasm_path]):
            print(f"  {C.YELLOW}⚠{C.RESET} Groth16 setup files not found. Run: npm run compile")
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

            self._print_progress(i + 1, self.iterations, "Groth16")

        result.iterations = self.iterations
        if result.prove_times:
            print(f"  {C.GREEN}✓{C.RESET} Завершено: {C.BOLD_YELLOW}{result.prove_mean:.2f} мс{C.RESET} prove, {C.BOLD_YELLOW}{result.verify_mean:.2f} мс{C.RESET} verify")
        return result

    def benchmark_plonk(self) -> BenchmarkResult:
        """Бенчмарк PLONK zk-SNARK."""
        print(f"\n{C.BOLD_WHITE}▶ PLONK zk-SNARK{C.RESET}")

        result = BenchmarkResult(protocol_name="PLONK")

        # Check if setup files exist
        zkey_path = self.circuits_path / "age_check_plonk.zkey"
        vkey_path = self.circuits_path / "verification_key_plonk.json"
        wasm_path = self.circuits_path / "age_check_js" / "age_check.wasm"
        witness_gen = self.circuits_path / "age_check_js" / "generate_witness.js"

        if not all(p.exists() for p in [zkey_path, vkey_path, wasm_path]):
            print(f"  {C.YELLOW}⚠{C.RESET} PLONK setup files not found. Run: npm run compile")
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

            self._print_progress(i + 1, self.iterations, "PLONK")

        result.iterations = self.iterations
        if result.prove_times:
            print(f"  {C.GREEN}✓{C.RESET} Завершено: {C.BOLD_YELLOW}{result.prove_mean:.2f} мс{C.RESET} prove, {C.BOLD_YELLOW}{result.verify_mean:.2f} мс{C.RESET} verify")
        return result

    def run_all(self) -> Dict[str, BenchmarkResult]:
        """Запуск усіх бенчмарків."""
        print("=" * 70)
        print("БЕНЧМАРК ZK-ПРОТОКОЛІВ")
        print("=" * 70)
        print(f"Ітерацій: {self.iterations}")
        print(f"Тестовий сценарій: вік={self.age}, поріг={self.required_age}")

        self.results['schnorr'] = self.benchmark_schnorr()
        self.results['groth16'] = self.benchmark_groth16()
        self.results['plonk'] = self.benchmark_plonk()

        return self.results

    def _make_bar(self, value: float, max_value: float, width: int = 30, char: str = "█") -> str:
        """Create an ASCII bar."""
        if max_value == 0:
            return ""
        filled = int((value / max_value) * width)
        return char * filled + "░" * (width - filled)

    def _get_medal(self, rank: int) -> str:
        """Get medal emoji for ranking."""
        medals = {1: "🥇", 2: "🥈", 3: "🥉"}
        return medals.get(rank, "  ")

    def print_results(self):
        """Виведення результатів бенчмарку."""
        print("\n")
        print(f"{C.BOLD_CYAN}{'═' * 80}{C.RESET}")
        print(f"{C.BOLD_WHITE}{'РЕЗУЛЬТАТИ ПОРІВНЯННЯ ZK-ПРОТОКОЛІВ'.center(80)}{C.RESET}")
        print(f"{C.BOLD_CYAN}{'═' * 80}{C.RESET}")
        print(f"{C.BOLD_WHITE}{'Протокол':<12} {'Setup (мс)':<14} {'Prove (мс)':<14} {'Verify (мс)':<14} {'Proof (Б)':<12} {'Валід':<8}{C.RESET}")
        print(f"{C.DIM}{'─' * 80}{C.RESET}")

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

        print(f"{C.DIM}{'─' * 80}{C.RESET}")
        print(f"Ітерацій: {C.BOLD_WHITE}{self.iterations}{C.RESET}")
        print()

    def print_ascii_charts(self):
        """Виведення ASCII-графіків для візуального порівняння."""
        # Filter protocols with data
        valid_results = [(name, r) for name, r in self.results.items() if r.iterations > 0]
        if not valid_results:
            return

        print(f"\n{C.BOLD_CYAN}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD_WHITE}{'ВІЗУАЛЬНЕ ПОРІВНЯННЯ'.center(70)}{C.RESET}")
        print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")

        # Prove Time Chart
        print(f"\n{C.BOLD_YELLOW}⏱  ЧАС ГЕНЕРАЦІЇ (мс){C.RESET}")
        print(f"{C.DIM}{'─' * 60}{C.RESET}")
        prove_times = [(r.protocol_name, r.prove_mean) for _, r in valid_results]
        max_prove = max(t[1] for t in prove_times) if prove_times else 1
        prove_sorted = sorted(prove_times, key=lambda x: x[1])

        for i, (name, value) in enumerate(prove_sorted):
            bar = self._make_bar(value, max_prove, 35)
            medal = self._get_medal(i + 1)
            color = C.GREEN if i == 0 else (C.YELLOW if i == 1 else C.WHITE)
            print(f"  {medal} {name:<10} {color}{bar}{C.RESET} {C.BOLD_WHITE}{value:>8.2f}{C.RESET} ms")

        # Verify Time Chart
        print(f"\n{C.BOLD_YELLOW}✓  ЧАС ВЕРИФІКАЦІЇ (мс){C.RESET}")
        print(f"{C.DIM}{'─' * 60}{C.RESET}")
        verify_times = [(r.protocol_name, r.verify_mean) for _, r in valid_results]
        max_verify = max(t[1] for t in verify_times) if verify_times else 1
        verify_sorted = sorted(verify_times, key=lambda x: x[1])

        for i, (name, value) in enumerate(verify_sorted):
            bar = self._make_bar(value, max_verify, 35)
            medal = self._get_medal(i + 1)
            color = C.GREEN if i == 0 else (C.YELLOW if i == 1 else C.WHITE)
            print(f"  {medal} {name:<10} {color}{bar}{C.RESET} {C.BOLD_WHITE}{value:>8.2f}{C.RESET} мс")

        # Proof Size Chart
        print(f"\n{C.BOLD_YELLOW}📦 РОЗМІР ДОКАЗУ (байт){C.RESET}")
        print(f"{C.DIM}{'─' * 60}{C.RESET}")
        proof_sizes = [(r.protocol_name, r.proof_size_mean) for _, r in valid_results]
        max_size = max(t[1] for t in proof_sizes) if proof_sizes else 1
        size_sorted = sorted(proof_sizes, key=lambda x: x[1])

        for i, (name, value) in enumerate(size_sorted):
            bar = self._make_bar(value, max_size, 35)
            medal = self._get_medal(i + 1)
            color = C.GREEN if i == 0 else (C.YELLOW if i == 1 else C.WHITE)
            print(f"  {medal} {name:<10} {color}{bar}{C.RESET} {C.BOLD_WHITE}{value:>8.0f}{C.RESET} Б")

        # Total Time Chart
        print(f"\n{C.BOLD_YELLOW}Σ  ЗАГАЛЬНИЙ ЧАС (prove + verify){C.RESET}")
        print(f"{C.DIM}{'─' * 60}{C.RESET}")
        total_times = [(r.protocol_name, r.prove_mean + r.verify_mean) for _, r in valid_results]
        max_total = max(t[1] for t in total_times) if total_times else 1
        total_sorted = sorted(total_times, key=lambda x: x[1])

        for i, (name, value) in enumerate(total_sorted):
            bar = self._make_bar(value, max_total, 35)
            medal = self._get_medal(i + 1)
            color = C.GREEN if i == 0 else (C.YELLOW if i == 1 else C.WHITE)
            print(f"  {medal} {name:<10} {color}{bar}{C.RESET} {C.BOLD_WHITE}{value:>8.2f}{C.RESET} мс")

    def print_rankings(self):
        """Виведення рейтингу та рекомендацій."""
        valid_results = [(name, r) for name, r in self.results.items() if r.iterations > 0]
        if not valid_results:
            return

        print(f"\n{C.BOLD_CYAN}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD_WHITE}{'РЕЙТИНГ ТА РЕКОМЕНДАЦІЇ'.center(70)}{C.RESET}")
        print(f"{C.BOLD_CYAN}{'═' * 70}{C.RESET}")

        # Find winners
        fastest_prove = min(valid_results, key=lambda x: x[1].prove_mean)
        fastest_verify = min(valid_results, key=lambda x: x[1].verify_mean)
        smallest_proof = min(valid_results, key=lambda x: x[1].proof_size_mean)
        fastest_total = min(valid_results, key=lambda x: x[1].prove_mean + x[1].verify_mean)

        print(f"""
  {C.BOLD_GREEN}🏆 ЛІДЕРИ ЗА КАТЕГОРІЯМИ:{C.RESET}

  {C.CYAN}Швидкість генерації:{C.RESET}  🥇 {C.BOLD_WHITE}{fastest_prove[1].protocol_name}{C.RESET} ({fastest_prove[1].prove_mean:.2f} мс)
  {C.CYAN}Швидкість верифікації:{C.RESET}🥇 {C.BOLD_WHITE}{fastest_verify[1].protocol_name}{C.RESET} ({fastest_verify[1].verify_mean:.2f} мс)
  {C.CYAN}Найменший доказ:{C.RESET}      🥇 {C.BOLD_WHITE}{smallest_proof[1].protocol_name}{C.RESET} ({smallest_proof[1].proof_size_mean:.0f} байт)
  {C.CYAN}Загальна швидкість:{C.RESET}   🥇 {C.BOLD_WHITE}{fastest_total[1].protocol_name}{C.RESET} ({fastest_total[1].prove_mean + fastest_total[1].verify_mean:.2f} мс)
""")

        print(f"  {C.BOLD_WHITE}📋 РЕКОМЕНДАЦІЇ ДЛЯ ЗАСТОСУВАННЯ:{C.RESET}")
        print(f"""
  ┌─────────────────────────────────────────────────────────────────┐
  │ {C.BOLD_CYAN}Real-time верифікація{C.RESET}          → {C.BOLD_WHITE}{fastest_total[1].protocol_name}{C.RESET}                         │
  │   {C.DIM}(найменша затримка для інтерактивних додатків){C.RESET}              │
  │                                                                 │
  │ {C.BOLD_CYAN}Обмежений канал зв'язку{C.RESET}        → {C.BOLD_WHITE}{smallest_proof[1].protocol_name}{C.RESET}                          │
  │   {C.DIM}(найменший розмір доказу для mobile/IoT){C.RESET}                    │
  │                                                                 │
  │ {C.BOLD_CYAN}Blockchain/On-chain{C.RESET}            → {C.BOLD_WHITE}{smallest_proof[1].protocol_name}{C.RESET}                          │
  │   {C.DIM}(витрати gas пропорційні розміру доказу){C.RESET}                    │
  └─────────────────────────────────────────────────────────────────┘
""")

    def print_detailed_stats(self):
        """Виведення детальної статистики."""
        print("\n")
        print(f"{C.BOLD_CYAN}{'=' * 70}{C.RESET}")
        print(f"{C.BOLD_WHITE}ДЕТАЛЬНА СТАТИСТИКА{C.RESET}")
        print(f"{C.BOLD_CYAN}{'=' * 70}{C.RESET}")

        for name, result in self.results.items():
            if result.iterations == 0:
                continue

            print(f"\n{C.BOLD_GREEN}{result.protocol_name}:{C.RESET}")
            print(f"  {C.CYAN}Час setup:{C.RESET}")
            print(f"    Mean: {C.BOLD_YELLOW}{result.setup_mean:.3f} мс{C.RESET}")
            print(f"    Std:  {result.setup_std:.3f} мс")
            print(f"    Min:  {min(result.setup_times):.3f} мс")
            print(f"    Max:  {max(result.setup_times):.3f} мс")

            print(f"  {C.CYAN}Час генерації:{C.RESET}")
            print(f"    Mean: {C.BOLD_YELLOW}{result.prove_mean:.3f} мс{C.RESET}")
            print(f"    Std:  {result.prove_std:.3f} мс")
            print(f"    Min:  {min(result.prove_times):.3f} мс")
            print(f"    Max:  {max(result.prove_times):.3f} мс")

            print(f"  {C.CYAN}Час верифікації:{C.RESET}")
            print(f"    Mean: {C.BOLD_YELLOW}{result.verify_mean:.3f} мс{C.RESET}")
            print(f"    Std:  {result.verify_std:.3f} мс")
            print(f"    Min:  {min(result.verify_times):.3f} мс")
            print(f"    Max:  {max(result.verify_times):.3f} мс")

            print(f"  {C.CYAN}Розмір доказу:{C.RESET} {C.BOLD_MAGENTA}{result.proof_size_mean:.0f} байт{C.RESET}")

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

    def export_charts(self, output_dir: str = "charts"):
        """
        Generate charts for thesis Section 3.4.

        Creates:
        - prove_verify_comparison.png - Bar chart of prove/verify times
        - proof_size_comparison.png - Bar chart of proof sizes
        - time_distribution.png - Box plot of time distribution
        - combined_metrics.png - Combined comparison chart
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
        except ImportError:
            print("ERROR: matplotlib not installed. Run: pip install matplotlib")
            return

        os.makedirs(output_dir, exist_ok=True)

        # Filter protocols with data
        protocols = []
        prove_times = []
        prove_stds = []
        verify_times = []
        verify_stds = []
        proof_sizes = []
        colors = ['#2ecc71', '#3498db', '#9b59b6']  # green, blue, purple

        for name, result in self.results.items():
            if result.iterations > 0 and result.prove_times:
                protocols.append(result.protocol_name)
                prove_times.append(result.prove_mean)
                prove_stds.append(result.prove_std)
                verify_times.append(result.verify_mean)
                verify_stds.append(result.verify_std)
                proof_sizes.append(result.proof_size_mean)

        if not protocols:
            print("No data to plot.")
            return

        # Set style
        plt.style.use('seaborn-v0_8-whitegrid')
        plt.rcParams['font.size'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12

        # Chart 1: Prove vs Verify Time Comparison
        fig, ax = plt.subplots(figsize=(10, 6))
        x = range(len(protocols))
        width = 0.35

        bars1 = ax.bar([i - width/2 for i in x], prove_times, width,
                       yerr=prove_stds, label='Prove Time', color='#3498db', capsize=5)
        bars2 = ax.bar([i + width/2 for i in x], verify_times, width,
                       yerr=verify_stds, label='Verify Time', color='#2ecc71', capsize=5)

        ax.set_xlabel('Protocol')
        ax.set_ylabel('Time (ms)')
        ax.set_title('ZK Protocol Performance: Prove vs Verify Time')
        ax.set_xticks(x)
        ax.set_xticklabels(protocols)
        ax.legend()
        ax.grid(axis='y', alpha=0.3)

        # Add value labels on bars
        for bar in bars1:
            height = bar.get_height()
            ax.annotate(f'{height:.1f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3), textcoords="offset points",
                       ha='center', va='bottom', fontsize=10)
        for bar in bars2:
            height = bar.get_height()
            ax.annotate(f'{height:.1f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3), textcoords="offset points",
                       ha='center', va='bottom', fontsize=10)

        plt.tight_layout()
        path1 = os.path.join(output_dir, 'prove_verify_comparison.png')
        plt.savefig(path1, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  Chart saved: {path1}")

        # Chart 2: Proof Size Comparison
        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.bar(protocols, proof_sizes, color=colors[:len(protocols)], edgecolor='black')
        ax.set_xlabel('Protocol')
        ax.set_ylabel('Proof Size (bytes)')
        ax.set_title('ZK Protocol Comparison: Proof Size')
        ax.grid(axis='y', alpha=0.3)

        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.0f} B',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3), textcoords="offset points",
                       ha='center', va='bottom', fontsize=11, fontweight='bold')

        plt.tight_layout()
        path2 = os.path.join(output_dir, 'proof_size_comparison.png')
        plt.savefig(path2, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  Chart saved: {path2}")

        # Chart 3: Time Distribution (Box Plot)
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        # Prove time distribution
        prove_data = []
        labels = []
        for name, result in self.results.items():
            if result.iterations > 0 and result.prove_times:
                prove_data.append(result.prove_times)
                labels.append(result.protocol_name)

        if prove_data:
            bp1 = axes[0].boxplot(prove_data, labels=labels, patch_artist=True)
            for patch, color in zip(bp1['boxes'], colors[:len(labels)]):
                patch.set_facecolor(color)
                patch.set_alpha(0.7)
            axes[0].set_ylabel('Time (ms)')
            axes[0].set_title('Prove Time Distribution')
            axes[0].grid(axis='y', alpha=0.3)

        # Verify time distribution
        verify_data = []
        for name, result in self.results.items():
            if result.iterations > 0 and result.verify_times:
                verify_data.append(result.verify_times)

        if verify_data:
            bp2 = axes[1].boxplot(verify_data, labels=labels, patch_artist=True)
            for patch, color in zip(bp2['boxes'], colors[:len(labels)]):
                patch.set_facecolor(color)
                patch.set_alpha(0.7)
            axes[1].set_ylabel('Time (ms)')
            axes[1].set_title('Verify Time Distribution')
            axes[1].grid(axis='y', alpha=0.3)

        plt.tight_layout()
        path3 = os.path.join(output_dir, 'time_distribution.png')
        plt.savefig(path3, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  Chart saved: {path3}")

        # Chart 4: Combined Metrics (Radar-like comparison using grouped bars)
        fig, axes = plt.subplots(1, 3, figsize=(14, 5))

        # Subplot 1: Prove Time
        ax1 = axes[0]
        bars = ax1.bar(protocols, prove_times, yerr=prove_stds,
                       color=colors[:len(protocols)], capsize=5, edgecolor='black')
        ax1.set_title('Prove Time (ms)')
        ax1.set_ylabel('Time (ms)')
        ax1.grid(axis='y', alpha=0.3)
        for bar in bars:
            height = bar.get_height()
            ax1.annotate(f'{height:.1f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points", ha='center', fontsize=10)

        # Subplot 2: Verify Time
        ax2 = axes[1]
        bars = ax2.bar(protocols, verify_times, yerr=verify_stds,
                       color=colors[:len(protocols)], capsize=5, edgecolor='black')
        ax2.set_title('Verify Time (ms)')
        ax2.set_ylabel('Time (ms)')
        ax2.grid(axis='y', alpha=0.3)
        for bar in bars:
            height = bar.get_height()
            ax2.annotate(f'{height:.1f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points", ha='center', fontsize=10)

        # Subplot 3: Proof Size
        ax3 = axes[2]
        bars = ax3.bar(protocols, proof_sizes, color=colors[:len(protocols)], edgecolor='black')
        ax3.set_title('Proof Size (bytes)')
        ax3.set_ylabel('Size (bytes)')
        ax3.grid(axis='y', alpha=0.3)
        for bar in bars:
            height = bar.get_height()
            ax3.annotate(f'{height:.0f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points", ha='center', fontsize=10)

        plt.suptitle(f'ZK Protocol Comparison (n={self.iterations})', fontsize=14, fontweight='bold')
        plt.tight_layout()
        path4 = os.path.join(output_dir, 'combined_metrics.png')
        plt.savefig(path4, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  Chart saved: {path4}")

        print(f"\nAll charts exported to: {output_dir}/")

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