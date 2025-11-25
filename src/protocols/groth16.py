"""
Groth16 zk-SNARK Protocol Implementation

Python wrapper for snarkjs Groth16 proving system.
Used for age verification with zero-knowledge proofs.

Groth16 Properties:
- Setup: Requires trusted setup (circuit-specific)
- Proof size: ~192 bytes (constant, very small)
- Verification: ~5-10ms (very fast, constant time)
- Proving: ~50-200ms (depends on circuit complexity)

Reference: "On the Size of Pairing-based Non-interactive Arguments" (Groth, 2016)
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Tuple, Optional, Any


class Groth16Protocol:
    """
    Groth16 zk-SNARK implementation using snarkjs.

    Workflow:
    1. setup() - Generate proving and verification keys (trusted setup)
    2. prove() - Generate proof for private inputs
    3. verify() - Verify proof with public inputs
    """

    def __init__(self, circuit_path: str = None, build_dir: str = None):
        """
        Initialize Groth16 protocol.

        Args:
            circuit_path: Path to .circom circuit file
            build_dir: Directory for compiled artifacts
        """
        base_path = Path(__file__).parent.parent.parent
        self.circuit_path = circuit_path or str(base_path / "circuits" / "age_check.circom")
        self.build_dir = build_dir or str(base_path / "circuits" / "compiled")

        # Paths for generated files
        self.wasm_path = os.path.join(self.build_dir, "age_check_js", "age_check.wasm")
        self.r1cs_path = os.path.join(self.build_dir, "age_check.r1cs")
        self.zkey_path = os.path.join(self.build_dir, "age_check_groth16.zkey")
        self.vkey_path = os.path.join(self.build_dir, "verification_key_groth16.json")

        self._setup_complete = False
        self._metrics = {}

    def _run_command(self, cmd: list, description: str = "") -> Tuple[bool, str]:
        """Execute shell command and return result."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            if result.returncode != 0:
                return False, result.stderr
            return True, result.stdout
        except subprocess.TimeoutExpired:
            return False, f"Command timed out: {description}"
        except FileNotFoundError as e:
            return False, f"Command not found: {e}"

    def check_dependencies(self) -> Dict[str, bool]:
        """Check if required tools are installed."""
        deps = {}

        # Check circom
        success, _ = self._run_command(["circom", "--version"], "circom version")
        deps['circom'] = success

        # Check snarkjs
        success, _ = self._run_command(["snarkjs", "--version"], "snarkjs version")
        deps['snarkjs'] = success

        # Check node
        success, _ = self._run_command(["node", "--version"], "node version")
        deps['node'] = success

        return deps

    def compile_circuit(self) -> Tuple[bool, Dict]:
        """
        Compile circom circuit to R1CS and WASM.

        Returns:
            Tuple of (success, metrics)
        """
        start_time = time.time()

        os.makedirs(self.build_dir, exist_ok=True)

        # Compile circuit
        cmd = [
            "circom", self.circuit_path,
            "--r1cs",
            "--wasm",
            "--sym",
            "-o", self.build_dir
        ]

        success, output = self._run_command(cmd, "compile circuit")

        compile_time = (time.time() - start_time) * 1000

        metrics = {
            'compile_time_ms': compile_time,
            'success': success,
            'output': output if not success else "Compilation successful"
        }

        return success, metrics

    def setup(self, ptau_path: str = None) -> Tuple[bool, Dict]:
        """
        Perform trusted setup for Groth16.

        This generates:
        - Proving key (zkey)
        - Verification key (vkey)

        Args:
            ptau_path: Path to powers of tau file (downloads if not provided)

        Returns:
            Tuple of (success, metrics)
        """
        start_time = time.time()
        metrics = {'steps': []}

        # Step 1: Compile circuit if not already done
        if not os.path.exists(self.r1cs_path):
            success, compile_metrics = self.compile_circuit()
            metrics['compile'] = compile_metrics
            if not success:
                return False, metrics

        # Step 2: Download or use provided ptau
        if ptau_path is None:
            ptau_path = os.path.join(self.build_dir, "pot12_final.ptau")
            if not os.path.exists(ptau_path):
                # Download powers of tau (pot12 supports up to 2^12 constraints)
                download_cmd = [
                    "curl", "-L",
                    "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau",
                    "-o", ptau_path
                ]
                success, _ = self._run_command(download_cmd, "download ptau")
                if not success:
                    metrics['error'] = "Failed to download powers of tau"
                    return False, metrics

        # Step 3: Generate zkey (proving key)
        step3_start = time.time()
        zkey_cmd = [
            "snarkjs", "groth16", "setup",
            self.r1cs_path,
            ptau_path,
            self.zkey_path
        ]
        success, output = self._run_command(zkey_cmd, "generate zkey")
        metrics['steps'].append({
            'name': 'generate_zkey',
            'time_ms': (time.time() - step3_start) * 1000,
            'success': success
        })
        if not success:
            metrics['error'] = output
            return False, metrics

        # Step 4: Export verification key
        step4_start = time.time()
        vkey_cmd = [
            "snarkjs", "zkey", "export", "verificationkey",
            self.zkey_path,
            self.vkey_path
        ]
        success, output = self._run_command(vkey_cmd, "export vkey")
        metrics['steps'].append({
            'name': 'export_vkey',
            'time_ms': (time.time() - step4_start) * 1000,
            'success': success
        })
        if not success:
            metrics['error'] = output
            return False, metrics

        self._setup_complete = True
        metrics['total_time_ms'] = (time.time() - start_time) * 1000
        metrics['success'] = True

        return True, metrics

    def prove(self, age: int, required_age: int) -> Tuple[Optional[Dict], Dict]:
        """
        Generate Groth16 proof that age >= required_age.

        Args:
            age: Private input (actual age, not revealed)
            required_age: Public input (minimum required age)

        Returns:
            Tuple of (proof_dict, metrics)
        """
        start_time = time.time()
        metrics = {}

        if not self._setup_complete and not os.path.exists(self.zkey_path):
            return None, {'error': 'Setup not complete. Run setup() first.'}

        # Create input file
        input_data = {
            "age": str(age),
            "requiredAge": str(required_age)
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(input_data, f)
            input_path = f.name

        proof_path = os.path.join(self.build_dir, "proof_groth16.json")
        public_path = os.path.join(self.build_dir, "public_groth16.json")

        try:
            # Generate witness
            witness_start = time.time()
            witness_path = os.path.join(self.build_dir, "witness.wtns")

            witness_cmd = [
                "node",
                os.path.join(self.build_dir, "age_check_js", "generate_witness.js"),
                self.wasm_path,
                input_path,
                witness_path
            ]
            success, output = self._run_command(witness_cmd, "generate witness")
            metrics['witness_time_ms'] = (time.time() - witness_start) * 1000

            if not success:
                return None, {'error': f'Witness generation failed: {output}'}

            # Generate proof
            prove_start = time.time()
            prove_cmd = [
                "snarkjs", "groth16", "prove",
                self.zkey_path,
                witness_path,
                proof_path,
                public_path
            ]
            success, output = self._run_command(prove_cmd, "generate proof")
            metrics['prove_time_ms'] = (time.time() - prove_start) * 1000

            if not success:
                return None, {'error': f'Proof generation failed: {output}'}

            # Read proof
            with open(proof_path, 'r') as f:
                proof = json.load(f)
            with open(public_path, 'r') as f:
                public_signals = json.load(f)

            # Calculate proof size
            proof_json = json.dumps(proof)
            metrics['proof_size_bytes'] = len(proof_json.encode('utf-8'))
            metrics['total_time_ms'] = (time.time() - start_time) * 1000
            metrics['success'] = True

            return {
                'proof': proof,
                'public_signals': public_signals,
                'protocol': 'groth16'
            }, metrics

        finally:
            # Cleanup
            if os.path.exists(input_path):
                os.unlink(input_path)

    def verify(self, proof_data: Dict) -> Tuple[bool, Dict]:
        """
        Verify Groth16 proof.

        Args:
            proof_data: Dict containing 'proof' and 'public_signals'

        Returns:
            Tuple of (is_valid, metrics)
        """
        start_time = time.time()
        metrics = {}

        if not os.path.exists(self.vkey_path):
            return False, {'error': 'Verification key not found. Run setup() first.'}

        # Write proof and public signals to temp files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(proof_data['proof'], f)
            proof_path = f.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(proof_data['public_signals'], f)
            public_path = f.name

        try:
            verify_cmd = [
                "snarkjs", "groth16", "verify",
                self.vkey_path,
                public_path,
                proof_path
            ]
            success, output = self._run_command(verify_cmd, "verify proof")

            metrics['verify_time_ms'] = (time.time() - start_time) * 1000
            metrics['success'] = True

            # snarkjs outputs "OK!" if verification succeeds
            is_valid = success and "OK" in output

            return is_valid, metrics

        finally:
            # Cleanup
            if os.path.exists(proof_path):
                os.unlink(proof_path)
            if os.path.exists(public_path):
                os.unlink(public_path)

    def get_protocol_info(self) -> Dict:
        """Return information about Groth16 protocol."""
        return {
            'name': 'Groth16',
            'type': 'zk-SNARK',
            'trusted_setup': True,
            'proof_size': '~192 bytes (constant)',
            'verification_time': 'O(1) - constant time',
            'proving_time': 'O(n) - linear in circuit size',
            'security': '128-bit (BN254 curve)',
            'reference': 'Groth, 2016 - "On the Size of Pairing-based Non-interactive Arguments"',
            'advantages': [
                'Smallest proof size among SNARKs',
                'Fastest verification',
                'Well-audited and battle-tested'
            ],
            'disadvantages': [
                'Requires trusted setup per circuit',
                'Setup ceremony needed for production'
            ]
        }


def demo():
    """Demonstrate Groth16 protocol usage."""
    print("=" * 60)
    print("Groth16 zk-SNARK Age Verification Demo")
    print("=" * 60)

    protocol = Groth16Protocol()

    # Check dependencies
    print("\n1. Checking dependencies...")
    deps = protocol.check_dependencies()
    for dep, installed in deps.items():
        status = "OK" if installed else "MISSING"
        print(f"   {dep}: {status}")

    if not all(deps.values()):
        print("\nPlease install missing dependencies:")
        print("  npm install -g snarkjs circomlib")
        print("  brew install circom  # or build from source")
        return

    # Setup
    print("\n2. Running trusted setup...")
    success, metrics = protocol.setup()
    if not success:
        print(f"   Setup failed: {metrics.get('error', 'Unknown error')}")
        return
    print(f"   Setup complete in {metrics['total_time_ms']:.2f}ms")

    # Generate proof
    print("\n3. Generating proof (age=25, required=18)...")
    proof_data, metrics = protocol.prove(age=25, required_age=18)
    if proof_data is None:
        print(f"   Proof generation failed: {metrics.get('error', 'Unknown error')}")
        return
    print(f"   Proof generated in {metrics['prove_time_ms']:.2f}ms")
    print(f"   Proof size: {metrics['proof_size_bytes']} bytes")

    # Verify proof
    print("\n4. Verifying proof...")
    is_valid, metrics = protocol.verify(proof_data)
    print(f"   Verification: {'VALID' if is_valid else 'INVALID'}")
    print(f"   Verification time: {metrics['verify_time_ms']:.2f}ms")

    # Protocol info
    print("\n5. Protocol Information:")
    info = protocol.get_protocol_info()
    print(f"   Name: {info['name']}")
    print(f"   Type: {info['type']}")
    print(f"   Proof size: {info['proof_size']}")
    print(f"   Verification: {info['verification_time']}")


if __name__ == "__main__":
    demo()