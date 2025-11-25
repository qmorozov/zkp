# Zero-Knowledge Proof Age Verification

Implementation of zero-knowledge cryptographic protocols for age verification without revealing the actual age.

## Implemented Protocols

| Protocol | Description | Features |
|----------|-------------|----------|
| **Schnorr Sigma** | Interactive proof on ECC | Fastest, no trusted setup |
| **Groth16** | zk-SNARK | Smallest proof (804 B) |
| **PLONK** | zk-SNARK | Universal trusted setup |

## Installation

### 1. Python Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Node.js Dependencies (for Groth16/PLONK)

```bash
npm install
```

### 3. Compile Circom Circuit (one-time)

```bash
npm run compile
```

## Quick Start

```bash
source .venv/bin/activate

# Interactive Schnorr Protocol demo
python age_demo.py

# Compare all protocols
python benchmark_demo.py --quick
```

## Commands

### Age Verification Demo

```bash
python age_demo.py
```

Interactive step-by-step demonstration:
- Creating Pedersen Commitment
- Generating ZK-proof
- Verification without revealing age

### Protocol Benchmarks

```bash
# Quick test (5 iterations, ~30 sec)
python benchmark_demo.py --quick

# Standard test (10 iterations, ~2 min)
python benchmark_demo.py

# Full test (100 iterations, ~10 min)
python benchmark_demo.py --full

# Custom iterations
python benchmark_demo.py -n 50

# Export results
python benchmark_demo.py --full --csv results.csv --latex table.tex
```

### Range Proof Test

```bash
python3 -c "
from src.crypto_library_zkp import CryptographyLibraryZKP

zkp = CryptographyLibraryZKP()

# Prove age is in range [0, 150] without revealing it
proof, _ = zkp.prove_age_with_range(age=25, required_age=18, max_age=150)
valid, _ = zkp.verify_age_with_range(proof)
print(f'Age >= 18 and <= 150: {valid}')
"
```

### Individual Protocols

```bash
# Schnorr only
python3 -c "
from src.crypto_library_zkp import CryptographyLibraryZKP
zkp = CryptographyLibraryZKP()
commitment, _ = zkp.create_age_commitment(25)
proof, _ = zkp.schnorr_prove(25, 18, commitment)
valid, _ = zkp.schnorr_verify(commitment, 18, proof)
print(f'Schnorr valid: {valid}')
"

# Groth16
npx snarkjs groth16 fullprove circuits/input.json \
    circuits/compiled/age_check_js/age_check.wasm \
    circuits/compiled/age_check_groth16.zkey \
    proof.json public.json

npx snarkjs groth16 verify \
    circuits/compiled/verification_key_groth16.json \
    public.json proof.json

# PLONK
npx snarkjs plonk fullprove circuits/input.json \
    circuits/compiled/age_check_js/age_check.wasm \
    circuits/compiled/age_check_plonk.zkey \
    proof.json public.json

npx snarkjs plonk verify \
    circuits/compiled/verification_key_plonk.json \
    public.json proof.json
```

## Project Structure

```
ZeroKnowledgeProofs/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── package.json              # Node.js dependencies
│
├── age_demo.py               # Interactive Schnorr demo
├── benchmark_demo.py         # Protocol comparison
│
├── src/
│   ├── crypto_library_zkp.py # Main library
│   │   ├── Schnorr Protocol
│   │   ├── Pedersen Commitment
│   │   └── Range Proof (Bit Decomposition)
│   │
│   ├── protocols/
│   │   ├── groth16.py        # Groth16 wrapper
│   │   └── plonk.py          # PLONK wrapper
│   │
│   └── benchmarks/
│       └── protocol_comparison.py
│
├── circuits/
│   ├── age_check.circom      # Circom circuit
│   └── compiled/             # Compiled artifacts
│
└── tests/
    └── test_zkp.py
```

## Benchmark Results

| Protocol | Setup | Prove | Verify | Proof Size |
|----------|-------|-------|--------|------------|
| Schnorr  | 0.06 ms | 2 ms | 4 ms | 336 B |
| Groth16  | 0 ms* | 470 ms | 408 ms | 804 B |
| PLONK    | 0 ms* | 534 ms | 408 ms | 2250 B |

\* Setup is performed once during compilation

## Cryptographic Properties

### Schnorr Sigma Protocol
- **Completeness**: Honest prover always convinces verifier
- **Soundness**: Cannot forge proof for age < required
- **Zero-Knowledge**: Verifier learns only that age >= required

### Pedersen Commitment
- **Hiding**: `C = age * G + r * H` — impossible to determine age
- **Binding**: Cannot open commitment to different value

### Range Proof
- **Bit Decomposition**: Proves each bit is 0 or 1
- **Commitment Consistency**: `Σ 2^i * C_i == C`

## API Reference

```python
from src.crypto_library_zkp import CryptographyLibraryZKP

zkp = CryptographyLibraryZKP()

# Create commitment
commitment, metrics = zkp.create_age_commitment(age=25)

# Generate proof
proof, metrics = zkp.schnorr_prove(age=25, required_age=18, commitment=commitment)

# Verify
is_valid, metrics = zkp.schnorr_verify(commitment, required_age=18, proof=proof)

# Range Proof
proof, metrics = zkp.prove_age_with_range(age=25, required_age=18, max_age=150)
is_valid, metrics = zkp.verify_age_with_range(proof)
```

## Requirements

- Python 3.10+
- Node.js 18+
- Circom 2.1.9 (for circuit compilation)

## License

MIT