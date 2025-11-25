"""
Zero-Knowledge Proof Protocols

This module provides implementations of various ZK proof systems:

1. Schnorr Protocol (Sigma Protocol)
   - Simple, efficient, no trusted setup
   - Interactive or non-interactive (Fiat-Shamir)
   - Used in: Bitcoin Taproot, Monero

2. Groth16 (zk-SNARK)
   - Smallest proof size (~192 bytes)
   - Fastest verification
   - Requires trusted setup per circuit
   - Used in: Zcash, Filecoin

3. PLONK (zk-SNARK)
   - Universal trusted setup (reusable)
   - Larger proofs than Groth16 (~400-800 bytes)
   - More flexible for circuit updates
   - Used in: Aztec, zkSync
"""

from .groth16 import Groth16Protocol
from .plonk import PlonkProtocol

__all__ = [
    'Groth16Protocol',
    'PlonkProtocol',
]

# Protocol comparison table for thesis Section 3.4.1
PROTOCOL_COMPARISON = {
    'schnorr': {
        'name': 'Schnorr Sigma Protocol',
        'setup_time': '0 ms',
        'prove_time': '25-40 ms',
        'verify_time': '10-15 ms',
        'proof_size': '~97 bytes',
        'trusted_setup': False,
        'security_assumption': 'ECDLP (Discrete Log)',
    },
    'groth16': {
        'name': 'Groth16 zk-SNARK',
        'setup_time': '2-5 s',
        'prove_time': '50-200 ms',
        'verify_time': '5-10 ms',
        'proof_size': '~192 bytes',
        'trusted_setup': True,
        'security_assumption': 'Pairing-based (BN254)',
    },
    'plonk': {
        'name': 'PLONK zk-SNARK',
        'setup_time': '3-8 s (universal)',
        'prove_time': '100-500 ms',
        'verify_time': '10-20 ms',
        'proof_size': '~400-800 bytes',
        'trusted_setup': 'Universal',
        'security_assumption': 'Pairing-based (BN254)',
    },
}


def get_protocol_comparison():
    """Return protocol comparison data for thesis."""
    return PROTOCOL_COMPARISON