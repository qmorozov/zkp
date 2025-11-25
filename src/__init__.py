"""
Zero Knowledge Proof Age Verification Package

Implementation of Schnorr Sigma Protocol with CORRECT verification.
Uses py_ecc (Ethereum Foundation) for elliptic curve operations.

Properties:
- COMPLETENESS: honest proof is always accepted
- SOUNDNESS: fake proof cannot be created
- ZERO-KNOWLEDGE: verifier learns nothing about age
"""

from .crypto_library_zkp import CryptographyLibraryZKP

__version__ = "2.0.0"
__author__ = "ZKP Age Verification"

__all__ = ["CryptographyLibraryZKP"]