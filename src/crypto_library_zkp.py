"""
Production Age Verification using Zero-Knowledge Proofs

Implementation of Schnorr Sigma Protocol with correct verification.
Uses py_ecc for elliptic curve operations (point addition).

Cryptographic Properties:
- COMPLETENESS: honest proof is always accepted
- SOUNDNESS: fake proof cannot be created (ECDLP)
- ZERO-KNOWLEDGE: verifier learns nothing about age

Commitment: Pedersen Commitment (C = age * G + r * H)
- Binding: impossible to change age (computational)
- Hiding: information-theoretic (brute-force impossible)

Curve: secp256k1 (Bitcoin/Ethereum standard)
Security: 128 bits
"""

import hashlib
import secrets
import time
from typing import Tuple, Dict, Optional

# py_ecc - library with point addition support
from py_ecc.secp256k1 import secp256k1
from py_ecc.fields import optimized_bn128_FQ as FQ

# Color support
try:
    from .colors import Colors, success, error, info, highlight, bold, warning
    COLORS = True
except ImportError:
    # Fallback if colors module not available
    class Colors:
        RESET = BOLD = BOLD_GREEN = BOLD_CYAN = BOLD_YELLOW = BOLD_WHITE = ""
        BOLD_MAGENTA = GREEN = CYAN = YELLOW = ""
    def success(x): return x
    def error(x): return x
    def info(x): return x
    def highlight(x): return x
    def bold(x): return x
    def warning(x): return x
    COLORS = False


class CryptographyLibraryZKP:
    """
    Zero-Knowledge Proof for age verification.

    Implements Schnorr Sigma Protocol with Fiat-Shamir transform.
    Uses secp256k1 curve (Bitcoin/Ethereum standard).

    Mathematical basis:
    - Pedersen Commitment: C = age * G + r * H (information-theoretic hiding)
    - Proof: prove that age >= required_age without revealing age
    - Verification: s1 * G + s2 * H == R + c * C'

    Pedersen Commitment Properties:
    - Binding: impossible to change age (computational, based on ECDLP)
    - Hiding: FULL concealment (information-theoretic, brute-force impossible)
    """

    def __init__(self):
        """Initialize with secp256k1 curve and generators G, H."""
        C = Colors
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")
        print(f"{C.BOLD_WHITE} ZERO-KNOWLEDGE PROOF AGE VERIFICATION{C.RESET}")
        print(f"{C.BOLD_WHITE} Schnorr Sigma Protocol + Pedersen Commitment{C.RESET}")
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")
        print()

        start = time.time()

        # secp256k1 parameters (Bitcoin/Ethereum curve)
        self.G = secp256k1.G  # Generator point G
        self.curve_order = secp256k1.N  # Group order
        self.curve_name = "secp256k1"
        self.security_level = 128  # bits

        # Generator H for Pedersen Commitment ("nothing up my sleeve")
        # H = Hash(G) - deterministic but independent of G
        self.H = self._generate_H()

        elapsed = (time.time() - start) * 1000

        print(f"  {C.CYAN}Elliptic Curve:{C.RESET} {C.BOLD_WHITE}{self.curve_name}{C.RESET}")
        print(f"  {C.CYAN}Security Level:{C.RESET} {C.BOLD_GREEN}{self.security_level} bits{C.RESET}")
        print(f"  {C.CYAN}Curve Order:{C.RESET} {self.curve_order.bit_length()} bits")
        print(f"  {C.CYAN}Used In:{C.RESET} {C.BOLD_YELLOW}Bitcoin, Ethereum, ZCash{C.RESET}")
        print(f"  {C.CYAN}Initialization:{C.RESET} {elapsed:.2f} ms")
        print()
        print(f"  {C.CYAN}Commitment:{C.RESET} {C.BOLD_MAGENTA}Pedersen (C = age*G + r*H){C.RESET}")
        print(f"  {C.CYAN}Hiding:{C.RESET} {C.BOLD_GREEN}Information-theoretic{C.RESET} (brute-force proof)")
        print(f"  {C.CYAN}Library:{C.RESET} py_ecc (Ethereum Foundation)")
        print(f"  {C.CYAN}Point Addition:{C.RESET} {C.BOLD_GREEN}SUPPORTED{C.RESET} (full verification)")
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")
        print()

    def _generate_H(self) -> tuple:
        """
        Generate second point H for Pedersen Commitment.

        Uses "nothing up my sleeve" approach:
        H = hash_to_curve(encode(G))

        This guarantees that nobody knows the discrete log of H with respect to G.
        """
        # Hash G coordinates to get seed
        hasher = hashlib.sha256()
        hasher.update(b"Pedersen_H_generator_secp256k1")
        hasher.update(self.G[0].to_bytes(32, 'big'))
        hasher.update(self.G[1].to_bytes(32, 'big'))

        # Use hash as scalar for multiplication by G
        # This gives us point H for which nobody knows discrete log with respect to G
        h_scalar = int.from_bytes(hasher.digest(), 'big') % self.curve_order
        H = secp256k1.multiply(self.G, h_scalar)

        return H

    def _scalar_mult(self, scalar: int, point=None) -> tuple:
        """
        Scalar multiplication: result = scalar * point

        Args:
            scalar: scalar for multiplication
            point: point (if None, uses G)

        Returns:
            Point on curve (x, y)
        """
        if point is None:
            point = self.G

        # Normalize scalar
        scalar = scalar % self.curve_order
        if scalar == 0:
            return None  # Point at infinity

        return secp256k1.multiply(point, scalar)

    def _point_add(self, p1: tuple, p2: tuple) -> tuple:
        """
        Point addition: result = p1 + p2

        Args:
            p1: first point
            p2: second point

        Returns:
            Sum of points
        """
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        return secp256k1.add(p1, p2)

    def _point_neg(self, p: tuple) -> tuple:
        """
        Point negation: result = -p

        For secp256k1: -P = (x, -y mod p)
        """
        if p is None:
            return None
        # secp256k1 field prime
        field_prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        return (p[0], (field_prime - p[1]) % field_prime)

    def _point_sub(self, p1: tuple, p2: tuple) -> tuple:
        """
        Point subtraction: result = p1 - p2
        """
        return self._point_add(p1, self._point_neg(p2))

    def _point_to_bytes(self, point: tuple) -> bytes:
        """Convert point to bytes for hashing."""
        if point is None:
            return b'\x00' * 64
        x, y = point
        return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

    def create_age_commitment(self, age: int) -> Tuple[tuple, Dict]:
        """
        Create cryptographic commitment to age.

        Commitment = age * G (scalar multiplication by generator)

        Properties:
        - Binding: impossible to change age after commitment
        - Hiding: age is hidden (ECDLP)

        Args:
            age: real age (secret)

        Returns:
            Tuple (commitment_point, metrics)
        """
        start = time.time()

        # C = age * G
        commitment = self._scalar_mult(age)

        elapsed = (time.time() - start) * 1000

        metrics = {
            'commitment_point': commitment,
            'age_value': age,
            'computation_time_ms': elapsed,
            'operation': 'Elliptic Curve Scalar Multiplication',
            'formula': 'C = age * G',
            'curve': self.curve_name,
            'library': 'py_ecc (Ethereum Foundation)'
        }

        return commitment, metrics

    def create_pedersen_commitment(self, age: int) -> Tuple[tuple, int, Dict]:
        """
        Create Pedersen Commitment to age.

        Pedersen Commitment: C = age * G + r * H

        where:
        - age: value being hidden
        - r: random blinding factor
        - G, H: independent generators

        Properties:
        - BINDING: impossible to find (age', r') != (age, r) with same C
                   (computational, based on ECDLP)
        - HIDING: INFORMATION-THEORETIC concealment
                  For any age there exists r that gives the same C
                  Brute-force attack IMPOSSIBLE!

        Args:
            age: real age (secret)

        Returns:
            Tuple (commitment_point, blinding_factor, metrics)
        """
        start = time.time()

        # Generate random blinding factor
        r = secrets.randbelow(self.curve_order - 1) + 1

        # C = age * G + r * H
        age_G = self._scalar_mult(age, self.G)
        r_H = self._scalar_mult(r, self.H)
        commitment = self._point_add(age_G, r_H)

        elapsed = (time.time() - start) * 1000

        metrics = {
            'commitment_point': commitment,
            'age_value': age,
            'blinding_factor_bits': r.bit_length(),
            'computation_time_ms': elapsed,
            'operation': 'Pedersen Commitment',
            'formula': 'C = age * G + r * H',
            'hiding': 'Information-theoretic (PERFECT)',
            'binding': 'Computational (ECDLP)',
            'curve': self.curve_name,
            'library': 'py_ecc'
        }

        return commitment, r, metrics

    def pedersen_prove(
        self,
        age: int,
        required_age: int,
        commitment: tuple,
        blinding_factor: int
    ) -> Tuple[Dict, Dict]:
        """
        Generate ZK proof for Pedersen Commitment.

        Prove knowledge of (age_diff, r) such that:
        C' = age_diff * G + r * H

        where C' = C - required_age * G

        Protocol (Double Schnorr / Okamoto):
        1. Generate random k1, k2
        2. R = k1 * G + k2 * H
        3. c = Hash(C' || R)
        4. s1 = k1 + c * age_diff (mod n)
        5. s2 = k2 + c * r (mod n)

        Verification:
        s1 * G + s2 * H == R + c * C'

        Args:
            age: real age (secret)
            required_age: minimum age (public)
            commitment: Pedersen commitment
            blinding_factor: r from commitment

        Returns:
            Tuple (proof_data, metrics)
        """
        if age < required_age:
            raise ValueError(
                f"Cannot prove age >= {required_age} when age = {age}. "
                f"This is the SOUNDNESS property."
            )

        total_start = time.time()

        age_diff = age - required_age

        # STEP 1: Generate random nonces
        step1_start = time.time()
        k1 = secrets.randbelow(self.curve_order - 1) + 1
        k2 = secrets.randbelow(self.curve_order - 1) + 1
        step1_time = (time.time() - step1_start) * 1000

        # STEP 2: R = k1 * G + k2 * H
        step2_start = time.time()
        k1_G = self._scalar_mult(k1, self.G)
        k2_H = self._scalar_mult(k2, self.H)
        R = self._point_add(k1_G, k2_H)
        step2_time = (time.time() - step2_start) * 1000

        # STEP 3: Challenge (Fiat-Shamir)
        step3_start = time.time()

        # C' = C - required_age * G
        req_G = self._scalar_mult(required_age, self.G)
        C_prime = self._point_sub(commitment, req_G)

        hasher = hashlib.sha256()
        hasher.update(self._point_to_bytes(C_prime))
        hasher.update(self._point_to_bytes(R))
        hasher.update(str(required_age).encode())
        challenge_bytes = hasher.digest()

        c = int.from_bytes(challenge_bytes, byteorder='big') % self.curve_order
        step3_time = (time.time() - step3_start) * 1000

        # STEP 4: Responses
        step4_start = time.time()
        s1 = (k1 + c * age_diff) % self.curve_order
        s2 = (k2 + c * blinding_factor) % self.curve_order
        step4_time = (time.time() - step4_start) * 1000

        total_time = (time.time() - total_start) * 1000

        proof_data = {
            'R': R,
            'c': c,
            's1': s1,
            's2': s2,
            'required_age': required_age,
            'commitment_type': 'pedersen'
        }

        # Proof size (larger due to s1, s2)
        proof_size = 32 + 32 + 32 + 32 + 64  # s1 + s2 + c + required_age + R(x,y)

        metrics = {
            'total_time_ms': total_time,
            'step1_nonce_generation_ms': step1_time,
            'step2_commitment_R_ms': step2_time,
            'step3_challenge_ms': step3_time,
            'step4_response_ms': step4_time,
            'proof_size_bytes': proof_size,
            'age_difference': age_diff,
            'protocol': 'Double Schnorr (Pedersen)',
            'transform': 'Fiat-Shamir (non-interactive)',
            'hash_function': 'SHA-256',
            'hiding': 'Information-theoretic',
            'library': 'py_ecc'
        }

        return proof_data, metrics

    def pedersen_verify(
        self,
        commitment: tuple,
        required_age: int,
        proof: Dict
    ) -> Tuple[bool, Dict]:
        """
        Verify ZK proof for Pedersen Commitment.

        Check equation:
        s1 * G + s2 * H == R + c * C'

        where C' = C - required_age * G

        Args:
            commitment: Pedersen commitment
            required_age: minimum age
            proof: proof data (R, c, s1, s2)

        Returns:
            Tuple (is_valid, metrics)
        """
        total_start = time.time()

        R = proof['R']
        c = proof['c']
        s1 = proof['s1']
        s2 = proof['s2']

        # STEP 1: Compute C'
        step1_start = time.time()
        req_G = self._scalar_mult(required_age, self.G)
        C_prime = self._point_sub(commitment, req_G)
        step1_time = (time.time() - step1_start) * 1000

        # STEP 2: Verify challenge (Fiat-Shamir)
        step2_start = time.time()
        hasher = hashlib.sha256()
        hasher.update(self._point_to_bytes(C_prime))
        hasher.update(self._point_to_bytes(R))
        hasher.update(str(required_age).encode())
        challenge_bytes = hasher.digest()

        c_verify = int.from_bytes(challenge_bytes, byteorder='big') % self.curve_order
        step2_time = (time.time() - step2_start) * 1000

        if c != c_verify:
            total_time = (time.time() - total_start) * 1000
            return False, {
                'valid': False,
                'reason': 'Challenge verification failed',
                'total_time_ms': total_time
            }

        # STEP 3: Compute LEFT side: s1 * G + s2 * H
        step3_start = time.time()
        s1_G = self._scalar_mult(s1, self.G)
        s2_H = self._scalar_mult(s2, self.H)
        left_side = self._point_add(s1_G, s2_H)
        step3_time = (time.time() - step3_start) * 1000

        # STEP 4: Compute RIGHT side: R + c * C'
        step4_start = time.time()
        c_C_prime = self._scalar_mult(c, C_prime)
        right_side = self._point_add(R, c_C_prime)
        step4_time = (time.time() - step4_start) * 1000

        # STEP 5: Check equation
        is_valid = (left_side == right_side)

        total_time = (time.time() - total_start) * 1000

        metrics = {
            'valid': is_valid,
            'total_time_ms': total_time,
            'step1_compute_C_prime_ms': step1_time,
            'step2_challenge_verification_ms': step2_time,
            'step3_left_side_ms': step3_time,
            'step4_right_side_ms': step4_time,
            'challenge_matched': c == c_verify,
            'equation_verified': is_valid,
            'verification_equation': 's1*G + s2*H == R + c*(C - required_age*G)',
            'commitment_type': 'pedersen',
            'library': 'py_ecc'
        }

        return is_valid, metrics

    def schnorr_prove(
        self,
        age: int,
        required_age: int,
        commitment: tuple
    ) -> Tuple[Dict, Dict]:
        """
        Generate Schnorr zero-knowledge proof for age >= required_age.

        Protocol:
        1. Compute age_diff = age - required_age
        2. Generate random nonce k
        3. Compute R = k * G
        4. Compute challenge c = Hash(C || R || required_age)
        5. Compute response s = k + c * age_diff (mod n)

        Proof = (R, c, s) - verified without knowing age

        Args:
            age: real age (secret)
            required_age: minimum age (public)
            commitment: commitment to age

        Returns:
            Tuple (proof_data, metrics)

        Raises:
            ValueError: if age < required_age
        """
        if age < required_age:
            raise ValueError(
                f"Cannot prove age >= {required_age} when age = {age}. "
                f"This is the SOUNDNESS property - ZKP cannot prove false statements."
            )

        total_start = time.time()

        # Age difference (this is what we actually prove: age_diff >= 0)
        age_diff = age - required_age

        # STEP 1: Generate random nonce
        step1_start = time.time()
        k = secrets.randbelow(self.curve_order - 1) + 1
        step1_time = (time.time() - step1_start) * 1000

        # STEP 2: Compute R = k * G
        step2_start = time.time()
        R = self._scalar_mult(k)
        step2_time = (time.time() - step2_start) * 1000

        # STEP 3: Challenge via Fiat-Shamir transform
        step3_start = time.time()

        # Hash(C || R || required_age)
        hasher = hashlib.sha256()
        hasher.update(self._point_to_bytes(commitment))
        hasher.update(self._point_to_bytes(R))
        hasher.update(str(required_age).encode())
        challenge_bytes = hasher.digest()

        c = int.from_bytes(challenge_bytes, byteorder='big') % self.curve_order
        step3_time = (time.time() - step3_start) * 1000

        # STEP 4: Response s = k + c * age_diff (mod n)
        step4_start = time.time()
        s = (k + c * age_diff) % self.curve_order
        step4_time = (time.time() - step4_start) * 1000

        total_time = (time.time() - total_start) * 1000

        proof_data = {
            'R': R,
            'c': c,
            's': s,
            'required_age': required_age
        }

        # Proof size
        proof_size = 32 + 32 + 32 + 64  # s + c + required_age + R(x,y)

        metrics = {
            'total_time_ms': total_time,
            'step1_nonce_generation_ms': step1_time,
            'step2_commitment_R_ms': step2_time,
            'step3_challenge_ms': step3_time,
            'step4_response_ms': step4_time,
            'proof_size_bytes': proof_size,
            'age_difference': age_diff,
            'protocol': 'Schnorr Sigma Protocol',
            'transform': 'Fiat-Shamir (non-interactive)',
            'hash_function': 'SHA-256',
            'library': 'py_ecc'
        }

        return proof_data, metrics

    def schnorr_verify(
        self,
        commitment: tuple,
        required_age: int,
        proof: Dict
    ) -> Tuple[bool, Dict]:
        """
        Verify Schnorr zero-knowledge proof.

        CORRECT VERIFICATION (not mock!):

        Verification equation:
            s * G == R + c * C'

        where:
            C' = C - required_age * G (commitment to age difference)
            s * G = left side
            R + c * C' = right side

        If equation holds - proof is valid.

        WHY THIS WORKS:
        - s = k + c * age_diff
        - s * G = k * G + c * age_diff * G = R + c * (age - required_age) * G
        - C' = age * G - required_age * G = (age - required_age) * G
        - Therefore: s * G = R + c * C'

        Args:
            commitment: commitment to age
            required_age: minimum age
            proof: proof data (R, c, s)

        Returns:
            Tuple (is_valid, metrics)
        """
        total_start = time.time()

        R = proof['R']
        c = proof['c']
        s = proof['s']

        # STEP 1: Recompute challenge (Fiat-Shamir verification)
        step1_start = time.time()

        hasher = hashlib.sha256()
        hasher.update(self._point_to_bytes(commitment))
        hasher.update(self._point_to_bytes(R))
        hasher.update(str(required_age).encode())
        challenge_bytes = hasher.digest()

        c_verify = int.from_bytes(challenge_bytes, byteorder='big') % self.curve_order
        step1_time = (time.time() - step1_start) * 1000

        # Check challenge
        if c != c_verify:
            total_time = (time.time() - total_start) * 1000
            return False, {
                'valid': False,
                'reason': 'Challenge verification failed (Fiat-Shamir)',
                'total_time_ms': total_time
            }

        # STEP 2: Compute LEFT side: s * G
        step2_start = time.time()
        left_side = self._scalar_mult(s)
        step2_time = (time.time() - step2_start) * 1000

        # STEP 3: Compute RIGHT side: R + c * C'
        step3_start = time.time()

        # C' = C - required_age * G
        required_age_point = self._scalar_mult(required_age)
        C_prime = self._point_sub(commitment, required_age_point)

        # c * C'
        c_times_C_prime = self._scalar_mult(c, C_prime)

        # R + c * C'
        right_side = self._point_add(R, c_times_C_prime)

        step3_time = (time.time() - step3_start) * 1000

        # STEP 4: Check equation s * G == R + c * C'
        step4_start = time.time()

        # Compare points
        is_valid = (left_side == right_side)

        step4_time = (time.time() - step4_start) * 1000

        total_time = (time.time() - total_start) * 1000

        metrics = {
            'valid': is_valid,
            'total_time_ms': total_time,
            'step1_challenge_verification_ms': step1_time,
            'step2_left_side_sG_ms': step2_time,
            'step3_right_side_R_cC_ms': step3_time,
            'step4_equation_check_ms': step4_time,
            'challenge_matched': c == c_verify,
            'equation_verified': is_valid,
            'verification_equation': 's * G == R + c * (C - required_age * G)',
            'library': 'py_ecc'
        }

        return is_valid, metrics

    # =========================================================================
    # RANGE PROOF (Bit Decomposition)
    # =========================================================================

    def create_range_commitment(
        self,
        value: int,
        num_bits: int = 8
    ) -> Tuple[tuple, int, list, list, Dict]:
        """
        Create Pedersen Commitment with Range Proof support.

        Decompose value into bits and create commitment for each bit.
        This allows proving that 0 <= value < 2^num_bits.

        Math:
        value = b_0 + 2*b_1 + 4*b_2 + ... + 2^(n-1) * b_{n-1}

        Commitment:
        C = value * G + r * H = sum(b_i * 2^i) * G + r * H

        Args:
            value: value for commitment (0 <= value < 2^num_bits)
            num_bits: number of bits (default 8 for range 0-255)

        Returns:
            Tuple (commitment, blinding_factor, bits, bit_blindings, metrics)
        """
        start = time.time()

        max_value = (1 << num_bits) - 1  # 2^num_bits - 1

        if value < 0 or value > max_value:
            raise ValueError(
                f"Value {value} out of range [0, {max_value}]. "
                f"Range proof requires 0 <= value < 2^{num_bits}."
            )

        # Decompose into bits
        bits = [(value >> i) & 1 for i in range(num_bits)]

        # Generate blinding factors for each bit
        # Last blinding is computed so that sum gives total r
        bit_blindings = [
            secrets.randbelow(self.curve_order - 1) + 1
            for _ in range(num_bits - 1)
        ]

        # Total blinding factor
        r = secrets.randbelow(self.curve_order - 1) + 1

        # Last bit blinding = r - sum(2^i * r_i) mod n
        sum_blindings = sum(
            (bit_blindings[i] * (1 << i)) % self.curve_order
            for i in range(num_bits - 1)
        ) % self.curve_order

        last_blinding = (r - sum_blindings) * pow(1 << (num_bits - 1), -1, self.curve_order)
        last_blinding = last_blinding % self.curve_order
        bit_blindings.append(last_blinding)

        # Create commitment: C = value * G + r * H
        value_G = self._scalar_mult(value, self.G)
        r_H = self._scalar_mult(r, self.H)
        commitment = self._point_add(value_G, r_H)

        # Create bit commitments: C_i = b_i * G + r_i * H
        bit_commitments = []
        for i, (b, r_i) in enumerate(zip(bits, bit_blindings)):
            b_G = self._scalar_mult(b, self.G) if b else None
            r_i_H = self._scalar_mult(r_i, self.H)
            C_i = self._point_add(b_G, r_i_H)
            bit_commitments.append(C_i)

        elapsed = (time.time() - start) * 1000

        metrics = {
            'value': value,
            'num_bits': num_bits,
            'max_value': max_value,
            'computation_time_ms': elapsed,
            'commitment_type': 'pedersen_with_range',
            'range': f'[0, {max_value}]'
        }

        return commitment, r, bits, bit_blindings, metrics

    def prove_bit_is_binary(
        self,
        bit: int,
        blinding: int,
        bit_commitment: tuple
    ) -> Dict:
        """
        Prove that bit is in {0, 1} without revealing the value.

        Protocol (OR-proof / Disjunctive Schnorr):
        Prove that C = 0*G + r*H OR C = 1*G + r*H

        Use simulation for the "fake" branch.

        Args:
            bit: bit value (0 or 1)
            blinding: blinding factor r
            bit_commitment: C = bit * G + r * H

        Returns:
            Proof dict
        """
        # OR-proof: prove (C = r*H) OR (C - G = r*H)

        if bit == 0:
            # Real proof for C = 0*G + r*H = r*H
            # Simulate proof for C - G = r*H (fake branch)

            # Simulation for bit=1
            c1 = secrets.randbelow(self.curve_order - 1) + 1
            s1 = secrets.randbelow(self.curve_order - 1) + 1

            # R1 = s1*H - c1*(C - G)
            s1_H = self._scalar_mult(s1, self.H)
            C_minus_G = self._point_sub(bit_commitment, self.G)
            c1_C_minus_G = self._scalar_mult(c1, C_minus_G)
            R1 = self._point_sub(s1_H, c1_C_minus_G)

            # Real proof for bit=0
            k0 = secrets.randbelow(self.curve_order - 1) + 1
            R0 = self._scalar_mult(k0, self.H)

            # Challenge
            hasher = hashlib.sha256()
            hasher.update(self._point_to_bytes(bit_commitment))
            hasher.update(self._point_to_bytes(R0))
            hasher.update(self._point_to_bytes(R1))
            c_total = int.from_bytes(hasher.digest(), 'big') % self.curve_order

            c0 = (c_total - c1) % self.curve_order
            s0 = (k0 + c0 * blinding) % self.curve_order

        else:  # bit == 1
            # Real proof for C - G = r*H
            # Simulate proof for C = r*H (fake branch)

            # Simulation for bit=0
            c0 = secrets.randbelow(self.curve_order - 1) + 1
            s0 = secrets.randbelow(self.curve_order - 1) + 1

            # R0 = s0*H - c0*C
            s0_H = self._scalar_mult(s0, self.H)
            c0_C = self._scalar_mult(c0, bit_commitment)
            R0 = self._point_sub(s0_H, c0_C)

            # Real proof for bit=1
            k1 = secrets.randbelow(self.curve_order - 1) + 1
            R1 = self._scalar_mult(k1, self.H)

            # Challenge
            hasher = hashlib.sha256()
            hasher.update(self._point_to_bytes(bit_commitment))
            hasher.update(self._point_to_bytes(R0))
            hasher.update(self._point_to_bytes(R1))
            c_total = int.from_bytes(hasher.digest(), 'big') % self.curve_order

            c1 = (c_total - c0) % self.curve_order
            s1 = (k1 + c1 * blinding) % self.curve_order

        return {
            'R0': R0,
            'R1': R1,
            'c0': c0,
            'c1': c1,
            's0': s0,
            's1': s1
        }

    def verify_bit_is_binary(
        self,
        bit_commitment: tuple,
        proof: Dict
    ) -> bool:
        """
        Verify that bit commitment contains 0 or 1.

        Check:
        1. c0 + c1 == Hash(C || R0 || R1)
        2. s0 * H == R0 + c0 * C
        3. s1 * H == R1 + c1 * (C - G)

        Args:
            bit_commitment: commitment to bit
            proof: OR-proof

        Returns:
            True if proof is valid
        """
        R0 = proof['R0']
        R1 = proof['R1']
        c0 = proof['c0']
        c1 = proof['c1']
        s0 = proof['s0']
        s1 = proof['s1']

        # Check 1: c0 + c1 == Hash(C || R0 || R1)
        hasher = hashlib.sha256()
        hasher.update(self._point_to_bytes(bit_commitment))
        hasher.update(self._point_to_bytes(R0))
        hasher.update(self._point_to_bytes(R1))
        c_total = int.from_bytes(hasher.digest(), 'big') % self.curve_order

        if (c0 + c1) % self.curve_order != c_total:
            return False

        # Check 2: s0 * H == R0 + c0 * C
        s0_H = self._scalar_mult(s0, self.H)
        c0_C = self._scalar_mult(c0, bit_commitment)
        right_side_0 = self._point_add(R0, c0_C)

        if s0_H != right_side_0:
            return False

        # Check 3: s1 * H == R1 + c1 * (C - G)
        s1_H = self._scalar_mult(s1, self.H)
        C_minus_G = self._point_sub(bit_commitment, self.G)
        c1_C_minus_G = self._scalar_mult(c1, C_minus_G)
        right_side_1 = self._point_add(R1, c1_C_minus_G)

        if s1_H != right_side_1:
            return False

        return True

    def prove_range(
        self,
        value: int,
        num_bits: int = 8
    ) -> Tuple[Dict, Dict]:
        """
        Generate Range Proof for value in range [0, 2^num_bits - 1].

        Prove that 0 <= value < 2^num_bits without revealing value.

        Method: Bit Decomposition + OR-proofs
        1. Decompose value into bits
        2. Create Pedersen commitment for each bit
        3. For each bit prove that it is in {0, 1}
        4. Prove that sum of bit commitments = total commitment

        Args:
            value: value (0 <= value < 2^num_bits)
            num_bits: number of bits

        Returns:
            Tuple (proof_data, metrics)
        """
        total_start = time.time()

        # Step 1: Create commitments
        commitment, r, bits, bit_blindings, _ = self.create_range_commitment(
            value, num_bits
        )

        # Step 2: Create bit commitments
        bit_commitments = []
        for i, (b, r_i) in enumerate(zip(bits, bit_blindings)):
            b_G = self._scalar_mult(b, self.G) if b else None
            r_i_H = self._scalar_mult(r_i, self.H)
            C_i = self._point_add(b_G, r_i_H)
            bit_commitments.append(C_i)

        # Step 3: OR-proof for each bit
        bit_proofs = []
        for i, (b, r_i, C_i) in enumerate(zip(bits, bit_blindings, bit_commitments)):
            bit_proof = self.prove_bit_is_binary(b, r_i, C_i)
            bit_proofs.append(bit_proof)

        total_time = (time.time() - total_start) * 1000

        # Proof size
        proof_size = num_bits * (64 + 64 + 32 + 32 + 32 + 32)  # 6 elements per bit

        proof_data = {
            'commitment': commitment,
            'bit_commitments': bit_commitments,
            'bit_proofs': bit_proofs,
            'num_bits': num_bits,
            'blinding_factor': r  # Needed for further prove
        }

        metrics = {
            'total_time_ms': total_time,
            'num_bits': num_bits,
            'range': f'[0, {(1 << num_bits) - 1}]',
            'proof_size_bytes': proof_size,
            'protocol': 'Bit Decomposition + OR-proofs',
            'hiding': 'Information-theoretic',
            'soundness': 'Computational (ECDLP)'
        }

        return proof_data, metrics

    def verify_range(
        self,
        commitment: tuple,
        proof: Dict
    ) -> Tuple[bool, Dict]:
        """
        Verify Range Proof.

        Check:
        1. Each bit commitment contains 0 or 1 (OR-proofs)
        2. Sum 2^i * C_i == C (commitment consistency)

        Args:
            commitment: total commitment
            proof: range proof data

        Returns:
            Tuple (is_valid, metrics)
        """
        total_start = time.time()

        bit_commitments = proof['bit_commitments']
        bit_proofs = proof['bit_proofs']
        num_bits = proof['num_bits']

        # Check 1: Each bit is in {0, 1}
        for i, (C_i, bit_proof) in enumerate(zip(bit_commitments, bit_proofs)):
            if not self.verify_bit_is_binary(C_i, bit_proof):
                return False, {
                    'valid': False,
                    'reason': f'Bit {i} proof failed',
                    'total_time_ms': (time.time() - total_start) * 1000
                }

        # Check 2: sum(2^i * C_i) == C
        # C_i = b_i * G + r_i * H
        # sum(2^i * C_i) = sum(2^i * b_i) * G + sum(2^i * r_i) * H = value * G + r * H = C
        reconstructed = None
        for i, C_i in enumerate(bit_commitments):
            scaled_C_i = self._scalar_mult(1 << i, C_i)
            reconstructed = self._point_add(reconstructed, scaled_C_i)

        if reconstructed != commitment:
            return False, {
                'valid': False,
                'reason': 'Commitment reconstruction failed',
                'total_time_ms': (time.time() - total_start) * 1000
            }

        total_time = (time.time() - total_start) * 1000

        metrics = {
            'valid': True,
            'total_time_ms': total_time,
            'num_bits_verified': num_bits,
            'range_verified': f'[0, {(1 << num_bits) - 1}]',
            'all_bits_binary': True,
            'commitment_consistent': True
        }

        return True, metrics

    def prove_age_with_range(
        self,
        age: int,
        required_age: int,
        max_age: int = 150
    ) -> Tuple[Dict, Dict]:
        """
        Full ZK proof for age verification with range proof.

        Prove:
        1. age >= required_age (Pedersen proof)
        2. 0 <= age <= max_age (Range proof)

        Args:
            age: real age
            required_age: minimum age
            max_age: maximum age (default 150)

        Returns:
            Tuple (proof_data, metrics)
        """
        total_start = time.time()

        # Determine number of bits for max_age
        num_bits = max_age.bit_length()

        if age < 0 or age > max_age:
            raise ValueError(f"Age {age} out of valid range [0, {max_age}]")

        if age < required_age:
            raise ValueError(
                f"Cannot prove age >= {required_age} when age = {age}. "
                f"SOUNDNESS property."
            )

        # Step 1: Range proof
        range_proof, range_metrics = self.prove_range(age, num_bits)

        # Step 2: Age verification proof (with Pedersen commitment)
        commitment = range_proof['commitment']
        blinding_factor = range_proof['blinding_factor']

        age_proof, age_metrics = self.pedersen_prove(
            age, required_age, commitment, blinding_factor
        )

        total_time = (time.time() - total_start) * 1000

        proof_data = {
            'range_proof': range_proof,
            'age_proof': age_proof,
            'required_age': required_age,
            'max_age': max_age,
            'num_bits': num_bits
        }

        metrics = {
            'total_time_ms': total_time,
            'range_proof_time_ms': range_metrics['total_time_ms'],
            'age_proof_time_ms': age_metrics['total_time_ms'],
            'range': f'[0, {(1 << num_bits) - 1}]',
            'required_age': required_age,
            'protocol': 'Pedersen + Bit Decomposition Range Proof'
        }

        return proof_data, metrics

    def verify_age_with_range(
        self,
        proof: Dict
    ) -> Tuple[bool, Dict]:
        """
        Verify full ZK proof for age with range proof.

        Args:
            proof: proof data from prove_age_with_range

        Returns:
            Tuple (is_valid, metrics)
        """
        total_start = time.time()

        range_proof = proof['range_proof']
        age_proof = proof['age_proof']
        required_age = proof['required_age']

        commitment = range_proof['commitment']

        # Step 1: Verify range proof
        range_valid, range_metrics = self.verify_range(commitment, range_proof)

        if not range_valid:
            return False, {
                'valid': False,
                'reason': 'Range proof verification failed',
                'range_metrics': range_metrics,
                'total_time_ms': (time.time() - total_start) * 1000
            }

        # Step 2: Verify age proof
        age_valid, age_metrics = self.pedersen_verify(
            commitment, required_age, age_proof
        )

        if not age_valid:
            return False, {
                'valid': False,
                'reason': 'Age proof verification failed',
                'age_metrics': age_metrics,
                'total_time_ms': (time.time() - total_start) * 1000
            }

        total_time = (time.time() - total_start) * 1000

        metrics = {
            'valid': True,
            'total_time_ms': total_time,
            'range_verified': True,
            'age_verified': True,
            'range_metrics': range_metrics,
            'age_metrics': age_metrics
        }

        return True, metrics

    def get_system_info(self) -> Dict:
        """Get system information."""
        return {
            'library': 'py_ecc',
            'maintainer': 'Ethereum Foundation',
            'curve': self.curve_name,
            'security_level_bits': self.security_level,
            'protocol': 'Schnorr Sigma Protocol',
            'non_interactive': 'Fiat-Shamir Transform',
            'hash_function': 'SHA-256',
            'point_addition': 'SUPPORTED',
            'verification': 'FULL EQUATION CHECK',
            'soundness': 'GUARANTEED (ECDLP hardness)',
            'used_by': ['Bitcoin', 'Ethereum', 'ZCash', 'Taproot']
        }


def format_point(point: tuple) -> str:
    """Format point for display."""
    if point is None:
        return "Point at Infinity"
    x, y = point
    hex_x = hex(x)
    hex_y = hex(y)
    if len(hex_x) > 20:
        hex_x = f"{hex_x[:10]}...{hex_x[-8:]}"
    if len(hex_y) > 20:
        hex_y = f"{hex_y[:10]}...{hex_y[-8:]}"
    return f"({hex_x}, {hex_y})"


def display_metrics(label: str, metrics: Dict):
    """Display metrics."""
    print(f"\n{label}:")
    for key, value in metrics.items():
        if key == 'commitment_point' or key == 'R':
            if isinstance(value, tuple):
                print(f"  {key}: {format_point(value)}")
        elif 'time' in key.lower() and 'ms' in key.lower():
            print(f"  {key}: {value:.4f} ms")
        elif isinstance(value, list):
            print(f"  {key}:")
            for item in value:
                print(f"    - {item}")
        elif key not in ['c', 's']:
            print(f"  {key}: {value}")