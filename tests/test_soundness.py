"""
SOUNDNESS Test: Verify that it is impossible to forge a proof

The SOUNDNESS property means:
- If the statement is FALSE, the verifier will REJECT the proof
- It is impossible to create a valid proof for a false statement

This test is CRITICAL for the thesis!
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from src.crypto_library_zkp import CryptographyLibraryZKP


class TestSoundness:
    """Tests for the SOUNDNESS property."""

    def setup_method(self):
        """Initialize before each test."""
        self.zkp = CryptographyLibraryZKP()

    def test_fake_proof_rejected(self):
        """
        CRITICAL TEST: Fake proof must be REJECTED.

        Scenario:
        - Create commitment for age 15
        - Attempt to "forge" proof that age >= 18
        - Verification MUST REJECT the fake proof
        """
        # Create commitment for age 15
        commitment, _ = self.zkp.create_age_commitment(15)

        # Create fake proof with random values
        fake_proof = {
            'R': self.zkp._scalar_mult(12345),  # random point
            'c': 99999,
            's': 88888
        }

        # Verification MUST be False!
        is_valid, metrics = self.zkp.schnorr_verify(commitment, 18, fake_proof)

        assert is_valid == False, (
            "CRITICAL SOUNDNESS ERROR: fake proof accepted! "
            "This means verification is not working correctly."
        )

    def test_honest_proof_accepted(self):
        """
        COMPLETENESS test: Honest proof must be ACCEPTED.

        Scenario:
        - Create commitment for age 25
        - Create honest proof that age >= 18
        - Verification MUST ACCEPT honest proof
        """
        commitment, _ = self.zkp.create_age_commitment(25)
        proof, _ = self.zkp.schnorr_prove(25, 18, commitment)

        is_valid, metrics = self.zkp.schnorr_verify(commitment, 18, proof)

        assert is_valid == True, (
            "COMPLETENESS ERROR: honest proof rejected! "
            "Verification must accept valid proofs."
        )

    def test_cannot_prove_false_statement(self):
        """
        Test: Cannot create proof for false statement.

        Scenario:
        - Age = 15, required_age = 18
        - Attempting to create proof should raise ValueError
        """
        commitment, _ = self.zkp.create_age_commitment(15)

        with pytest.raises(ValueError) as excinfo:
            self.zkp.schnorr_prove(15, 18, commitment)

        assert "SOUNDNESS" in str(excinfo.value) or "Cannot" in str(excinfo.value)

    def test_modified_challenge_rejected(self):
        """
        Test: Modified challenge must be rejected.

        Scenario:
        - Create valid proof
        - Modify challenge to different value
        - Verification must reject
        """
        commitment, _ = self.zkp.create_age_commitment(25)
        proof, _ = self.zkp.schnorr_prove(25, 18, commitment)

        # Modify challenge
        modified_proof = {
            'R': proof['R'],
            'c': proof['c'] + 1,  # modification!
            's': proof['s']
        }

        is_valid, metrics = self.zkp.schnorr_verify(commitment, 18, modified_proof)

        assert is_valid == False, (
            "ERROR: modified challenge accepted! "
            "Fiat-Shamir verification should reject this."
        )

    def test_modified_response_rejected(self):
        """
        Test: Modified response must be rejected.

        Scenario:
        - Create valid proof
        - Modify response s to different value
        - Verification must reject (equation doesn't hold)
        """
        commitment, _ = self.zkp.create_age_commitment(25)
        proof, _ = self.zkp.schnorr_prove(25, 18, commitment)

        # Modify response
        modified_proof = {
            'R': proof['R'],
            'c': proof['c'],
            's': proof['s'] + 1  # modification!
        }

        is_valid, metrics = self.zkp.schnorr_verify(commitment, 18, modified_proof)

        assert is_valid == False, (
            "ERROR: modified response accepted! "
            "Equation s*G == R + c*C' should not hold."
        )

    def test_wrong_required_age_rejected(self):
        """
        Test: Proof for different required_age must be rejected.

        Scenario:
        - Create proof for required_age = 18
        - Verify with required_age = 21
        - Verification must reject
        """
        commitment, _ = self.zkp.create_age_commitment(25)
        proof, _ = self.zkp.schnorr_prove(25, 18, commitment)

        # Verify with different required_age
        is_valid, metrics = self.zkp.schnorr_verify(commitment, 21, proof)

        assert is_valid == False, (
            "ERROR: proof for different required_age accepted! "
            "Challenge depends on required_age."
        )

    def test_multiple_proofs_all_valid(self):
        """
        Test: Multiple proofs for same commitment are all valid.

        Demonstrates that proofs are dynamically generated (not mocks).
        """
        commitment, _ = self.zkp.create_age_commitment(30)

        proofs = []
        for _ in range(3):
            proof, _ = self.zkp.schnorr_prove(30, 18, commitment)
            proofs.append(proof)

        # All proofs should be different
        r_values = [p['R'] for p in proofs]
        assert len(set(str(r) for r in r_values)) == 3, (
            "ERROR: proofs are not unique! Possibly using mocks."
        )

        # All proofs should be valid
        for i, proof in enumerate(proofs):
            is_valid, _ = self.zkp.schnorr_verify(commitment, 18, proof)
            assert is_valid == True, f"Proof #{i+1} is invalid!"


class TestZeroKnowledge:
    """Tests for the ZERO-KNOWLEDGE property."""

    def setup_method(self):
        """Initialize before each test."""
        self.zkp = CryptographyLibraryZKP()

    def test_different_ages_same_required_indistinguishable(self):
        """
        Zero-Knowledge test: Proof does not reveal exact age.

        Scenario:
        - Create proof for age 25 (required 18)
        - Create proof for age 50 (required 18)
        - Both proofs are structurally similar (cannot determine age)
        """
        commitment1, _ = self.zkp.create_age_commitment(25)
        commitment2, _ = self.zkp.create_age_commitment(50)

        proof1, metrics1 = self.zkp.schnorr_prove(25, 18, commitment1)
        proof2, metrics2 = self.zkp.schnorr_prove(50, 18, commitment2)

        # Both proofs should be valid
        assert self.zkp.schnorr_verify(commitment1, 18, proof1)[0] == True
        assert self.zkp.schnorr_verify(commitment2, 18, proof2)[0] == True

        # Proof size is the same (no information leaks through size)
        assert metrics1['proof_size_bytes'] == metrics2['proof_size_bytes']


class TestEdgeCases:
    """Edge case tests."""

    def setup_method(self):
        """Initialize before each test."""
        self.zkp = CryptographyLibraryZKP()

    def test_age_equals_required(self):
        """Test: age == required_age (edge case)."""
        commitment, _ = self.zkp.create_age_commitment(18)
        proof, _ = self.zkp.schnorr_prove(18, 18, commitment)

        is_valid, _ = self.zkp.schnorr_verify(commitment, 18, proof)
        assert is_valid == True, "Age == required should be valid!"

    def test_age_just_above_required(self):
        """Test: age = required_age + 1."""
        commitment, _ = self.zkp.create_age_commitment(19)
        proof, _ = self.zkp.schnorr_prove(19, 18, commitment)

        is_valid, _ = self.zkp.schnorr_verify(commitment, 18, proof)
        assert is_valid == True

    def test_large_age_difference(self):
        """Test: large age difference."""
        commitment, _ = self.zkp.create_age_commitment(100)
        proof, _ = self.zkp.schnorr_prove(100, 18, commitment)

        is_valid, _ = self.zkp.schnorr_verify(commitment, 18, proof)
        assert is_valid == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
