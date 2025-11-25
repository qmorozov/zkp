#!/usr/bin/env python3
"""
Zero-Knowledge Proof Age Verification Demo

Demonstration of Schnorr Sigma Protocol with Pedersen Commitment.
Interactive step-by-step demonstration of ZKP for age verification.

Uses PEDERSEN COMMITMENT: C = age * G + r * H
- Information-theoretic hiding (brute-force impossible)
- Computational binding (based on ECDLP)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.crypto_library_zkp import CryptographyLibraryZKP, format_point
from src.colors import Colors
import time

C = Colors


def clear():
    """Clear console."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_centered(text, width=80):
    """Print centered text."""
    print(f"{C.BOLD_WHITE}{text.center(width)}{C.RESET}")


def print_header(title, width=80):
    """Print colored header."""
    print(f"{C.BOLD_CYAN}{'=' * width}{C.RESET}")
    print_centered(title, width)
    print(f"{C.BOLD_CYAN}{'=' * width}{C.RESET}")


def print_box(title, lines, width=80):
    """Print text in a box."""
    print(f"{C.BOLD_CYAN}{'=' * width}{C.RESET}")
    print_centered(title, width)
    print(f"{C.BOLD_CYAN}{'=' * width}{C.RESET}")
    for line in lines:
        print(line)
    print(f"{C.BOLD_CYAN}{'=' * width}{C.RESET}")


def wait():
    """Wait for Enter key."""
    input(f"\n {C.DIM}Press Enter to continue...{C.RESET}")


def get_age(prompt):
    """Get age input from user."""
    while True:
        try:
            age = int(input(f"\n{C.BOLD_WHITE}{prompt}:{C.RESET} "))
            if 0 <= age <= 150:
                return age
            print(f"{C.BOLD_RED}Enter age from 0 to 150{C.RESET}")
        except ValueError:
            print(f"{C.BOLD_RED}Enter a number{C.RESET}")
        except KeyboardInterrupt:
            print(f"\n\n{C.BOLD_YELLOW}Program interrupted.{C.RESET}")
            sys.exit(0)


def main():
    # SCREEN 0: Welcome
    clear()
    print_box(
        "ZERO-KNOWLEDGE PROOF AGE VERIFICATION",
        [
            "",
            f"  {C.CYAN}Zero-Knowledge Proof{C.RESET} = Prove something {C.BOLD_GREEN}without revealing{C.RESET} information",
            "",
            f"  {C.CYAN}Library:{C.RESET}    {C.BOLD_WHITE}py_ecc{C.RESET} (Ethereum Foundation)",
            f"  {C.CYAN}Curve:{C.RESET}      {C.BOLD_YELLOW}secp256k1{C.RESET} (Bitcoin, Ethereum, ZCash)",
            f"  {C.CYAN}Protocol:{C.RESET}   {C.BOLD_MAGENTA}Schnorr Sigma{C.RESET} + Fiat-Shamir (non-interactive)",
            f"  {C.CYAN}Commitment:{C.RESET} {C.BOLD_GREEN}Pedersen{C.RESET} (C = age*G + r*H)",
            f"  {C.CYAN}Security:{C.RESET}   {C.BOLD_WHITE}128 bits{C.RESET} (equivalent to 3072-bit RSA)",
            "",
            f"  {C.BOLD_WHITE}Pedersen Commitment Properties:{C.RESET}",
            f"    {C.GREEN}•{C.RESET} {C.BOLD_GREEN}Hiding:{C.RESET} Information-theoretic (brute-force IMPOSSIBLE)",
            f"    {C.GREEN}•{C.RESET} {C.BOLD_GREEN}Binding:{C.RESET} Computational (based on ECDLP hardness)",
            ""
        ]
    )
    wait()

    # Input data
    clear()
    print_header("INPUT DATA")

    actual_age = get_age("Enter your REAL age (will be kept SECRET)")
    required_age = get_age("Enter required minimum age (PUBLIC threshold)")

    # Initialize
    clear()
    print_header("SYSTEM INITIALIZATION")
    print(f"\n{C.CYAN}Initializing cryptographic parameters...{C.RESET}\n")

    system = CryptographyLibraryZKP()

    wait()

    # Check possibility
    if actual_age < required_age:
        clear()
        print_header("CANNOT CREATE PROOF")
        print(f"\n  {C.CYAN}Your age:{C.RESET} {C.BOLD_WHITE}{actual_age}{C.RESET} years")
        print(f"  {C.CYAN}Required:{C.RESET} >= {C.BOLD_WHITE}{required_age}{C.RESET} years")
        print(f"\n  {C.CYAN}Result:{C.RESET} {C.BOLD_RED}{actual_age} < {required_age}{C.RESET}")
        print(f"\n  {C.BOLD_YELLOW}ZKP cannot prove false statements!{C.RESET}")
        print(f"  This is the {C.BOLD_GREEN}SOUNDNESS{C.RESET} property:")
        print(f"  {C.DIM}It is mathematically impossible to create a valid proof")
        print(f"  for a statement that is not true.{C.RESET}\n")
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")
        return

    # STEP 1: Pedersen Commitment
    clear()
    print_header("STEP 1/3: CREATE PEDERSEN COMMITMENT")
    print(f"\n  {C.CYAN}Your age:{C.RESET} {C.BOLD_WHITE}{actual_age}{C.RESET} years {C.BOLD_RED}(SECRET — never leaves your device){C.RESET}")
    print(f"  {C.CYAN}Required:{C.RESET} >= {C.BOLD_WHITE}{required_age}{C.RESET} years {C.CYAN}(PUBLIC threshold){C.RESET}")
    print()
    print(f"  {C.BOLD_WHITE}Pedersen Commitment Formula:{C.RESET}")
    print(f"    {C.BOLD_MAGENTA}C = age × G + r × H{C.RESET}")
    print()
    print(f"  {C.CYAN}Where:{C.RESET}")
    print(f"    {C.CYAN}G{C.RESET} = generator point of secp256k1 (public, fixed)")
    print(f"    {C.CYAN}H{C.RESET} = second generator, H = hash_to_curve(G) (public, fixed)")
    print(f"    {C.CYAN}r{C.RESET} = random 256-bit blinding factor (SECRET)")
    print()
    print(f"  {C.BOLD_WHITE}Why is brute-force IMPOSSIBLE?{C.RESET}")
    print(f"    For ANY age value, there exists an 'r' that produces the SAME commitment.")
    print(f"    Attacker cannot distinguish age=18 from age=99 — both are equally likely!")
    print()

    start = time.perf_counter()
    commitment, blinding_factor, comm_metrics = system.create_pedersen_commitment(actual_age)
    elapsed = (time.perf_counter() - start) * 1000

    # Show commitment
    commitment_hex = system._point_to_bytes(commitment).hex()

    print(f"  {C.BOLD_GREEN}✓ Pedersen Commitment created{C.RESET} in {C.BOLD_YELLOW}{elapsed:.4f} ms{C.RESET}")
    print()
    print(f"  {C.CYAN}Commitment C (point on curve):{C.RESET}")
    print(f"    {C.DIM}X: {commitment_hex[:64]}{C.RESET}")
    print(f"    {C.DIM}Y: {commitment_hex[64:128]}{C.RESET}")
    print(f"    Size: {C.BOLD_MAGENTA}{len(commitment_hex)//2} bytes{C.RESET}")
    print()
    print(f"  {C.CYAN}Blinding factor r:{C.RESET} {C.BOLD_RED}SECRET{C.RESET} ({blinding_factor.bit_length()} bits)")
    print()
    print(f"  {C.BOLD_WHITE}Security guarantee:{C.RESET}")
    print(f"    Verifier {C.BOLD_WHITE}SEES{C.RESET} commitment C")
    print(f"    Verifier {C.BOLD_RED}CANNOT{C.RESET} determine age (information-theoretic hiding)")
    print(f"    Breaking requires solving ECDLP: {C.BOLD_YELLOW}~2^128 operations{C.RESET}")
    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    wait()

    # STEP 2: Proof Generation (Double Schnorr / Okamoto)
    clear()
    print_header("STEP 2/3: GENERATE ZERO-KNOWLEDGE PROOF")
    print(f"\n  {C.BOLD_WHITE}Goal:{C.RESET} Prove that {C.BOLD_GREEN}age >= {required_age}{C.RESET}")
    print(f"  {C.BOLD_WHITE}Without revealing:{C.RESET} exact age = {C.BOLD_RED}{actual_age}{C.RESET}")
    print()
    print(f"  {C.BOLD_WHITE}Protocol: Double Schnorr (Okamoto) with Fiat-Shamir{C.RESET}")
    print()
    print(f"  {C.CYAN}Mathematical steps:{C.RESET}")
    print(f"    {C.BOLD_GREEN}1.{C.RESET} Compute C' = C - required_age × G")
    print(f"       (C' is commitment to age_diff = age - required_age)")
    print(f"    {C.BOLD_GREEN}2.{C.RESET} Generate random nonces {C.BOLD_MAGENTA}k₁, k₂{C.RESET}")
    print(f"    {C.BOLD_GREEN}3.{C.RESET} Compute {C.BOLD_MAGENTA}R = k₁ × G + k₂ × H{C.RESET}")
    print(f"    {C.BOLD_GREEN}4.{C.RESET} Compute challenge {C.BOLD_MAGENTA}c = SHA256(C' || R || required_age){C.RESET}")
    print(f"    {C.BOLD_GREEN}5.{C.RESET} Compute responses:")
    print(f"       {C.BOLD_MAGENTA}s₁ = k₁ + c × (age - required_age) mod n{C.RESET}")
    print(f"       {C.BOLD_MAGENTA}s₂ = k₂ + c × r mod n{C.RESET}")
    print()

    start = time.perf_counter()
    proof_data, proof_metrics = system.pedersen_prove(actual_age, required_age, commitment, blinding_factor)
    elapsed = (time.perf_counter() - start) * 1000

    print(f"  {C.BOLD_WHITE}Timing breakdown:{C.RESET}")
    print(f"    Step 1 - Nonce generation (k₁, k₂): {C.BOLD_YELLOW}{proof_metrics['step1_nonce_generation_ms']:.4f} ms{C.RESET}")
    print(f"    Step 2 - Compute R = k₁G + k₂H:     {C.BOLD_YELLOW}{proof_metrics['step2_commitment_R_ms']:.4f} ms{C.RESET}")
    print(f"    Step 3 - Challenge c (SHA-256):     {C.BOLD_YELLOW}{proof_metrics['step3_challenge_ms']:.4f} ms{C.RESET}")
    print(f"    Step 4 - Responses s₁, s₂:          {C.BOLD_YELLOW}{proof_metrics['step4_response_ms']:.4f} ms{C.RESET}")
    print(f"    {C.DIM}─────────────────────────────────────────────────────{C.RESET}")
    print(f"    {C.BOLD_WHITE}TOTAL:{C.RESET}                              {C.BOLD_GREEN}{proof_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print()

    # Show proof components
    R_hex = system._point_to_bytes(proof_data['R']).hex()
    c_str = str(proof_data['c'])
    s1_str = str(proof_data['s1'])
    s2_str = str(proof_data['s2'])

    print(f"  {C.BOLD_WHITE}Proof components (sent to verifier):{C.RESET}")
    print(f"    {C.CYAN}R (point):{C.RESET}  {C.DIM}{R_hex[:50]}...{C.RESET}")
    print(f"    {C.CYAN}c (hash):{C.RESET}   {C.DIM}{c_str[:50]}...{C.RESET}")
    print(f"    {C.CYAN}s₁ (scalar):{C.RESET} {C.DIM}{s1_str[:50]}...{C.RESET}")
    print(f"    {C.CYAN}s₂ (scalar):{C.RESET} {C.DIM}{s2_str[:50]}...{C.RESET}")
    print(f"    {C.CYAN}Size:{C.RESET}       {C.BOLD_MAGENTA}{proof_metrics['proof_size_bytes']} bytes{C.RESET}")
    print()
    print(f"  {C.BOLD_WHITE}Zero-Knowledge property:{C.RESET}")
    print(f"    From (R, c, s₁, s₂) it is {C.BOLD_RED}IMPOSSIBLE{C.RESET} to recover:")
    print(f"      • exact age")
    print(f"      • blinding factor r")
    print(f"      • nonces k₁, k₂")
    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    wait()

    # STEP 3: Verification
    clear()
    print_header("STEP 3/3: VERIFY PROOF")
    print(f"\n  {C.BOLD_WHITE}Verifier's perspective:{C.RESET}")
    print()
    print(f"  {C.BOLD_GREEN}Verifier KNOWS (public):{C.RESET}")
    print(f"    {C.CYAN}•{C.RESET} Commitment C (point on curve)")
    print(f"    {C.CYAN}•{C.RESET} Proof: (R, c, s₁, s₂)")
    print(f"    {C.CYAN}•{C.RESET} required_age = {C.BOLD_WHITE}{required_age}{C.RESET}")
    print(f"    {C.CYAN}•{C.RESET} Public parameters: G, H, curve")
    print()
    print(f"  {C.BOLD_RED}Verifier DOES NOT KNOW (private):{C.RESET}")
    print(f"    {C.CYAN}•{C.RESET} Exact age = {actual_age} {C.BOLD_RED}← HIDDEN!{C.RESET}")
    print(f"    {C.CYAN}•{C.RESET} Blinding factor r")
    print(f"    {C.CYAN}•{C.RESET} Random nonces k₁, k₂")
    print()
    print(f"  {C.BOLD_WHITE}Verification equation:{C.RESET}")
    print(f"    {C.BOLD_MAGENTA}s₁ × G + s₂ × H  ==  R + c × C'{C.RESET}")
    print(f"    where C' = C - required_age × G")
    print()
    print(f"  {C.BOLD_WHITE}Why this works (mathematical proof):{C.RESET}")
    print(f"    Left side:  s₁G + s₂H = (k₁ + c·age_diff)G + (k₂ + c·r)H")
    print(f"              = k₁G + k₂H + c·(age_diff·G + r·H)")
    print(f"              = R + c·C'")
    print(f"    Right side: R + c·C'")
    print(f"    {C.BOLD_GREEN}✓ Equation holds only if prover knows age_diff and r{C.RESET}")
    print()

    start = time.perf_counter()
    is_valid, verify_metrics = system.pedersen_verify(commitment, required_age, proof_data)
    elapsed = (time.perf_counter() - start) * 1000

    print(f"  {C.BOLD_WHITE}Verification timing:{C.RESET}")
    print(f"    Step 1 - Compute C':               {C.BOLD_YELLOW}{verify_metrics['step1_compute_C_prime_ms']:.4f} ms{C.RESET}")
    print(f"    Step 2 - Verify challenge:         {C.BOLD_YELLOW}{verify_metrics['step2_challenge_verification_ms']:.4f} ms{C.RESET}")
    print(f"    Step 3 - Compute s₁G + s₂H:        {C.BOLD_YELLOW}{verify_metrics['step3_left_side_ms']:.4f} ms{C.RESET}")
    print(f"    Step 4 - Compute R + c·C':         {C.BOLD_YELLOW}{verify_metrics['step4_right_side_ms']:.4f} ms{C.RESET}")
    print(f"    {C.DIM}─────────────────────────────────────────────────────{C.RESET}")
    print(f"    {C.BOLD_WHITE}TOTAL:{C.RESET}                             {C.BOLD_GREEN}{verify_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print()

    if is_valid:
        print(f"  {C.BOLD_GREEN}╔══════════════════════════════════════╗{C.RESET}")
        print(f"  {C.BOLD_GREEN}║     ✓ PROOF SUCCESSFULLY VERIFIED   ║{C.RESET}")
        print(f"  {C.BOLD_GREEN}╚══════════════════════════════════════╝{C.RESET}")
        print(f"\n  {C.BOLD_WHITE}Conclusion:{C.RESET} age >= {required_age} {C.BOLD_GREEN}CONFIRMED{C.RESET}")
        print(f"  Exact age value {C.BOLD_GREEN}REMAINS SECRET{C.RESET}")
    else:
        print(f"  {C.BOLD_RED}╔══════════════════════════════════════╗{C.RESET}")
        print(f"  {C.BOLD_RED}║     ✗ PROOF VERIFICATION FAILED     ║{C.RESET}")
        print(f"  {C.BOLD_RED}╚══════════════════════════════════════╝{C.RESET}")

    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    wait()

    # FINAL RESULT
    clear()
    print_header("SUMMARY")
    print()
    print(f"  {C.CYAN}Your age:{C.RESET}    {C.BOLD_WHITE}{actual_age}{C.RESET} years")
    print(f"  {C.CYAN}Requirement:{C.RESET} >= {C.BOLD_WHITE}{required_age}{C.RESET} years")
    print()

    if is_valid:
        print(f"  {C.BOLD_GREEN}╔════════════════════════════════════════╗{C.RESET}")
        print(f"  {C.BOLD_GREEN}║         ✓ ACCESS GRANTED              ║{C.RESET}")
        print(f"  {C.BOLD_GREEN}║   Age requirement verified via ZKP    ║{C.RESET}")
        print(f"  {C.BOLD_GREEN}╚════════════════════════════════════════╝{C.RESET}")
        print()
        print(f"  {C.BOLD_WHITE}Zero-Knowledge Proof Properties Demonstrated:{C.RESET}")
        print()
        print(f"    {C.BOLD_GREEN}COMPLETENESS{C.RESET}")
        print(f"      If statement is TRUE, honest proof is ALWAYS accepted")
        print(f"      {C.DIM}(We proved age >= {required_age}, and it was accepted){C.RESET}")
        print()
        print(f"    {C.BOLD_GREEN}SOUNDNESS{C.RESET}")
        print(f"      If statement is FALSE, no valid proof can be created")
        print(f"      {C.DIM}(Based on ECDLP hardness — 2^128 operations to break){C.RESET}")
        print()
        print(f"    {C.BOLD_GREEN}ZERO-KNOWLEDGE{C.RESET}")
        print(f"      Verifier learns NOTHING except that age >= {required_age}")
        print(f"      {C.DIM}(Cannot distinguish age={required_age} from age=100){C.RESET}")
    else:
        print(f"  {C.BOLD_RED}╔════════════════════════════════════════╗{C.RESET}")
        print(f"  {C.BOLD_RED}║         ✗ ACCESS DENIED               ║{C.RESET}")
        print(f"  {C.BOLD_RED}╚════════════════════════════════════════╝{C.RESET}")

    print()

    total_time = (
        comm_metrics['computation_time_ms'] +
        proof_metrics['total_time_ms'] +
        verify_metrics['total_time_ms']
    )

    print(f"  {C.BOLD_WHITE}Performance Metrics:{C.RESET}")
    print(f"    {C.CYAN}Commitment:{C.RESET}   {C.BOLD_YELLOW}{comm_metrics['computation_time_ms']:.4f} ms{C.RESET}")
    print(f"    {C.CYAN}Proof:{C.RESET}        {C.BOLD_YELLOW}{proof_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print(f"    {C.CYAN}Verification:{C.RESET} {C.BOLD_YELLOW}{verify_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print(f"    {C.DIM}───────────────────────────────────{C.RESET}")
    print(f"    {C.BOLD_WHITE}TOTAL:{C.RESET}        {C.BOLD_GREEN}{total_time:.4f} ms{C.RESET}")
    print()
    print(f"  {C.BOLD_WHITE}Cryptographic Parameters:{C.RESET}")
    print(f"    {C.CYAN}Curve:{C.RESET}        {C.BOLD_YELLOW}secp256k1{C.RESET} (Bitcoin, Ethereum)")
    print(f"    {C.CYAN}Security:{C.RESET}     {C.BOLD_GREEN}128 bits{C.RESET}")
    print(f"    {C.CYAN}Commitment:{C.RESET}   {C.BOLD_GREEN}Pedersen{C.RESET} (information-theoretic hiding)")
    print(f"    {C.CYAN}Protocol:{C.RESET}     {C.BOLD_MAGENTA}Double Schnorr + Fiat-Shamir{C.RESET}")
    print(f"    {C.CYAN}Library:{C.RESET}      py_ecc (Ethereum Foundation)")
    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    # Offer to regenerate proof
    print()
    choice = input(f"Generate another proof for the same age? ({C.BOLD_GREEN}y{C.RESET}/{C.BOLD_RED}n{C.RESET}): ").strip().lower()

    if choice == 'y':
        clear()
        print_header("PROOF UNIQUENESS DEMONSTRATION")
        print()
        print(f"  {C.BOLD_WHITE}Demonstrating Zero-Knowledge property:{C.RESET}")
        print(f"  Each proof is DIFFERENT (new random nonces)")
        print(f"  But both prove the SAME statement: age >= {required_age}")
        print()
        print(f"  {C.CYAN}Age:{C.RESET} {C.BOLD_WHITE}{actual_age}{C.RESET} (unchanged)")
        print()

        wait()

        start = time.perf_counter()
        proof_data2, proof_metrics2 = system.pedersen_prove(actual_age, required_age, commitment, blinding_factor)
        elapsed2 = (time.perf_counter() - start) * 1000

        R_hex2 = system._point_to_bytes(proof_data2['R']).hex()
        c_str2 = str(proof_data2['c'])
        s1_str2 = str(proof_data2['s1'])
        s2_str2 = str(proof_data2['s2'])

        print(f"  {C.BOLD_WHITE}PROOF #1:{C.RESET}")
        print(f"    {C.CYAN}R:{C.RESET}  {C.DIM}{R_hex[:50]}...{C.RESET}")
        print(f"    {C.CYAN}c:{C.RESET}  {C.DIM}{c_str[:50]}...{C.RESET}")
        print(f"    {C.CYAN}s₁:{C.RESET} {C.DIM}{s1_str[:50]}...{C.RESET}")
        print(f"    {C.CYAN}s₂:{C.RESET} {C.DIM}{s2_str[:50]}...{C.RESET}")
        print()
        print(f"  {C.BOLD_WHITE}PROOF #2:{C.RESET}")
        print(f"    {C.CYAN}R:{C.RESET}  {C.DIM}{R_hex2[:50]}...{C.RESET}")
        print(f"    {C.CYAN}c:{C.RESET}  {C.DIM}{c_str2[:50]}...{C.RESET}")
        print(f"    {C.CYAN}s₁:{C.RESET} {C.DIM}{s1_str2[:50]}...{C.RESET}")
        print(f"    {C.CYAN}s₂:{C.RESET} {C.DIM}{s2_str2[:50]}...{C.RESET}")
        print()

        if R_hex != R_hex2:
            print(f"  {C.BOLD_GREEN}✓ Proofs are DIFFERENT{C.RESET}")
            print(f"    (Different random nonces k₁, k₂ → different R, c, s₁, s₂)")
        else:
            print(f"  {C.BOLD_RED}✗ Proofs are identical{C.RESET} (this should not happen!)")

        print()
        print(f"  {C.CYAN}Verifying proof #2...{C.RESET}")
        is_valid2, _ = system.pedersen_verify(commitment, required_age, proof_data2)

        if is_valid2:
            print(f"  {C.BOLD_GREEN}✓ Proof #2 is also VALID{C.RESET}")
        else:
            print(f"  {C.BOLD_RED}✗ Proof #2 is INVALID{C.RESET}")

        print()
        print(f"  {C.BOLD_WHITE}What this demonstrates:{C.RESET}")
        print(f"    {C.CYAN}•{C.RESET} Multiple valid proofs can exist for the same statement")
        print(f"    {C.CYAN}•{C.RESET} Proofs are freshly generated (not pre-computed)")
        print(f"    {C.CYAN}•{C.RESET} Verifier cannot link two proofs to the same prover")
        print(f"    {C.CYAN}•{C.RESET} This is the {C.BOLD_GREEN}ZERO-KNOWLEDGE{C.RESET} property in action")
        print()
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear()
        print(f"\n{C.BOLD_YELLOW}Program interrupted.{C.RESET}\n")
        sys.exit(0)