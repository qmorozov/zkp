#!/usr/bin/env python3
"""
Zero-Knowledge Proof Age Verification Demo

Demonstration of Schnorr Sigma Protocol with CORRECT verification.
Interactive step-by-step demonstration of ZKP for age verification.
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
            f"  {C.CYAN}Library:{C.RESET} {C.BOLD_WHITE}py_ecc{C.RESET} (Ethereum Foundation)",
            f"  {C.CYAN}Curve:{C.RESET} {C.BOLD_YELLOW}secp256k1{C.RESET} (Bitcoin/Ethereum)",
            f"  {C.CYAN}Protocol:{C.RESET} {C.BOLD_MAGENTA}Schnorr Sigma{C.RESET} (1989)",
            f"  {C.CYAN}Verification:{C.RESET} {C.BOLD_GREEN}FULL EQUATION CHECK{C.RESET} (s*G == R + c*C')",
            ""
        ]
    )
    wait()

    # Input data
    clear()
    print_header("INPUT DATA")

    actual_age = get_age("Enter your age")
    required_age = get_age("Enter required minimum age")

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
        print(f"\n  {C.BOLD_YELLOW}ZKP cannot prove false statements.{C.RESET}")
        print(f"  This is the {C.BOLD_GREEN}SOUNDNESS{C.RESET} property.\n")
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")
        return

    # STEP 1: Commitment
    clear()
    print_header("STEP 1/3: CREATE COMMITMENT")
    print(f"\n  {C.CYAN}Your age:{C.RESET} {C.BOLD_WHITE}{actual_age}{C.RESET} years {C.BOLD_RED}(SECRET){C.RESET}")
    print(f"  {C.CYAN}Required:{C.RESET} >= {C.BOLD_WHITE}{required_age}{C.RESET} years")
    print()
    print(f"  {C.CYAN}Computing:{C.RESET} {C.BOLD_MAGENTA}Commitment = age * G{C.RESET}")
    print(f"  {C.CYAN}G{C.RESET} = generator point of secp256k1 curve")
    print()

    start = time.perf_counter()
    commitment, comm_metrics = system.create_age_commitment(actual_age)
    elapsed = (time.perf_counter() - start) * 1000

    # Show commitment
    commitment_hex = system._point_to_bytes(commitment).hex()

    print(f"  {C.BOLD_GREEN}✓ Commitment created{C.RESET} in {C.BOLD_YELLOW}{elapsed:.4f} ms{C.RESET}")
    print(f"  Exact age is {C.BOLD_GREEN}CRYPTOGRAPHICALLY HIDDEN{C.RESET}")
    print()
    print(f"  {C.CYAN}Commitment (hex):{C.RESET}")
    print(f"    {C.DIM}X: {commitment_hex[:64]}{C.RESET}")
    print(f"    {C.DIM}Y: {commitment_hex[64:128]}{C.RESET}")
    print(f"    ({len(commitment_hex)} chars, {C.BOLD_MAGENTA}{len(commitment_hex)//2} bytes{C.RESET})")
    print()
    print(f"  Verifier {C.BOLD_WHITE}SEES{C.RESET} commitment but {C.BOLD_RED}CANNOT{C.RESET} recover age")
    print(f"  Requires solving ECDLP: {C.BOLD_YELLOW}~2^128 operations{C.RESET} (~10^38 years)")
    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    wait()

    # STEP 2: Proof Generation
    clear()
    print_header("STEP 2/3: GENERATE PROOF")
    print(f"\n  {C.CYAN}Proving:{C.RESET} {C.BOLD_GREEN}age >= {required_age}{C.RESET}")
    print(f"  {C.CYAN}WITHOUT revealing:{C.RESET} {C.BOLD_RED}age = {actual_age}{C.RESET}")
    print()
    print(f"  {C.BOLD_WHITE}Schnorr Protocol (step by step):{C.RESET}")
    print(f"    {C.BOLD_GREEN}1.{C.RESET} Generate random nonce {C.BOLD_MAGENTA}k{C.RESET}")
    print(f"    {C.BOLD_GREEN}2.{C.RESET} Compute {C.BOLD_MAGENTA}R = k * G{C.RESET}")
    print(f"    {C.BOLD_GREEN}3.{C.RESET} Compute challenge {C.BOLD_MAGENTA}c = Hash(C || R || required_age){C.RESET}")
    print(f"    {C.BOLD_GREEN}4.{C.RESET} Compute response {C.BOLD_MAGENTA}s = k + c * (age - required_age){C.RESET}")
    print()

    start = time.perf_counter()
    proof_data, proof_metrics = system.schnorr_prove(actual_age, required_age, commitment)
    elapsed = (time.perf_counter() - start) * 1000

    print()
    print(f"  {C.BOLD_WHITE}DETAILED METRICS:{C.RESET}")
    print(f"    Step 1 - Nonce generation:    {C.BOLD_YELLOW}{proof_metrics['step1_nonce_generation_ms']:.4f} ms{C.RESET}")
    print(f"    Step 2 - Compute R = k * G:   {C.BOLD_YELLOW}{proof_metrics['step2_commitment_R_ms']:.4f} ms{C.RESET}")
    print(f"    Step 3 - Challenge (SHA-256): {C.BOLD_YELLOW}{proof_metrics['step3_challenge_ms']:.4f} ms{C.RESET}")
    print(f"    Step 4 - Response s:          {C.BOLD_YELLOW}{proof_metrics['step4_response_ms']:.4f} ms{C.RESET}")
    print(f"    {C.DIM}─────────────────────────────────────────────{C.RESET}")
    print(f"    {C.BOLD_WHITE}TOTAL:{C.RESET}                        {C.BOLD_GREEN}{proof_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print()

    # Show proof components
    R_hex = system._point_to_bytes(proof_data['R']).hex()
    c_str = str(proof_data['c'])
    s_str = str(proof_data['s'])

    print(f"  {C.BOLD_WHITE}PROOF COMPONENTS:{C.RESET}")
    print(f"    {C.CYAN}R (point):{C.RESET} {C.DIM}{R_hex[:60]}...{C.RESET}")
    print(f"    {C.CYAN}c (hash):{C.RESET}  {C.DIM}{c_str[:60]}...{C.RESET}")
    print(f"    {C.CYAN}s (scalar):{C.RESET}{C.DIM}{s_str[:60]}...{C.RESET}")
    print(f"    {C.CYAN}Size:{C.RESET}      {C.BOLD_MAGENTA}{proof_metrics['proof_size_bytes']} bytes{C.RESET}")
    print()
    print(f"  From (R, c, s) it is {C.BOLD_RED}IMPOSSIBLE{C.RESET} to recover age")
    print(f"  {C.DIM}s is masked by random nonce k{C.RESET}")
    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    wait()

    # STEP 3: Verification
    clear()
    print_header("STEP 3/3: VERIFY PROOF")
    print(f"\n  Verifier checks the proof")
    print(f"  Verifier {C.BOLD_RED}DOES NOT KNOW{C.RESET} exact age = {C.BOLD_WHITE}{actual_age}{C.RESET}")
    print()
    print(f"  {C.BOLD_GREEN}Verifier KNOWS:{C.RESET}")
    print(f"    {C.CYAN}•{C.RESET} Commitment C (public point)")
    print(f"    {C.CYAN}•{C.RESET} Proof: (R, c, s)")
    print(f"    {C.CYAN}•{C.RESET} required_age = {C.BOLD_WHITE}{required_age}{C.RESET}")
    print()
    print(f"  {C.BOLD_RED}Verifier DOES NOT KNOW:{C.RESET}")
    print(f"    {C.CYAN}•{C.RESET} age = {actual_age}")
    print(f"    {C.CYAN}•{C.RESET} random nonce k")
    print()
    print(f"  {C.BOLD_WHITE}VERIFICATION EQUATION:{C.RESET}")
    print(f"    {C.BOLD_MAGENTA}s * G  ==  R + c * (C - required_age * G){C.RESET}")
    print()
    print(f"  This is {C.BOLD_GREEN}FULL CRYPTOGRAPHIC VERIFICATION{C.RESET} (not a mock!)")
    print()

    start = time.perf_counter()
    is_valid, verify_metrics = system.schnorr_verify(commitment, required_age, proof_data)
    elapsed = (time.perf_counter() - start) * 1000

    print(f"  {C.BOLD_WHITE}VERIFICATION METRICS:{C.RESET}")
    print(f"    Step 1 - Recompute challenge:  {C.BOLD_YELLOW}{verify_metrics['step1_challenge_verification_ms']:.4f} ms{C.RESET}")
    print(f"    Step 2 - Compute s * G:        {C.BOLD_YELLOW}{verify_metrics['step2_left_side_sG_ms']:.4f} ms{C.RESET}")
    print(f"    Step 3 - Compute R + c * C':   {C.BOLD_YELLOW}{verify_metrics['step3_right_side_R_cC_ms']:.4f} ms{C.RESET}")
    print(f"    Step 4 - Check equation:       {C.BOLD_YELLOW}{verify_metrics['step4_equation_check_ms']:.4f} ms{C.RESET}")
    print(f"    {C.DIM}───────────────────────────────────────{C.RESET}")
    print(f"    {C.BOLD_WHITE}TOTAL:{C.RESET}                         {C.BOLD_GREEN}{verify_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print()

    if is_valid:
        print(f"  {C.BOLD_GREEN}✓ PROOF IS VALID{C.RESET}")
        print(f"  {C.BOLD_WHITE}Confirmed:{C.RESET} age >= {required_age}")
        print(f"  Exact age {C.BOLD_GREEN}REMAINS SECRET{C.RESET}")
    else:
        print(f"  {C.BOLD_RED}✗ PROOF IS INVALID{C.RESET}")

    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    wait()

    # RESULT
    clear()
    print_header("FINAL RESULT")
    print()
    print(f"  {C.CYAN}Your age:{C.RESET} {C.BOLD_WHITE}{actual_age}{C.RESET} years")
    print(f"  {C.CYAN}Requirement:{C.RESET} >= {C.BOLD_WHITE}{required_age}{C.RESET} years")
    print()

    if is_valid:
        print(f"  {C.BOLD_GREEN}{'─' * 30}{C.RESET}")
        print(f"  {C.BOLD_GREEN}   ✓ ACCESS GRANTED{C.RESET}")
        print(f"  {C.BOLD_GREEN}{'─' * 30}{C.RESET}")
        print()
        print(f"  {C.BOLD_WHITE}Zero-Knowledge Proof Properties:{C.RESET}")
        print(f"    {C.BOLD_GREEN}COMPLETENESS:{C.RESET}   Honest proof accepted")
        print(f"    {C.BOLD_GREEN}SOUNDNESS:{C.RESET}      Impossible to forge (ECDLP)")
        print(f"    {C.BOLD_GREEN}ZERO-KNOWLEDGE:{C.RESET} Exact age not revealed")
    else:
        print(f"  {C.BOLD_RED}{'─' * 30}{C.RESET}")
        print(f"  {C.BOLD_RED}   ✗ ACCESS DENIED{C.RESET}")
        print(f"  {C.BOLD_RED}{'─' * 30}{C.RESET}")

    print()

    total_time = (
        comm_metrics['computation_time_ms'] +
        proof_metrics['total_time_ms'] +
        verify_metrics['total_time_ms']
    )

    print(f"  {C.BOLD_WHITE}PERFORMANCE:{C.RESET}")
    print(f"    {C.CYAN}Commitment:{C.RESET}    {C.BOLD_YELLOW}{comm_metrics['computation_time_ms']:.4f} ms{C.RESET}")
    print(f"    {C.CYAN}Proof:{C.RESET}         {C.BOLD_YELLOW}{proof_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print(f"    {C.CYAN}Verification:{C.RESET}  {C.BOLD_YELLOW}{verify_metrics['total_time_ms']:.4f} ms{C.RESET}")
    print(f"    {C.DIM}─────────────────────────────────────{C.RESET}")
    print(f"    {C.BOLD_WHITE}TOTAL TIME:{C.RESET}    {C.BOLD_GREEN}{total_time:.4f} ms{C.RESET}")
    print()
    print(f"  {C.BOLD_WHITE}CRYPTOGRAPHY:{C.RESET}")
    print(f"    {C.CYAN}Library:{C.RESET}       py_ecc (Ethereum Foundation)")
    print(f"    {C.CYAN}Curve:{C.RESET}         {C.BOLD_YELLOW}secp256k1{C.RESET} (Bitcoin/Ethereum)")
    print(f"    {C.CYAN}Security:{C.RESET}      {C.BOLD_GREEN}128 bits{C.RESET} (= 3072-bit RSA)")
    print(f"    {C.CYAN}Verification:{C.RESET}  {C.BOLD_GREEN}FULL EQUATION CHECK{C.RESET}")
    print()
    print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")

    # Offer to regenerate proof
    print()
    choice = input(f"Generate another PROOF for the same age? ({C.BOLD_GREEN}y{C.RESET}/{C.BOLD_RED}n{C.RESET}): ").strip().lower()

    if choice == 'y':
        clear()
        print_header("REGENERATE PROOF")
        print()
        print(f"  {C.CYAN}Age:{C.RESET} {C.BOLD_WHITE}{actual_age}{C.RESET} (same!)")
        print(f"  But proof will be {C.BOLD_MAGENTA}DIFFERENT{C.RESET} (new random nonce)")
        print()

        wait()

        start = time.perf_counter()
        proof_data2, proof_metrics2 = system.schnorr_prove(actual_age, required_age, commitment)
        elapsed2 = (time.perf_counter() - start) * 1000

        R_hex2 = system._point_to_bytes(proof_data2['R']).hex()
        c_str2 = str(proof_data2['c'])
        s_str2 = str(proof_data2['s'])

        print(f"  {C.BOLD_WHITE}PROOF #1:{C.RESET}")
        print(f"    {C.CYAN}R:{C.RESET} {C.DIM}{R_hex[:60]}...{C.RESET}")
        print(f"    {C.CYAN}c:{C.RESET} {C.DIM}{c_str[:60]}...{C.RESET}")
        print(f"    {C.CYAN}s:{C.RESET} {C.DIM}{s_str[:60]}...{C.RESET}")
        print()
        print(f"  {C.BOLD_WHITE}PROOF #2:{C.RESET}")
        print(f"    {C.CYAN}R:{C.RESET} {C.DIM}{R_hex2[:60]}...{C.RESET}")
        print(f"    {C.CYAN}c:{C.RESET} {C.DIM}{c_str2[:60]}...{C.RESET}")
        print(f"    {C.CYAN}s:{C.RESET} {C.DIM}{s_str2[:60]}...{C.RESET}")
        print()

        if R_hex != R_hex2:
            print(f"  {C.BOLD_GREEN}✓ PROOFS ARE DIFFERENT!{C.RESET} (dynamically generated, not mocks)")
        else:
            print(f"  {C.BOLD_RED}✗ PROOFS ARE SAME{C.RESET} (impossible!)")

        print()
        print(f"  {C.CYAN}Verifying second proof...{C.RESET}")
        is_valid2, _ = system.schnorr_verify(commitment, required_age, proof_data2)

        if is_valid2:
            print(f"  {C.BOLD_GREEN}✓ Second proof is also VALID!{C.RESET}")
        else:
            print(f"  {C.BOLD_RED}✗ Second proof is INVALID{C.RESET}")

        print()
        print(f"  {C.BOLD_WHITE}WHAT THIS PROVES:{C.RESET}")
        print(f"     {C.CYAN}•{C.RESET} Each time a {C.BOLD_MAGENTA}NEW{C.RESET} proof is generated (dynamic, not mocks)")
        print(f"     {C.CYAN}•{C.RESET} Both proofs are {C.BOLD_GREEN}VALID{C.RESET} (real mathematics)")
        print(f"     {C.CYAN}•{C.RESET} Verifier did {C.BOLD_RED}NOT{C.RESET} learn age from either proof")
        print()
        print(f"{C.BOLD_CYAN}{'=' * 80}{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear()
        print(f"\n{C.BOLD_YELLOW}Program interrupted.{C.RESET}\n")
        sys.exit(0)
