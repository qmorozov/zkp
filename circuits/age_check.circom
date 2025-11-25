pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Age Verification Circuit for Zero-Knowledge Proofs
 *
 * Proves: age >= requiredAge without revealing actual age
 *
 * Private inputs:
 *   - age: the actual age (hidden from verifier)
 *
 * Public inputs:
 *   - requiredAge: minimum age requirement (known to verifier)
 *
 * Output:
 *   - valid: 1 if age >= requiredAge, 0 otherwise
 */

template AgeCheck(n) {
    // n = number of bits for age representation (8 bits = max 255)

    signal input age;           // private input
    signal input requiredAge;   // public input
    signal output valid;

    // Constraint: age must be representable in n bits (0 <= age < 2^n)
    component ageRangeCheck = Num2Bits(n);
    ageRangeCheck.in <== age;

    // Constraint: requiredAge must be representable in n bits
    component reqRangeCheck = Num2Bits(n);
    reqRangeCheck.in <== requiredAge;

    // Check if age >= requiredAge
    // Using GreaterEqThan from circomlib
    component geq = GreaterEqThan(n);
    geq.in[0] <== age;
    geq.in[1] <== requiredAge;

    valid <== geq.out;
}

// Main component with 8 bits (ages 0-255)
// requiredAge is public, age is private (default)
component main {public [requiredAge]} = AgeCheck(8);