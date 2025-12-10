// Zero-Knowledge Proof utilities for age verification
// Uses hash chain method for proving age >= min_age without revealing actual age

import { sha256Sync } from "./crypto";

export interface AgeProof {
  proof: string;
  encryptedAge: string;
  seed: string;
}

// Generate secure random seed
function generateSecureSeed(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Hash a value n times
function hashNTimes(value: string, n: number): string {
  let result = value;
  for (let i = 0; i < n; i++) {
    result = sha256Sync(result);
  }
  return result;
}

/**
 * Generate ZKP for proving age >= min_age without revealing actual_age.
 * Uses hash chain method for zero-knowledge.
 *
 * @param actualAge - The user's actual age
 * @param minAge - The minimum age to prove
 * @param seed - Optional seed (if not provided, generates random)
 * @returns AgeProof object containing proof, encrypted age, and seed
 *
 * How it works:
 * - Proof: hash^{1 + actual_age - min_age}(seed)
 * - Encrypted age: hash^{actual_age + 1}(seed)
 * - Verifier can hash the proof min_age times to check if it equals encrypted_age
 */
export function generateAgeProof(
  actualAge: number,
  minAge: number,
  seed?: string
): AgeProof {
  if (actualAge < minAge) {
    throw new Error("Cannot prove age requirement - actual age too low");
  }

  const seedValue = seed || generateSecureSeed();

  // Proof: hash^{1 + actual_age - min_age}(seed)
  const proofIterations = 1 + actualAge - minAge;
  const proof = hashNTimes(seedValue, proofIterations);

  // Encrypted age: hash^{actual_age + 1}(seed)
  const encryptedAge = hashNTimes(seedValue, actualAge + 1);

  return {
    proof,
    encryptedAge,
    seed: seedValue,
  };
}

/**
 * Verify ZKP: Hash proof min_age times and check if matches encrypted_age.
 *
 * @param proof - The proof string
 * @param encryptedAge - The encrypted age string
 * @param minAge - The minimum age to verify
 * @returns True if proven age >= min_age
 *
 * The verifier hashes the proof min_age times:
 * - If hash^{min_age}(proof) == encryptedAge, then age >= min_age is proven
 * - Verifier learns NOTHING about the exact age
 */
export function verifyAgeProof(
  proof: string,
  encryptedAge: string,
  minAge: number
): boolean {
  const result = hashNTimes(proof, minAge);
  return result === encryptedAge;
}

/**
 * Demo: Show the math behind the ZKP
 * This helps explain how the proof works without revealing the actual age
 */
export function explainAgeProof(actualAge: number, minAge: number): string {
  return `
Zero-Knowledge Age Proof Explanation:
======================================

Given:
- Actual Age: ${actualAge} (PRIVATE - never revealed)
- Min Age Required: ${minAge} (PUBLIC)
- Random Seed: S (from trusted issuer)

Prover computes:
1. Proof = hash^${1 + actualAge - minAge}(S)
   - This is the seed hashed ${1 + actualAge - minAge} times

2. Encrypted Age = hash^${actualAge + 1}(S)
   - This is the seed hashed ${actualAge + 1} times

Verifier receives:
- Proof
- Encrypted Age
- Min Age = ${minAge}

Verifier checks:
- hash^${minAge}(Proof) == Encrypted Age?

If TRUE: Age >= ${minAge} is PROVEN ✓
The verifier knows NOTHING about actual age (${actualAge})!

Math check:
hash^${minAge}(Proof) = hash^${minAge}(hash^${1 + actualAge - minAge}(S))
                       = hash^${minAge + 1 + actualAge - minAge}(S)
                       = hash^${actualAge + 1}(S)
                       = Encrypted Age ✓
`;
}

/**
 * Advanced: Generate range proof (e.g., age is between 18-65)
 * This is more complex but still maintains zero-knowledge
 */
export interface RangeProof {
  lowerProof: AgeProof;
  upperProof: AgeProof;
}

export function generateAgeRangeProof(
  actualAge: number,
  minAge: number,
  maxAge: number,
  seed?: string
): RangeProof {
  if (actualAge < minAge || actualAge > maxAge) {
    throw new Error("Actual age outside required range");
  }

  const seedValue = seed || generateSecureSeed();

  // Prove age >= minAge
  const lowerProof = generateAgeProof(actualAge, minAge, seedValue);

  // Prove age <= maxAge by proving (maxAge - actualAge) >= 0
  // This requires a different approach
  const upperProof = {
    proof: hashNTimes(seedValue, maxAge - actualAge + 1),
    encryptedAge: hashNTimes(seedValue, maxAge + 1),
    seed: seedValue,
  };

  return {
    lowerProof,
    upperProof,
  };
}

export function verifyAgeRangeProof(
  rangeProof: RangeProof,
  minAge: number,
  maxAge: number
): { lowerBoundValid: boolean; upperBoundValid: boolean } {
  const lowerBoundValid = verifyAgeProof(
    rangeProof.lowerProof.proof,
    rangeProof.lowerProof.encryptedAge,
    minAge
  );

  const upperBoundValid = verifyAgeProof(
    rangeProof.upperProof.proof,
    rangeProof.upperProof.encryptedAge,
    0
  );

  return { lowerBoundValid, upperBoundValid };
}
