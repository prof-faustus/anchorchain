import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AGE_BITS,
  issuerBirthCommitment,
  ageDeltaCommitment,
  proveAgeAtLeastBP,
  verifyAgeAtLeastBP,
  proveRangeBP,
  commitEq,
  randScalar,
} from '@anchorchain/privacy';

// Same numeric vector as the Rust idattr-zkp tests: birth 1990, "over 21 in 2026" =>
// threshold_year = 2026 - 21 = 2005; 1990 <= 2005 so the holder is over 21.
const BIRTH = 1990n;
const THRESHOLD = 2005n;

test('bridge: over-21 proves and verifies, bound to the issuer commitment', () => {
  const rBirth = randScalar();
  const cBirth = issuerBirthCommitment(BIRTH, rBirth);
  const res = proveAgeAtLeastBP(BIRTH, rBirth, THRESHOLD);
  assert.ok(res.ok, 'honest over-21 holder can prove');
  if (!res.ok) return;
  assert.equal(verifyAgeAtLeastBP(cBirth, THRESHOLD, res.proof), true);
});

test('bridge: the compact proof is LOGARITHMIC in the bit-width (unlike idattr-zkp linear bits)', () => {
  const rBirth = randScalar();
  const res = proveAgeAtLeastBP(BIRTH, rBirth, THRESHOLD);
  assert.ok(res.ok);
  if (!res.ok) return;
  // AGE_BITS = 32 -> log2(32) = 5 inner-product rounds (the Ristretto idattr-zkp proof carries
  // 32 BitProofs instead; this carries 5 (L,R) pairs).
  assert.equal(AGE_BITS, 32);
  assert.equal(res.proof.ip.L.length, 5);
  assert.equal(res.proof.ip.R.length, 5);
});

test('bridge: an under-age holder cannot prove (no honest proof exists)', () => {
  const rBirth = randScalar();
  const underAgeBirth = 2010n; // 16 in 2026, > threshold 2005
  const res = proveAgeAtLeastBP(underAgeBirth, rBirth, THRESHOLD);
  assert.equal(res.ok, false);
  if (!res.ok) assert.equal(res.error.kind, 'UnderAge');
});

test('bridge: a forged commitment is rejected (verifier recomputes C_delta from C_birth)', () => {
  // Mirrors the Rust `under_age_forged_commitment_is_rejected`: an under-age holder (birth 2010)
  // builds a Bulletproof for a small bogus delta against a commitment of THEIR choosing, but the
  // verifier recomputes C_delta from the issuer's real C_birth(2010) => mismatch => reject.
  const rBirth = randScalar();
  const cBirth = issuerBirthCommitment(2010n, rBirth);
  const forgedBlind = randScalar();
  const forged = proveRangeBP(5n, forgedBlind, AGE_BITS); // "I wish my delta were 5"
  assert.ok(forged.ok);
  if (!forged.ok) return;
  // forged.commitment = commit(5, forgedBlind) != ageDeltaCommitment(2005, cBirth(2010))
  assert.equal(commitEq(forged.commitment, ageDeltaCommitment(THRESHOLD, cBirth)), false);
  assert.equal(verifyAgeAtLeastBP(cBirth, THRESHOLD, forged.proof), false);
});

test('bridge: a wrong issuer commitment or wrong threshold is rejected', () => {
  const rBirth = randScalar();
  const cBirth = issuerBirthCommitment(BIRTH, rBirth);
  const res = proveAgeAtLeastBP(BIRTH, rBirth, THRESHOLD);
  assert.ok(res.ok);
  if (!res.ok) return;
  // a different issuer commitment (different birth year) does not verify
  const cWrong = issuerBirthCommitment(BIRTH + 1n, rBirth);
  assert.equal(verifyAgeAtLeastBP(cWrong, THRESHOLD, res.proof), false);
  // a different threshold (different delta commitment) does not verify
  assert.equal(verifyAgeAtLeastBP(cBirth, THRESHOLD + 1n, res.proof), false);
});

test('bridge: exactly-at-threshold (delta = 0) proves and verifies', () => {
  // birth_year == threshold_year => exactly min_age today => delta 0, still in range.
  const rBirth = randScalar();
  const cBirth = issuerBirthCommitment(THRESHOLD, rBirth);
  const res = proveAgeAtLeastBP(THRESHOLD, rBirth, THRESHOLD);
  assert.ok(res.ok);
  if (!res.ok) return;
  assert.equal(verifyAgeAtLeastBP(cBirth, THRESHOLD, res.proof), true);
});
