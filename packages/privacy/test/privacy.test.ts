import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scalarAdd, scalarSub } from '@anchorchain/bsv';
import {
  commit,
  addCommit,
  commitEq,
  G,
  H,
  proveDlog,
  verifyDlog,
  proveOneOfMany,
  verifyOneOfMany,
  proveRange,
  verifyRange,
  proveMembership,
  verifyMembership,
  proveConservation,
  verifyConservation,
  obfuscateField,
  verifyObfuscatedField,
  randScalar,
} from '@anchorchain/privacy';

test('9.1 Pedersen commitments are additively homomorphic', () => {
  const v1 = 100n, v2 = 250n;
  const r1 = randScalar(), r2 = randScalar();
  const lhs = addCommit(commit(v1, r1), commit(v2, r2));
  const rhs = commit(scalarAdd(v1, v2), scalarAdd(r1, r2));
  assert.equal(commitEq(lhs, rhs), true);
  // a different value (same blinding) gives a different commitment
  assert.equal(commitEq(commit(v1, r1), commit(v1 + 1n, r1)), false);
});

test('9.2 Schnorr proof of knowledge of a discrete log verifies and rejects a wrong witness', () => {
  const x = randScalar();
  const P = commit(0n, x); // P = x*H
  const proof = proveDlog('t', H, P, x);
  assert.equal(verifyDlog('t', H, P, proof), true);
  // wrong statement / wrong label both fail
  assert.equal(verifyDlog('t', H, commit(0n, randScalar()), proof), false);
  assert.equal(verifyDlog('other', H, P, proof), false);
});

test('9.2 one-out-of-many OR proves membership without revealing the index, and tamper fails', () => {
  const w = randScalar();
  const real = commit(0n, w); // real = w*H, witness known
  const decoys = [commit(0n, randScalar()), commit(0n, randScalar())];
  const statements = [decoys[0]!, real, decoys[1]!];
  const proof = proveOneOfMany('m', H, statements, 1, w);
  assert.equal(verifyOneOfMany('m', H, statements, proof), true);
  // flipping a response breaks the proof
  const bad = { ...proof, s: [proof.s[0]!, scalarAdd(proof.s[1]!, 1n), proof.s[2]!] };
  assert.equal(verifyOneOfMany('m', H, statements, bad), false);
});

test('9.3 range proof: an in-range value verifies against its commitment', () => {
  const value = 200n, blinding = randScalar(), bits = 8;
  const r = proveRange(value, blinding, bits);
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(verifyRange(r.commitment, r.proof), true);
    assert.equal(commitEq(r.commitment, commit(value, blinding)), true);
  }
});

test('9.3 range proof: out-of-range is unprovable; wrong commitment and tampered bits fail', () => {
  const bits = 8;
  assert.equal(proveRange(300n, randScalar(), bits).ok, false); // 300 >= 2^8
  const r = proveRange(123n, randScalar(), bits);
  assert.ok(r.ok);
  if (!r.ok) return;
  // a different commitment does not satisfy the bit-sum binding
  assert.equal(verifyRange(commit(124n, randScalar()), r.proof), false);
  // tampering a single bit commitment is rejected
  const tampered = { ...r.proof, bitCommits: [...r.proof.bitCommits] };
  tampered.bitCommits[0] = commit(1n, randScalar());
  assert.equal(verifyRange(r.commitment, tampered), false);
});

test('9.4 membership proof: in-set verifies, out-of-set is unprovable, wrong set fails', () => {
  const set = [10n, 20n, 30n, 40n];
  const value = 30n, blinding = randScalar();
  const c = commit(value, blinding);
  const m = proveMembership(c, blinding, set, value);
  assert.ok(m.ok);
  if (!m.ok) return;
  assert.equal(verifyMembership(c, set, m.proof), true);
  // same commitment, a set that does not contain the value -> verification fails
  assert.equal(verifyMembership(c, [11n, 21n, 31n, 41n], m.proof), false);
  // a value not in the set cannot be proven
  assert.equal(proveMembership(commit(99n, blinding), blinding, set, 99n).ok, false);
});

test('9.5 homomorphic conservation: balanced books verify, an unbalanced set fails', () => {
  const r1 = randScalar(), r2 = randScalar(), r3 = randScalar(), r4 = randScalar();
  const inputs = [commit(100n, r1), commit(50n, r2)];
  const outputs = [commit(120n, r3), commit(30n, r4)]; // 150 in, 150 out: balanced
  const excess = scalarSub(scalarAdd(r1, r2), scalarAdd(r3, r4));
  const p = proveConservation(inputs, outputs, excess);
  assert.ok(p.ok);
  if (!p.ok) return;
  assert.equal(verifyConservation(inputs, outputs, p.proof), true);
  // an unbalanced output set (140 != 150) cannot pass even with the right excess
  const badOut = [commit(120n, r3), commit(20n, r4)];
  const badExcess = scalarSub(scalarAdd(r1, r2), scalarAdd(r3, r4));
  const bp = proveConservation(inputs, badOut, badExcess);
  assert.ok(bp.ok);
  if (bp.ok) assert.equal(verifyConservation(inputs, badOut, bp.proof), false);
});

test('9.6 metadata obfuscation: a bucketed field verifies and an out-of-bucket value is rejected', () => {
  const blinding = randScalar();
  // value 5000 lies in the bucket [4096, 4096 + 2^10) = [4096, 5120)
  const f = obfuscateField('sizeBytes', 5000n, blinding, 4096n, 10);
  assert.ok(f.ok);
  if (f.ok) {
    assert.equal(verifyObfuscatedField(f.field), true);
    assert.equal('value' in f.field, false); // the cleartext value is not present
  }
  // a value below the bucket cannot be obfuscated into it
  assert.equal(obfuscateField('sizeBytes', 100n, blinding, 4096n, 10).ok, false);
});
