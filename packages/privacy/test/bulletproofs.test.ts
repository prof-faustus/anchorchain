import { test } from 'node:test';
import assert from 'node:assert/strict';
import { proveRangeBP, verifyRangeBP, commit, commitEq, randScalar } from '@anchorchain/privacy';

test('9.7 Bulletproof: in-range values verify across bit-widths', () => {
  for (const bits of [8, 16, 32]) {
    const r = randScalar();
    const value = (123456789n + BigInt(bits)) % (1n << BigInt(bits));
    const p = proveRangeBP(value, r, bits);
    assert.ok(p.ok, `prove ${bits}`);
    if (!p.ok) continue;
    assert.equal(commitEq(p.commitment, commit(value, r)), true);
    assert.equal(verifyRangeBP(p.commitment, p.proof), true);
  }
});

test('9.7 Bulletproof: boundary values 0 and 2^n - 1 verify', () => {
  const bits = 16;
  for (const value of [0n, (1n << BigInt(bits)) - 1n]) {
    const r = randScalar();
    const p = proveRangeBP(value, r, bits);
    assert.ok(p.ok);
    if (p.ok) assert.equal(verifyRangeBP(p.commitment, p.proof), true);
  }
});

test('9.7 Bulletproof: out-of-range is unprovable and bad bit-widths are rejected', () => {
  assert.equal(proveRangeBP(1n << 16n, randScalar(), 16).ok, false); // 2^16 needs >16 bits
  assert.equal(proveRangeBP(5n, randScalar(), 12).ok, false); // 12 is not a power of two
});

test('9.7 Bulletproof: the proof is logarithmic in the bit-width', () => {
  const r = randScalar();
  const p8 = proveRangeBP(200n, r, 8);
  const p32 = proveRangeBP(200n, r, 32);
  assert.ok(p8.ok && p32.ok);
  if (p8.ok && p32.ok) {
    assert.equal(p8.proof.ip.L.length, 3); // log2(8)
    assert.equal(p32.proof.ip.L.length, 5); // log2(32) -- grows logarithmically, not linearly
  }
});

test('9.7 Bulletproof: a wrong commitment and a tampered proof are rejected', () => {
  const r = randScalar();
  const p = proveRangeBP(500n, r, 16);
  assert.ok(p.ok);
  if (!p.ok) return;
  // a commitment to a different value fails check 1
  assert.equal(verifyRangeBP(commit(501n, r), p.proof), false);
  // tampering the inner-product scalar a fails the final check
  const tampered = { ...p.proof, ip: { ...p.proof.ip, a: p.proof.ip.a + 1n } };
  assert.equal(verifyRangeBP(p.commitment, tampered), false);
  // tampering tHat fails check 1
  const tampered2 = { ...p.proof, tHat: p.proof.tHat + 1n };
  assert.equal(verifyRangeBP(p.commitment, tampered2), false);
});
