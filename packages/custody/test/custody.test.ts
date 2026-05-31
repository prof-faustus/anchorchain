import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ecdsaVerify, doubleSha256, pubKeyOf, pointEq } from '@anchorchain/bsv';
import { splitSecret, reconstruct, KeyCustodian, verifyLifecycle } from '@anchorchain/custody';

const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};
const msg = doubleSha256(new TextEncoder().encode('sign me'));

test('10.1 Shamir: any threshold subset reconstructs the secret; too few do not', () => {
  const secret = 0x9911_2233_4455_6677_8899n;
  const split = splitSecret(secret, 3, 5);
  assert.ok(split.ok);
  if (!split.ok) return;
  const shares = split.shares;
  // every distinct 3-subset reconstructs the secret
  assert.equal(reconstruct([shares[0]!, shares[2]!, shares[4]!]), secret);
  assert.equal(reconstruct([shares[1]!, shares[3]!, shares[4]!]), secret);
  // two shares reconstruct to something that is NOT the secret
  assert.notEqual(reconstruct([shares[0]!, shares[1]!]), secret);
  // and the reconstructed key's public key matches the secret's
  assert.equal(pointEq(pubKeyOf(reconstruct([shares[0]!, shares[1]!, shares[2]!])), pubKeyOf(secret)), true);
});

test('10.2 custodian signs by reconstruction; signature verifies against the public key', () => {
  const { custodian, shares } = unwrap(KeyCustodian.generate(2, 3, 100n));
  const sig = unwrap(custodian.sign([shares[0]!, shares[2]!], msg));
  assert.equal(ecdsaVerify(custodian.publicKey(), msg, sig), true);
  // too few shares reconstruct the wrong key and are rejected
  assert.equal(custodian.sign([shares[0]!], msg).ok, false);
});

test('10.3 rotation invalidates old shares for signing; new shares sign', () => {
  const gen = unwrap(KeyCustodian.generate(2, 3, 100n));
  const custodian = gen.custodian;
  const oldShares = gen.shares;
  const { shares: newShares } = unwrap(custodian.rotate(2, 3, 200n));
  // old shares now reconstruct the pre-rotation key, which is not the current key
  assert.equal(custodian.sign([oldShares[0]!, oldShares[1]!], msg).ok, false);
  // new shares sign and verify against the rotated public key
  const sig = unwrap(custodian.sign([newShares[0]!, newShares[1]!], msg));
  assert.equal(ecdsaVerify(custodian.publicKey(), msg, sig), true);
});

test('10.4 revocation halts signing and is recorded in the lifecycle chain', () => {
  const { custodian, shares } = unwrap(KeyCustodian.generate(2, 3, 100n));
  custodian.revoke(300n);
  assert.equal(custodian.isRevoked(), true);
  assert.equal(custodian.sign([shares[0]!, shares[1]!], msg).ok, false);
  assert.equal(custodian.rotate(2, 3, 400n).ok, false);
});

test('10.5 the lifecycle hash chain verifies genesis->rotation->revocation and detects tampering', () => {
  const gen = unwrap(KeyCustodian.generate(2, 3, 100n));
  const custodian = gen.custodian;
  unwrap(custodian.rotate(2, 3, 200n));
  custodian.revoke(300n);
  const events = custodian.lifecycle();
  assert.deepEqual(events.map((e) => e.kind), ['genesis', 'rotation', 'revocation']);
  assert.equal(verifyLifecycle(events), true);
  // tamper with a middle event's time -> chain no longer verifies
  const tampered = events.map((e) => ({ ...e }));
  tampered[1] = { ...tampered[1]!, logicalTime: 999n };
  assert.equal(verifyLifecycle(tampered), false);
});
