import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ecdsaSign, ecdsaVerify, pubKeyOf, doubleSha256, CURVE_N, scalarMod } from '@anchorchain/bsv';

const msg = doubleSha256(new TextEncoder().encode('anchorchain ecdsa vector'));

test('ecdsa: sign then verify round-trips and is low-s', () => {
  const d = 0x1234_5678_9abc_def0_1122_3344_5566_7788n;
  const pub = pubKeyOf(d);
  const sig = ecdsaSign(d, msg);
  assert.equal(ecdsaVerify(pub, msg, sig), true);
  assert.equal(sig.s <= CURVE_N >> 1n, true); // low-s normalised
});

test('ecdsa: a wrong key, wrong message, and tampered signature all fail', () => {
  const d = 0xdead_beefn;
  const pub = pubKeyOf(d);
  const sig = ecdsaSign(d, msg);
  assert.equal(ecdsaVerify(pubKeyOf(0xfeedn), msg, sig), false); // wrong key
  assert.equal(ecdsaVerify(pub, doubleSha256(new TextEncoder().encode('other')), sig), false); // wrong message
  assert.equal(ecdsaVerify(pub, msg, { r: sig.r, s: scalarMod(sig.s + 1n) }), false); // tampered s
  assert.equal(ecdsaVerify(pub, msg, { r: 0n, s: sig.s }), false); // out-of-range r
});
