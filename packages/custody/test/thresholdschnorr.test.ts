import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pubKeyOf } from '@anchorchain/bsv';
import { splitSecret, ThresholdParty, verifyCommitments, aggregate, aggregatedR, verifyThresholdSchnorr } from '@anchorchain/custody';
import type { Share } from '@anchorchain/custody';

const msg = new TextEncoder().encode('threshold message');

function shares(secret: bigint, t: number, n: number): Share[] {
  const r = splitSecret(secret, t, n);
  if (!r.ok) throw new Error('split');
  return r.shares;
}

// Run a full t-of-n signing session WITHOUT ever reconstructing the key.
function sign(secret: bigint, signing: Share[]) {
  const P = pubKeyOf(secret);
  const parties = signing.map((s) => new ThresholdParty(s));
  const commitments = parties.map((p) => p.commit());
  const reveals = parties.map((p) => p.reveal());
  assert.equal(verifyCommitments(commitments, reveals), true);
  const R = aggregatedR(reveals);
  const set = signing.map((s) => s.x);
  const partials = parties.map((p) => p.partialSign(msg, P, R, set));
  const agg = aggregate(reveals, partials);
  if (!agg.ok) throw new Error('aggregate');
  return { P, sig: agg.value };
}

test('10.6 threshold Schnorr: any t-of-n signing set produces a valid signature', () => {
  const secret = 0x5ec12345678n;
  const all = shares(secret, 3, 5);
  const a = sign(secret, [all[0]!, all[2]!, all[4]!]);
  assert.equal(verifyThresholdSchnorr(a.P, msg, a.sig), true);
  // a different signing set of the same threshold also signs validly
  const b = sign(secret, [all[1]!, all[3]!, all[4]!]);
  assert.equal(verifyThresholdSchnorr(b.P, msg, b.sig), true);
});

test('10.6 below-threshold parties cannot produce a valid signature', () => {
  const secret = 0x5ec12345678n;
  const all = shares(secret, 3, 5);
  // only two parties sign, but the threshold is three: Lagrange over a 2-set
  // reconstructs the wrong key, so the aggregate signature does not verify
  const bad = sign(secret, [all[0]!, all[1]!]);
  assert.equal(verifyThresholdSchnorr(bad.P, msg, bad.sig), false);
});

test('10.6 a nonce that does not match its round-1 commitment is detected', () => {
  const all = shares(0x5ec12345678n, 2, 3);
  const parties = [new ThresholdParty(all[0]!), new ThresholdParty(all[1]!)];
  const commitments = parties.map((p) => p.commit());
  const reveals = parties.map((p) => p.reveal());
  // a party swaps in a different R after committing
  const other = new ThresholdParty(all[2]!);
  other.commit();
  const tamperedReveals = [reveals[0]!, { index: reveals[1]!.index, R: other.reveal().R }];
  assert.equal(verifyCommitments(commitments, tamperedReveals), false);
});

test('10.6 a tampered aggregate signature fails verification', () => {
  const secret = 0x5ec12345678n;
  const all = shares(secret, 2, 3);
  const a = sign(secret, [all[0]!, all[2]!]);
  assert.equal(verifyThresholdSchnorr(a.P, msg, { R: a.sig.R, s: a.sig.s + 1n }), false);
  assert.equal(verifyThresholdSchnorr(a.P, new TextEncoder().encode('other'), a.sig), false);
});
