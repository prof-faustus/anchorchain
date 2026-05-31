import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pubKeyOf, ecdsaSign } from '@anchorchain/bsv';
import { IdentityService, authMessage, bindingHash } from '@anchorchain/identity';
import { HashOps } from '@anchorchain/bsv';

const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};

// A holder: a private scalar with the matching public key, able to answer challenges.
function holder(d: bigint) {
  return {
    pub: pubKeyOf(d),
    answer(uuid: string, nonceHex: string, expiry: bigint) {
      return { uuid, nonceHex, expiry, signature: ecdsaSign(d, authMessage(uuid, nonceHex, expiry)) };
    },
  };
}

test('11.1 binding records a uuid<->pubkey pair with an anchorable hash', () => {
  const svc = new IdentityService();
  const a = holder(0xa11cen);
  const b = unwrap(svc.register('uuid-alice', a.pub, 1n));
  assert.equal(b.uuid, 'uuid-alice');
  assert.equal(b.bindingHashDisplay, HashOps.toDisplayHex(bindingHash('uuid-alice', b.publicKeyHex)));
  // a uuid binds once
  assert.equal(svc.register('uuid-alice', a.pub, 2n).ok, false);
});

test('11.2 authentication requires a valid signature over uuid||nonce||expiry', () => {
  const svc = new IdentityService();
  const a = holder(0xa11cen);
  unwrap(svc.register('uuid-alice', a.pub, 1n));
  const ch = svc.challenge('uuid-alice', 100n);
  assert.equal(svc.authenticate(a.answer('uuid-alice', ch.nonceHex, ch.expiry), 50n).ok, true);
  // an imposter's signature does not verify against alice's bound key
  const imposter = holder(0xbadn);
  const ch2 = svc.challenge('uuid-alice', 100n);
  const bad = svc.authenticate(imposter.answer('uuid-alice', ch2.nonceHex, ch2.expiry), 50n);
  assert.equal(bad.ok === false && bad.error.kind, 'BadSignature');
});

test('11.2 replay is refused: a consumed nonce cannot be used twice', () => {
  const svc = new IdentityService();
  const a = holder(0xa11cen);
  unwrap(svc.register('uuid-alice', a.pub, 1n));
  const ch = svc.challenge('uuid-alice', 100n, 'abcd1234');
  const resp = a.answer('uuid-alice', ch.nonceHex, ch.expiry);
  assert.equal(svc.authenticate(resp, 50n).ok, true);
  const replay = svc.authenticate(resp, 50n);
  assert.equal(replay.ok === false && replay.error.kind, 'ReplayedNonce');
});

test('11.2 expiry is enforced in logical time', () => {
  const svc = new IdentityService();
  const a = holder(0xa11cen);
  unwrap(svc.register('uuid-alice', a.pub, 1n));
  const ch = svc.challenge('uuid-alice', 100n, 'beef');
  const expired = svc.authenticate(a.answer('uuid-alice', ch.nonceHex, ch.expiry), 101n);
  assert.equal(expired.ok === false && expired.error.kind, 'Expired');
});

test('11.3 entitlements are non-transferable: only the bound identity can exercise', () => {
  const svc = new IdentityService();
  const alice = holder(0xa11cen);
  const bob = holder(0xb0bn);
  unwrap(svc.register('uuid-alice', alice.pub, 1n));
  unwrap(svc.register('uuid-bob', bob.pub, 1n));
  unwrap(svc.grant('ent-1', 'uuid-alice', 'anchor:write'));
  // alice exercises with a fresh authenticated response
  const chA = svc.challenge('uuid-alice', 100n, 'n-alice');
  const exA = svc.exercise('ent-1', alice.answer('uuid-alice', chA.nonceHex, chA.expiry), 10n);
  assert.equal(exA.ok && exA.value.scope, 'anchor:write');
  // bob cannot exercise alice's entitlement even with his own valid auth
  const exB = svc.exercise('ent-1', bob.answer('uuid-bob', 'n-bob', 100n), 10n);
  assert.equal(exB.ok === false && exB.error.kind, 'NotEntitled');
  // and bob cannot forge alice's identity on the entitlement (signature fails)
  const forged = svc.exercise('ent-1', { uuid: 'uuid-alice', nonceHex: 'n-forge', expiry: 100n, signature: bob.answer('uuid-bob', 'n-forge', 100n).signature }, 10n);
  assert.equal(forged.ok === false && forged.error.kind, 'BadSignature');
});
