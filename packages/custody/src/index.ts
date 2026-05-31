// Key custody by SHAMIR RECONSTRUCTION. A private key is split into shares; to
// sign, a threshold of shares is presented, the key is REASSEMBLED locally, used
// once, and discarded — it is never stored by the custodian. Rotation replaces the
// key (old shares stop being able to sign, because they no longer reconstruct the
// current public key) and revocation halts signing; both are recorded in a hash-
// chained lifecycle log whose head hash is anchorable on chain.
//
// HONEST LABELLING: this is RECONSTRUCTION custody. There is a moment, inside
// sign(), when the full private key exists in memory. This is NOT threshold ECDSA
// and NOT multi-party computation: the key is not kept distributed through signing,
// and a party holding a threshold of shares can recover it. The security property
// is "no fewer than t shares reveal the key", not "the key never exists". No share,
// key, or reconstructed secret is ever logged.
import type { Scalar, Point, Hash, Result, EcdsaSig } from '@anchorchain/bsv';
import { ok, err, pubKeyOf, ecdsaSign, pointEq, pointToHex, doubleSha256, concat, writeVarInt, HashOps, reduceScalar } from '@anchorchain/bsv';
import type { Share } from './shamir.js';
import { splitSecret, reconstruct } from './shamir.js';

export type { Share } from './shamir.js';
export { splitSecret, reconstruct } from './shamir.js';

export type LifecycleKind = 'genesis' | 'rotation' | 'revocation';

export interface LifecycleEvent {
  kind: LifecycleKind;
  publicKeyHex: string;
  logicalTime: bigint;
  prevHashHex: string;
  hashHex: string;
}

export type CustodyError =
  | { kind: 'Revoked'; message: string }
  | { kind: 'WrongShares'; message: string }
  | { kind: 'BadParams'; message: string };

const enc = new TextEncoder();

function eventHash(kind: LifecycleKind, publicKeyHex: string, logicalTime: bigint, prevHash: Uint8Array): Hash {
  return doubleSha256(concat(enc.encode('custody/' + kind + '/'), enc.encode(publicKeyHex), writeVarInt(logicalTime), prevHash));
}

function randSecret(): Scalar {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  const s = reduceScalar(b);
  return s === 0n ? 1n : s;
}

export class KeyCustodian {
  private pub: Point;
  private revoked = false;
  private readonly events: LifecycleEvent[] = [];
  private lastHash: Hash = HashOps.zero();

  private constructor(pub: Point, genesisTime: bigint) {
    this.pub = pub;
    this.appendEvent('genesis', genesisTime);
  }

  // Create a custodian and DISTRIBUTE shares. The returned shares are the only copy
  // of the key material; the custodian retains the public key and lifecycle only.
  static generate(threshold: number, numShares: number, logicalTime: bigint, secret?: Scalar): Result<{ custodian: KeyCustodian; shares: Share[] }, CustodyError> {
    const s = secret ?? randSecret();
    const split = splitSecret(s, threshold, numShares);
    if (!split.ok) return err({ kind: 'BadParams', message: split.error.message });
    const custodian = new KeyCustodian(pubKeyOf(s), logicalTime);
    return ok({ custodian, shares: split.shares });
  }

  private appendEvent(kind: LifecycleKind, logicalTime: bigint): void {
    const prevHash = this.lastHash;
    const pubHex = pointToHex(this.pub);
    const h = eventHash(kind, pubHex, logicalTime, HashOps.toInternalBytes(prevHash));
    this.events.push({ kind, publicKeyHex: pubHex, logicalTime, prevHashHex: HashOps.toDisplayHex(prevHash), hashHex: HashOps.toDisplayHex(h) });
    this.lastHash = h;
  }

  publicKey(): Point {
    return this.pub;
  }
  publicKeyHex(): string {
    return pointToHex(this.pub);
  }
  isRevoked(): boolean {
    return this.revoked;
  }
  lifecycle(): LifecycleEvent[] {
    return this.events.map((e) => ({ ...e }));
  }
  // The anchorable head of the lifecycle chain.
  headHash(): Hash {
    return this.lastHash;
  }

  // Sign by reconstructing the key from a presented threshold of shares. The
  // reconstructed key must produce THIS custodian's public key, or the shares are
  // rejected (wrong key / too few shares). The key is local to this call.
  sign(shareSubset: Share[], msgHash: Uint8Array): Result<EcdsaSig, CustodyError> {
    if (this.revoked) return err({ kind: 'Revoked', message: 'key is revoked; signing refused' });
    if (shareSubset.length === 0) return err({ kind: 'WrongShares', message: 'no shares presented' });
    const key = reconstruct(shareSubset);
    if (!pointEq(pubKeyOf(key), this.pub)) return err({ kind: 'WrongShares', message: 'shares do not reconstruct the current key (too few, or stale after rotation)' });
    return ok(ecdsaSign(key, msgHash));
  }

  // Rotate to a fresh key: distribute new shares, record a rotation event. Shares
  // from before the rotation can no longer sign (they reconstruct the old key).
  rotate(threshold: number, numShares: number, logicalTime: bigint, secret?: Scalar): Result<{ shares: Share[] }, CustodyError> {
    if (this.revoked) return err({ kind: 'Revoked', message: 'key is revoked; cannot rotate' });
    const s = secret ?? randSecret();
    const split = splitSecret(s, threshold, numShares);
    if (!split.ok) return err({ kind: 'BadParams', message: split.error.message });
    this.pub = pubKeyOf(s);
    this.appendEvent('rotation', logicalTime);
    return ok({ shares: split.shares });
  }

  // Permanently revoke the key; recorded in the lifecycle chain.
  revoke(logicalTime: bigint): void {
    if (this.revoked) return;
    this.revoked = true;
    this.appendEvent('revocation', logicalTime);
  }
}

// Verify the lifecycle hash chain links correctly from genesis to head.
export function verifyLifecycle(events: LifecycleEvent[]): boolean {
  if (events.length === 0 || events[0]!.kind !== 'genesis') return false;
  let prev = HashOps.zero();
  for (const e of events) {
    if (e.prevHashHex !== HashOps.toDisplayHex(prev)) return false;
    const h = eventHash(e.kind, e.publicKeyHex, e.logicalTime, HashOps.toInternalBytes(prev));
    if (HashOps.toDisplayHex(h) !== e.hashHex) return false;
    prev = h;
  }
  return true;
}
