// Agent identity. An identity is a UUID bound one-to-one to a secp256k1 public key;
// the binding is hashed and anchorable on chain. Authentication is challenge-
// response and replay-hardened on three axes: the holder must produce a valid ECDSA
// SIGNATURE over (uuid || nonce || expiry); the NONCE is single-use (a replayed
// response is refused); and the EXPIRY bounds the response in logical time.
// Entitlements are NON-TRANSFERABLE: an entitlement names the UUID it belongs to,
// and exercising it requires a fresh authenticated response from THAT UUID — another
// identity cannot present it because it cannot sign for the bound key. No private
// key is held or logged here; the service holds only public keys.
import type { Hash, Point, Result, EcdsaSig } from '@anchorchain/bsv';
import { ok, err, ecdsaVerify, pointToHex, pointFromHex, doubleSha256, concat, writeVarInt, toHexLower, HashOps } from '@anchorchain/bsv';

const enc = new TextEncoder();

export interface IdentityBinding {
  uuid: string;
  publicKeyHex: string;
  bindingHashDisplay: string;
}

export interface Challenge {
  uuid: string;
  nonceHex: string;
  expiry: bigint; // logical-time bound
}

export interface AuthResponse {
  uuid: string;
  nonceHex: string;
  expiry: bigint;
  signature: EcdsaSig;
}

export interface Entitlement {
  entitlementId: string;
  uuid: string; // the bound holder
  scope: string;
}

export type IdentityError =
  | { kind: 'UnknownIdentity'; message: string; uuid: string }
  | { kind: 'DuplicateIdentity'; message: string; uuid: string }
  | { kind: 'BadPublicKey'; message: string };

export type AuthError =
  | { kind: 'UnknownIdentity'; message: string; uuid: string }
  | { kind: 'BadSignature'; message: string }
  | { kind: 'Expired'; message: string }
  | { kind: 'ReplayedNonce'; message: string };

export type EntitlementError =
  | { kind: 'UnknownEntitlement'; message: string; entitlementId: string }
  | { kind: 'NotEntitled'; message: string }
  | AuthError;

// The anchorable binding hash for a uuid<->pubkey pair.
export function bindingHash(uuid: string, publicKeyHex: string): Hash {
  return doubleSha256(concat(enc.encode('identity/binding/'), enc.encode(uuid), enc.encode(':'), enc.encode(publicKeyHex)));
}

// The exact message a holder signs to answer a challenge.
export function authMessage(uuid: string, nonceHex: string, expiry: bigint): Uint8Array {
  return doubleSha256(concat(enc.encode('identity/auth/'), enc.encode(uuid), enc.encode(nonceHex), writeVarInt(expiry)));
}

export class IdentityService {
  private readonly byUuid = new Map<string, { pub: Point; pubHex: string }>();
  private readonly entitlements = new Map<string, Entitlement>();
  private readonly consumedNonces = new Set<string>(); // (uuid|nonce) single-use

  // Bind a uuid to a public key. One uuid binds once.
  register(uuid: string, publicKey: Point, _logicalTime: bigint): Result<IdentityBinding, IdentityError> {
    if (this.byUuid.has(uuid)) return err({ kind: 'DuplicateIdentity', message: `uuid ${uuid} already bound`, uuid });
    const pubHex = pointToHex(publicKey);
    this.byUuid.set(uuid, { pub: publicKey, pubHex });
    const h = bindingHash(uuid, pubHex);
    return ok({ uuid, publicKeyHex: pubHex, bindingHashDisplay: hashDisplay(h) });
  }

  binding(uuid: string): IdentityBinding | undefined {
    const e = this.byUuid.get(uuid);
    if (e === undefined) return undefined;
    return { uuid, publicKeyHex: e.pubHex, bindingHashDisplay: hashDisplay(bindingHash(uuid, e.pubHex)) };
  }

  // Issue a challenge for a uuid (caller supplies a fresh random nonce, or one is
  // generated). Expiry is a logical-time bound.
  challenge(uuid: string, expiry: bigint, nonceHex?: string): Challenge {
    const n = nonceHex ?? randomNonceHex();
    return { uuid, nonceHex: n, expiry };
  }

  // Authenticate a response: signature valid for the bound key, not expired, nonce
  // unused. On success the nonce is consumed so the same response cannot be replayed.
  authenticate(response: AuthResponse, logicalNow: bigint): Result<{ uuid: string }, AuthError> {
    const e = this.byUuid.get(response.uuid);
    if (e === undefined) return err({ kind: 'UnknownIdentity', message: `unknown uuid ${response.uuid}`, uuid: response.uuid });
    if (logicalNow > response.expiry) return err({ kind: 'Expired', message: 'response is past its expiry' });
    const nonceKey = response.uuid + '|' + response.nonceHex;
    if (this.consumedNonces.has(nonceKey)) return err({ kind: 'ReplayedNonce', message: 'nonce already used' });
    const msg = authMessage(response.uuid, response.nonceHex, response.expiry);
    if (!ecdsaVerify(e.pub, msg, response.signature)) return err({ kind: 'BadSignature', message: 'signature does not verify for the bound key' });
    this.consumedNonces.add(nonceKey);
    return ok({ uuid: response.uuid });
  }

  // Grant a non-transferable entitlement to a (registered) uuid.
  grant(entitlementId: string, uuid: string, scope: string): Result<Entitlement, IdentityError> {
    if (!this.byUuid.has(uuid)) return err({ kind: 'UnknownIdentity', message: `unknown uuid ${uuid}`, uuid });
    const ent: Entitlement = { entitlementId, uuid, scope };
    this.entitlements.set(entitlementId, ent);
    return ok(ent);
  }

  // Exercise an entitlement: requires a fresh authenticated response from the BOUND
  // uuid. A response from any other identity is NotEntitled even if it authenticates.
  exercise(entitlementId: string, response: AuthResponse, logicalNow: bigint): Result<{ scope: string }, EntitlementError> {
    const ent = this.entitlements.get(entitlementId);
    if (ent === undefined) return err({ kind: 'UnknownEntitlement', message: `unknown entitlement ${entitlementId}`, entitlementId });
    if (response.uuid !== ent.uuid) return err({ kind: 'NotEntitled', message: 'entitlement is bound to a different identity' });
    const auth = this.authenticate(response, logicalNow);
    if (!auth.ok) return err(auth.error);
    return ok({ scope: ent.scope });
  }
}

function hashDisplay(h: Hash): string {
  return HashOps.toDisplayHex(h);
}
function randomNonceHex(): string {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return toHexLower(b);
}

// Re-export for callers that store a pubkey as hex and need to decode it.
export { pointFromHex };
