// A durable, AVAILABILITY-ONLY store for the artifacts a holder needs to present a
// proof entity: serialized Merkle paths, proof shards, file manifests, and the
// proof entities themselves. The store provides AVAILABILITY, not trust: it never
// vouches for the validity of what it holds (validity is decided header-only by the
// proofentity layer). Its one integrity guarantee is content-addressing with
// REHASH-BINDING — every object is keyed by the double-SHA-256 of its bytes, and
// every read rehashes the returned bytes against the requested key. A backing store
// that loses, corrupts, or substitutes bytes is caught at read time and cannot pass
// off wrong content under a key. No object content is ever logged.
import type { Result } from '@anchorchain/bsv';
import { ok, err, doubleSha256, HashOps, toHexLower } from '@anchorchain/bsv';

export type StoreError =
  | { kind: 'NotFound'; message: string; key: string }
  | { kind: 'Tampered'; message: string; key: string }
  | { kind: 'BadKey'; message: string; key: string };

export type ObjectKind = 'proof' | 'shard' | 'manifest' | 'entity';

export interface AvailabilityReceipt {
  key: string;
  kind: ObjectKind;
  sizeBytes: number;
}

// The content-addressing key: lower-hex double-SHA-256 of the bytes.
export function contentKey(bytes: Uint8Array): string {
  return toHexLower(HashOps.toInternalBytes(doubleSha256(bytes)));
}

// The pluggable durable backend. A real deployment supplies a disk/object-store
// implementation; the store wraps any backend with rehash-binding so the backend
// itself need not be trusted for integrity.
export interface StoreBackend {
  write(key: string, bytes: Uint8Array): void;
  read(key: string): Uint8Array | undefined;
  has(key: string): boolean;
  keys(): string[];
}

export class InMemoryBackend implements StoreBackend {
  private readonly map = new Map<string, Uint8Array>();
  write(key: string, bytes: Uint8Array): void {
    this.map.set(key, Uint8Array.from(bytes));
  }
  read(key: string): Uint8Array | undefined {
    const v = this.map.get(key);
    return v === undefined ? undefined : Uint8Array.from(v);
  }
  has(key: string): boolean {
    return this.map.has(key);
  }
  keys(): string[] {
    return [...this.map.keys()];
  }
}

export class ProofStore {
  private readonly backend: StoreBackend;
  private readonly kinds = new Map<string, ObjectKind>();

  constructor(backend?: StoreBackend) {
    this.backend = backend ?? new InMemoryBackend();
  }

  // Store bytes under their content key. Idempotent: identical bytes map to the
  // same key, so re-putting is a no-op that returns the same receipt.
  put(bytes: Uint8Array, kind: ObjectKind): AvailabilityReceipt {
    const key = contentKey(bytes);
    if (!this.backend.has(key)) this.backend.write(key, bytes);
    this.kinds.set(key, kind);
    return { key, kind, sizeBytes: bytes.length };
  }

  // Retrieve bytes, REHASH-BOUND: the bytes the backend returns must hash back to
  // the requested key, or the read is refused as tampered. This is the store's
  // sole integrity guarantee.
  get(key: string): Result<Uint8Array, StoreError> {
    if (key.length !== 64) return err({ kind: 'BadKey', message: 'key must be 32-byte hex', key });
    const bytes = this.backend.read(key);
    if (bytes === undefined) return err({ kind: 'NotFound', message: 'no object at key', key });
    if (contentKey(bytes) !== key) return err({ kind: 'Tampered', message: 'backend returned bytes that do not rehash to the key', key });
    return ok(bytes);
  }

  has(key: string): boolean {
    return this.backend.has(key);
  }

  // An availability attestation: what the store holds at a key and how large it is.
  // This asserts AVAILABILITY only — it makes no claim about the object's validity.
  availability(key: string): Result<AvailabilityReceipt, StoreError> {
    const got = this.get(key);
    if (!got.ok) return got;
    return ok({ key, kind: this.kinds.get(key) ?? 'proof', sizeBytes: got.value.length });
  }

  keys(): string[] {
    return this.backend.keys();
  }
}
