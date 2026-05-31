import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ProofStore, InMemoryBackend, contentKey } from '@anchorchain/proofstore';

const bytes = (n: number, seed: number) => new Uint8Array(n).map((_, i) => (i * 17 + seed) & 0xff);

test('8.2 content key is deterministic and put is idempotent', () => {
  const store = new ProofStore();
  const a = bytes(120, 3);
  const r1 = store.put(a, 'proof');
  const r2 = store.put(Uint8Array.from(a), 'proof');
  assert.equal(r1.key, r2.key);
  assert.equal(r1.key, contentKey(a));
  assert.equal(store.keys().length, 1); // identical bytes -> one object
});

test('8.2 round-trip returns the exact bytes under the content key', () => {
  const store = new ProofStore();
  const m = bytes(300, 9);
  const { key } = store.put(m, 'manifest');
  const got = store.get(key);
  assert.equal(got.ok, true);
  assert.deepEqual(got.ok && got.value, m);
  assert.equal(store.has(key), true);
});

test('8.2 unknown key and malformed key are refused', () => {
  const store = new ProofStore();
  assert.equal(store.get('00'.repeat(32)).ok, false); // well-formed but absent
  const absent = store.get('00'.repeat(32));
  assert.equal(absent.ok === false && absent.error.kind, 'NotFound');
  const bad = store.get('not-a-key');
  assert.equal(bad.ok === false && bad.error.kind, 'BadKey');
});

test('8.2 rehash-binding catches a backend that substitutes bytes under a key', () => {
  const backend = new InMemoryBackend();
  const store = new ProofStore(backend);
  const { key } = store.put(bytes(200, 1), 'shard');
  // a faulty/hostile backend swaps the stored bytes for a different object
  backend.write(key, bytes(200, 2));
  const got = store.get(key);
  assert.equal(got.ok === false && got.error.kind, 'Tampered');
  // availability inherits the same integrity check
  assert.equal(store.availability(key).ok, false);
});

test('8.2 availability attests size and kind but not validity', () => {
  const store = new ProofStore();
  const obj = bytes(512, 7);
  const { key } = store.put(obj, 'entity');
  const av = store.availability(key);
  assert.equal(av.ok, true);
  if (av.ok) {
    assert.equal(av.value.sizeBytes, 512);
    assert.equal(av.value.kind, 'entity');
  }
});
