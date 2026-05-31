import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProofStore, FileBackend } from '@anchorchain/proofstore';

const bytes = (n: number, seed: number) => new Uint8Array(n).map((_, i) => (i * 13 + seed) & 0xff);

test('8.2 file-backed store persists objects across instances', () => {
  const dir = mkdtempSync(join(tmpdir(), 'anchorchain-ps-'));
  const a = new ProofStore(new FileBackend(dir));
  const { key } = a.put(bytes(256, 5), 'proof');
  // a fresh store over the same directory still serves the object
  const b = new ProofStore(new FileBackend(dir));
  const got = b.get(key);
  assert.equal(got.ok, true);
  assert.deepEqual(got.ok && got.value, bytes(256, 5));
});

test('8.2 rehash-binding catches an on-disk file that was corrupted', () => {
  const dir = mkdtempSync(join(tmpdir(), 'anchorchain-ps-'));
  const store = new ProofStore(new FileBackend(dir));
  const { key } = store.put(bytes(256, 9), 'manifest');
  // corrupt the file on disk directly
  writeFileSync(join(dir, key), bytes(256, 10));
  const got = store.get(key);
  assert.equal(got.ok === false && got.error.kind, 'Tampered');
  // the key is still a single file
  assert.equal(readdirSync(dir).length, 1);
});
