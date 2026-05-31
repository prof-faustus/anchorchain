import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HashOps } from '@anchorchain/bsv';
import { chunkFile, discloseChunk, discloseRange, verifyChunk, verifyWholeFile } from '@anchorchain/file';

const bytes = (n: number) => new Uint8Array(n).map((_, i) => (i * 31 + 7) & 0xff);
const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};

test('6.5 deterministic chunking: same file -> same chunks, root, and file id', () => {
  const a = unwrap(chunkFile(bytes(5000), { chunkSizeBytes: 1024, maxFileBytes: 1 << 20 }));
  const b = unwrap(chunkFile(bytes(5000), { chunkSizeBytes: 1024, maxFileBytes: 1 << 20 }));
  assert.equal(a.manifest.rootDisplay, b.manifest.rootDisplay);
  assert.equal(a.manifest.fileId, b.manifest.fileId);
  assert.equal(a.manifest.chunkCount, 5); // ceil(5000/1024)
});

test('6.5 single-chunk and range disclosure verify against the root; no other chunk is revealed', () => {
  const f = unwrap(chunkFile(bytes(5000), { chunkSizeBytes: 1024, maxFileBytes: 1 << 20 }));
  const d = unwrap(discloseChunk(f, 2));
  assert.equal(verifyChunk(d, f.root).ok, true);
  // the disclosure carries only sibling hashes, not any other chunk's bytes
  const proofBytes = new Uint8Array(d.proof.siblings.flatMap((h) => Array.from(HashOps.toInternalBytes(h))));
  for (let i = 0; i < f.chunks.length; i++) {
    if (i === 2) continue;
    assert.equal(contains(proofBytes, f.chunks[i]!), false);
  }
  const range = unwrap(discloseRange(f, 1, 3));
  for (const c of range) assert.equal(verifyChunk(c, f.root).ok, true);
});

test('6.5 rehash-binding rejects a substituted chunk and a substituted file', () => {
  const f = unwrap(chunkFile(bytes(5000), { chunkSizeBytes: 1024, maxFileBytes: 1 << 20 }));
  const d = unwrap(discloseChunk(f, 2));
  const swapped = { ...d, chunk: Uint8Array.from(d.chunk).map((b) => b ^ 0xff) };
  assert.equal(verifyChunk(swapped, f.root).ok, false); // rehashes to a different leaf
  // whole-file: a substituted file does not rebuild to the root
  const tampered = bytes(5000);
  tampered[100] ^= 0xff;
  const r = unwrap(verifyWholeFile(tampered, f.manifest));
  assert.equal(r.ok, false);
  // genuine whole file rebuilds
  assert.equal(unwrap(verifyWholeFile(bytes(5000), f.manifest)).ok, true);
});

test('6.5 the large-file bound is enforced', () => {
  assert.equal(chunkFile(bytes(2000), { chunkSizeBytes: 256, maxFileBytes: 1000 }).ok, false);
});

function contains(hay: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true;
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}
