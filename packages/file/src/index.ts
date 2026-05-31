// File linking + sharded selective disclosure. A file is chunked deterministically
// (a recorded rule), each chunk hashed into a Merkle leaf, and the file Merkle
// root committed (then anchored by the anchor layer). A requester can be served a
// single chunk (or a contiguous range) with its Merkle path and verify it against
// the anchored root WITHOUT receiving the rest. Retrieval is rehash-bound (CAS):
// a retrieved chunk must rehash to its committed leaf, a whole file to its root.
import type { Hash, Result, VerifyResult } from '@anchorchain/bsv';
import { ok, err, HashOps, toHexLower } from '@anchorchain/bsv';
import type { MerkleProof, MerkleVerifyReason } from '@anchorchain/merkle';
import { hashLeaf, merkleRoot, merkleProof, verifyProof } from '@anchorchain/merkle';

export type ChunkingRule = 'fixedSize';

export type FileError =
  | { kind: 'FileTooLarge'; message: string; max: number; got: number }
  | { kind: 'BadRange'; message: string }
  | { kind: 'Empty'; message: string };

export interface FileManifest {
  fileId: string;
  rootDisplay: string;
  chunkCount: number;
  chunkSizeBytes: number;
  totalBytes: number;
  rule: ChunkingRule;
  schemaFingerprintHex?: string;
}

export interface CommittedFile {
  manifest: FileManifest;
  root: Hash;
  leaves: Hash[];
  chunks: Uint8Array[];
}

export function chunkFile(bytes: Uint8Array, opts: { rule?: ChunkingRule; chunkSizeBytes: number; maxFileBytes: number; schemaFingerprintHex?: string }): Result<CommittedFile, FileError> {
  if (bytes.length > opts.maxFileBytes) return err({ kind: 'FileTooLarge', message: `file ${bytes.length} > max ${opts.maxFileBytes}`, max: opts.maxFileBytes, got: bytes.length });
  if (bytes.length === 0) return err({ kind: 'Empty', message: 'empty file' });
  if (opts.chunkSizeBytes <= 0) return err({ kind: 'BadRange', message: 'chunk size must be positive' });
  const chunks: Uint8Array[] = [];
  for (let off = 0; off < bytes.length; off += opts.chunkSizeBytes) chunks.push(Uint8Array.from(bytes.subarray(off, Math.min(off + opts.chunkSizeBytes, bytes.length))));
  const leaves = chunks.map((c) => hashLeaf(c));
  const root = merkleRoot(leaves);
  if (!root.ok) return err({ kind: 'Empty', message: 'no chunks' });
  // deterministic file id from the committed root (same file -> same id)
  const fileId = 'file-' + HashOps.toDisplayHex(root.value).slice(0, 24);
  const manifest: FileManifest = { fileId, rootDisplay: HashOps.toDisplayHex(root.value), chunkCount: chunks.length, chunkSizeBytes: opts.chunkSizeBytes, totalBytes: bytes.length, rule: opts.rule ?? 'fixedSize' };
  if (opts.schemaFingerprintHex !== undefined) manifest.schemaFingerprintHex = opts.schemaFingerprintHex;
  return ok({ manifest, root: root.value, leaves, chunks });
}

export interface DisclosedChunk {
  index: number;
  chunk: Uint8Array;
  proof: MerkleProof;
}

export function discloseChunk(file: CommittedFile, index: number): Result<DisclosedChunk, FileError> {
  if (index < 0 || index >= file.chunks.length) return err({ kind: 'BadRange', message: `chunk ${index} out of range` });
  const proof = merkleProof(file.leaves, index);
  if (!proof.ok) return err({ kind: 'BadRange', message: 'bad index' });
  return ok({ index, chunk: file.chunks[index] as Uint8Array, proof: proof.value });
}

export function discloseRange(file: CommittedFile, start: number, endExclusive: number): Result<DisclosedChunk[], FileError> {
  if (start < 0 || endExclusive > file.chunks.length || start >= endExclusive) return err({ kind: 'BadRange', message: 'bad range' });
  const out: DisclosedChunk[] = [];
  for (let i = start; i < endExclusive; i++) {
    const d = discloseChunk(file, i);
    if (!d.ok) return d;
    out.push(d.value);
  }
  return ok(out);
}

// Verify a disclosed chunk against the committed root, REHASH-BOUND: the chunk is
// rehashed to its leaf before the Merkle check, so a substituted chunk is rejected.
export function verifyChunk(disclosed: DisclosedChunk, root: Hash): VerifyResult<MerkleVerifyReason> {
  const leaf = hashLeaf(disclosed.chunk); // CAS rehash-binding
  return verifyProof(leaf, disclosed.proof, root);
}

// Rebuild a whole retrieved file and confirm it commits to the root.
export function verifyWholeFile(bytes: Uint8Array, manifest: FileManifest): Result<VerifyResult<{ kind: 'RootMismatch' }>, FileError> {
  const rebuilt = chunkFile(bytes, { rule: manifest.rule, chunkSizeBytes: manifest.chunkSizeBytes, maxFileBytes: bytes.length });
  if (!rebuilt.ok) return rebuilt;
  return ok(rebuilt.value.manifest.rootDisplay === manifest.rootDisplay ? { ok: true } : { ok: false, reason: { kind: 'RootMismatch' } });
}

// Content-addressable key for a chunk (its committed leaf), used by the CAS store.
export function chunkKey(leaf: Hash): string {
  return toHexLower(HashOps.toInternalBytes(leaf));
}
