// Memory-leaf hashing. A memory atom's leaf is H(context ‖ vector ‖ timestamp),
// H = double SHA-256. The context binds the atom to its provenance (agent id,
// source-document hash, prompt-chain reference, memory-layer reference). Vector
// encoding (raw vs quantised) is explicit and recorded; an optional
// provenance-compression mode commits a transformed embedding with the
// transformation-matrix UUID and schema fingerprint.
import type { Hash } from '@anchorchain/bsv';
import { doubleSha256, concat, writeVarInt } from '@anchorchain/bsv';

const enc = new TextEncoder();

export interface MemoryContext {
  agentId: string;
  sourceDocHash: Uint8Array; // 32 bytes
  promptChainRef: string;
  memoryLayerRef: string;
}

export type VectorEncoding = 'raw' | 'quantised';

export interface ProvenanceCompression {
  transformMatrixUuid: string;
  schemaFingerprintHex: string;
}

export interface LeafOptions {
  encoding?: VectorEncoding;
  compression?: ProvenanceCompression;
}

function vstr(s: string): Uint8Array {
  const b = enc.encode(s);
  return concat(writeVarInt(BigInt(b.length)), b);
}
function vbytes(b: Uint8Array): Uint8Array {
  return concat(writeVarInt(BigInt(b.length)), b);
}

export function serializeContext(c: MemoryContext): Uint8Array {
  return concat(vstr(c.agentId), vbytes(c.sourceDocHash), vstr(c.promptChainRef), vstr(c.memoryLayerRef));
}

export function encodeVector(vector: number[], encoding: VectorEncoding): Uint8Array {
  const parts: Uint8Array[] = [writeVarInt(BigInt(vector.length)), Uint8Array.of(encoding === 'raw' ? 0 : 1)];
  if (encoding === 'raw') {
    const buf = new Uint8Array(vector.length * 8);
    const dv = new DataView(buf.buffer);
    for (let i = 0; i < vector.length; i++) dv.setFloat64(i * 8, vector[i] as number, false);
    parts.push(buf);
  } else {
    const q = new Uint8Array(vector.length);
    for (let i = 0; i < vector.length; i++) q[i] = Math.max(0, Math.min(255, Math.round(vector[i] as number))) & 0xff;
    parts.push(q);
  }
  return concat(...parts);
}

function encodeCompression(c: ProvenanceCompression | undefined): Uint8Array {
  if (c === undefined) return Uint8Array.of(0);
  return concat(Uint8Array.of(1), vstr(c.transformMatrixUuid), vstr(c.schemaFingerprintHex));
}

export function memoryLeaf(context: MemoryContext, vector: number[], timestamp: bigint, opts: LeafOptions = {}): Hash {
  const encoding: VectorEncoding = opts.encoding ?? 'raw';
  return doubleSha256(concat(serializeContext(context), encodeVector(vector, encoding), writeVarInt(timestamp), encodeCompression(opts.compression)));
}
