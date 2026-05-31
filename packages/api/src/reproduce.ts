// Deterministic reproduction. computeVectors() regenerates every deterministic
// artifact the project commits — schema fingerprint, a fixed memory leaf, a fixed
// Merkle root, the anchor data-carrier blob, and the studies — from first
// principles. reproduceAndCheck() compares them, field by field, to the committed
// vector at vectors/anchorchain/repro_v1.json and fails on ANY divergence, so a
// change in serialisation, hashing, or proof structure cannot pass unnoticed.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { HashOps, toHexLower } from '@anchorchain/bsv';
import { memoryLeaf } from '@anchorchain/hashing';
import { schemaFingerprintHex } from '@anchorchain/schema';
import { encodeAnchorBlob } from '@anchorchain/anchor';
import { hashLeaf, merkleRoot } from './internal-merkle.js';
import { runStudies } from './studies.js';
import type { Studies } from './studies.js';

export interface ReproVectors {
  schemaFingerprintHex: string;
  memoryLeafDisplayHex: string;
  merkleRootDisplayHex: string;
  anchorBlobHex: string;
  studies: Studies;
}

const FIXED_SCHEMA = { name: 'memory-v1', fields: [{ fieldId: 'embedding', type: 'vector' as const, dim: 8 }, { fieldId: 'label', type: 'string' as const }], timestampMode: 'logicalStep' as const };
const FIXED_VECTOR = [0.5, -0.25, 1, 0, 2, -1, 0.125, 3];
const FIXED_CONTEXT = { agentId: 'agent-fixed', sourceDocHash: HashOps.toInternalBytes(HashOps.zero()), promptChainRef: 'chain-0', memoryLayerRef: 'layer-0' };

export function computeVectors(): ReproVectors {
  const leaf = memoryLeaf(FIXED_CONTEXT, FIXED_VECTOR, 42n);
  const leaves = Array.from({ length: 8 }, (_, i) => hashLeaf(Uint8Array.of(0xab, i)));
  const root = merkleRoot(leaves);
  const blob = encodeAnchorBlob(root, leaves.length, 'batch-fixed');
  return {
    schemaFingerprintHex: schemaFingerprintHex(FIXED_SCHEMA),
    memoryLeafDisplayHex: HashOps.toDisplayHex(leaf),
    merkleRootDisplayHex: HashOps.toDisplayHex(root),
    anchorBlobHex: toHexLower(blob),
    studies: runStudies(),
  };
}

export interface ReproResult {
  ok: boolean;
  generated: ReproVectors;
  mismatches: string[];
  committedFound: boolean;
}

export function vectorPath(repoRoot: string): string {
  return join(repoRoot, 'vectors', 'anchorchain', 'repro_v1.json');
}

export function reproduceAndCheck(repoRoot: string): ReproResult {
  const generated = computeVectors();
  const path = vectorPath(repoRoot);
  if (!existsSync(path)) return { ok: false, generated, mismatches: ['committed vector missing: ' + path], committedFound: false };
  const committed = JSON.parse(readFileSync(path, 'utf8')) as ReproVectors;
  const mismatches = diff('', generated as unknown as Json, committed as unknown as Json);
  return { ok: mismatches.length === 0, generated, mismatches, committedFound: true };
}

type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

// A structural diff that reports the path of every divergence (deterministic order).
function diff(path: string, a: Json, b: Json): string[] {
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') {
    return a === b ? [] : [`${path || '<root>'}: generated=${JSON.stringify(a)} committed=${JSON.stringify(b)}`];
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return [`${path}: array/object mismatch`];
    if (a.length !== b.length) return [`${path}: length generated=${a.length} committed=${b.length}`];
    return a.flatMap((x, i) => diff(`${path}[${i}]`, x, b[i] as Json));
  }
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  return keys.flatMap((k) => diff(path ? `${path}.${k}` : k, (a as Record<string, Json>)[k] ?? null, (b as Record<string, Json>)[k] ?? null));
}
