import { readFileSync } from 'node:fs';
import { join } from 'node:path';
const dir = join(import.meta.dirname, 'fixtures');
export const readJson = (n) => JSON.parse(readFileSync(join(dir, n), 'utf8'));
export const blockFixture = readJson('block.json');
export const txFixture = readJson('transaction.json');
export const headersFixture = readJson('headers.json');
export const hexToBytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
export function unwrap(r) {
  if (!r.ok) throw new Error('expected ok: ' + JSON.stringify(r.error));
  return r.value;
}
export async function buildHeader(rec) {
  const { HashOps } = await import('@anchorchain/bsv');
  return {
    version: rec.version,
    prevBlockHash: unwrap(HashOps.fromDisplayHex(rec.previousblockhash)),
    merkleRoot: unwrap(HashOps.fromDisplayHex(rec.merkleroot)),
    time: rec.time,
    bits: rec.bits,
    nonce: rec.nonce,
  };
}
