// Transaction parse (length-exact, typed errors — the SDK parser is lenient) and
// a deterministic serialiser used to build data-carrier (anchor) transactions.
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { txMalformed, txTruncated } from './errors.js';
import { readU32LE, writeU32LE, readVarInt, writeVarInt, concat } from './bytes.js';
import type { Txid } from './txid.js';
import { fromInternalBytes as txidFromInternal, toInternalBytes as txidToInternal, ofTransactionBytes } from './txid.js';
import type { Script } from './script.js';
import { fromBytes as scriptFromBytes, toBytes as scriptToBytes } from './script.js';

export interface TxInput {
  prevTxid: Txid;
  prevIndex: number;
  unlockingScript: Script;
  sequence: number;
}
export interface TxOutput {
  amountMinorUnits: bigint;
  lockingScript: Script;
}
export interface Transaction {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
  raw: Uint8Array;
}

function readU64LE(buf: Uint8Array, offset: number): Result<bigint, BsvError> {
  if (offset + 8 > buf.length) return err(txTruncated(offset + 8, buf.length));
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[offset + i] as number);
  return ok(v);
}

export function parseTransaction(raw: Uint8Array): Result<Transaction, BsvError> {
  let offset = 0;
  const version = readU32LE(raw, offset);
  if (!version.ok) return err(txTruncated(4, raw.length));
  offset += 4;
  const inCount = readVarInt(raw, offset);
  if (!inCount.ok) return err(txTruncated(offset + 1, raw.length));
  offset = inCount.value.nextOffset;
  if (inCount.value.value > BigInt(raw.length)) return err(txMalformed(`input count ${inCount.value.value}`));
  const inputs: TxInput[] = [];
  for (let i = 0; i < Number(inCount.value.value); i++) {
    if (offset + 32 > raw.length) return err(txTruncated(offset + 32, raw.length));
    const prev = txidFromInternal(raw.subarray(offset, offset + 32));
    if (!prev.ok) return err(prev.error);
    offset += 32;
    const idx = readU32LE(raw, offset);
    if (!idx.ok) return err(txTruncated(offset + 4, raw.length));
    offset += 4;
    const sLen = readVarInt(raw, offset);
    if (!sLen.ok) return err(txTruncated(offset + 1, raw.length));
    offset = sLen.value.nextOffset;
    const scriptLen = Number(sLen.value.value);
    if (sLen.value.value > BigInt(raw.length)) return err(txMalformed(`input ${i} script length`));
    if (offset + scriptLen > raw.length) return err(txTruncated(offset + scriptLen, raw.length));
    const unlockingScript = scriptFromBytes(raw.subarray(offset, offset + scriptLen));
    offset += scriptLen;
    const seq = readU32LE(raw, offset);
    if (!seq.ok) return err(txTruncated(offset + 4, raw.length));
    offset += 4;
    inputs.push({ prevTxid: prev.value, prevIndex: idx.value, unlockingScript, sequence: seq.value });
  }
  const outCount = readVarInt(raw, offset);
  if (!outCount.ok) return err(txTruncated(offset + 1, raw.length));
  offset = outCount.value.nextOffset;
  if (outCount.value.value > BigInt(raw.length)) return err(txMalformed(`output count ${outCount.value.value}`));
  const outputs: TxOutput[] = [];
  for (let i = 0; i < Number(outCount.value.value); i++) {
    const amount = readU64LE(raw, offset);
    if (!amount.ok) return err(amount.error);
    offset += 8;
    const sLen = readVarInt(raw, offset);
    if (!sLen.ok) return err(txTruncated(offset + 1, raw.length));
    offset = sLen.value.nextOffset;
    const scriptLen = Number(sLen.value.value);
    if (sLen.value.value > BigInt(raw.length)) return err(txMalformed(`output ${i} script length`));
    if (offset + scriptLen > raw.length) return err(txTruncated(offset + scriptLen, raw.length));
    outputs.push({ amountMinorUnits: amount.value, lockingScript: scriptFromBytes(raw.subarray(offset, offset + scriptLen)) });
    offset += scriptLen;
  }
  const locktime = readU32LE(raw, offset);
  if (!locktime.ok) return err(txTruncated(offset + 4, raw.length));
  offset += 4;
  return ok({ version: version.value, inputs, outputs, locktime: locktime.value, raw: Uint8Array.from(raw) });
}

export function serializeTransaction(version: number, inputs: TxInput[], outputs: TxOutput[], locktime: number): Uint8Array {
  const parts: Uint8Array[] = [];
  const v = new Uint8Array(4);
  writeU32LE(version, v, 0);
  parts.push(v);
  parts.push(writeVarInt(BigInt(inputs.length)));
  for (const inp of inputs) {
    parts.push(txidToInternal(inp.prevTxid));
    const idx = new Uint8Array(4);
    writeU32LE(inp.prevIndex, idx, 0);
    parts.push(idx);
    const sb = scriptToBytes(inp.unlockingScript);
    parts.push(writeVarInt(BigInt(sb.length)), sb);
    const seq = new Uint8Array(4);
    writeU32LE(inp.sequence, seq, 0);
    parts.push(seq);
  }
  parts.push(writeVarInt(BigInt(outputs.length)));
  for (const o of outputs) {
    const val = new Uint8Array(8);
    let amt = o.amountMinorUnits & 0xffffffffffffffffn;
    for (let i = 0; i < 8; i++) {
      val[i] = Number(amt & 0xffn);
      amt >>= 8n;
    }
    parts.push(val);
    const sb = scriptToBytes(o.lockingScript);
    parts.push(writeVarInt(BigInt(sb.length)), sb);
  }
  const lt = new Uint8Array(4);
  writeU32LE(locktime, lt, 0);
  parts.push(lt);
  return concat(...parts);
}

export function txidOf(raw: Uint8Array): Txid {
  return ofTransactionBytes(raw);
}
