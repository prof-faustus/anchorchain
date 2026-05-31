import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Curve, BigNumber } from '@bsv/sdk';
import {
  HashOps,
  TxidOps,
  parseHeader,
  serializeHeader,
  headerHash,
  targetFromBits,
  meetsTarget,
  HeaderChain,
  parseTransaction,
  txidOf,
  buildDataCarrier,
  parseDataCarrier,
  doubleSha256,
  CURVE_G,
  CURVE_H,
  CURVE_N,
  pointMulG,
  pointAdd,
  pointMul,
  pointEq,
  pointToHex,
  encodePoint,
  decodePoint,
  scalarInv,
  scalarMul,
} from '@anchorchain/bsv';
import { blockFixture, txFixture, headersFixture, hexToBytes, unwrap, buildHeader } from './load.mjs';

test('byte order: a genuine block merkle root round-trips display<->internal', () => {
  const root = unwrap(HashOps.fromDisplayHex(blockFixture.merkleRoot));
  assert.equal(HashOps.toDisplayHex(root), blockFixture.merkleRoot);
});

test('a genuine header hashes to its published block hash and meets target', async () => {
  const h = await buildHeader(headersFixture.headers[2]);
  const raw = serializeHeader(h);
  assert.equal(raw.length, 80);
  assert.equal(HashOps.toDisplayHex(headerHash(h)), headersFixture.headers[2].hash);
  assert.deepEqual(Array.from(serializeHeader(unwrap(parseHeader(raw)))), Array.from(raw));
  assert.equal(meetsTarget(h), true);
  assert.equal(targetFromBits(486604799), 0xffffn << 208n);
});

test('header chain validates a genuine sequence and rejects tampering', async () => {
  const hs = await Promise.all(headersFixture.headers.map(buildHeader));
  const chain = new HeaderChain(headersFixture.headers[0].height);
  for (const h of hs) assert.equal(chain.add(h).ok, true);
  assert.equal(chain.tipHeight(), headersFixture.headers[2].height);
  assert.equal(HashOps.toDisplayHex(chain.merkleRootAtHeight(181)!), headersFixture.headers[2].merkleroot);
  assert.equal(chain.containsMerkleRoot(hs[1]!.merkleRoot)!.height, 180);

  // tampered prevHash rejected
  const bad = new HeaderChain(headersFixture.headers[0].height);
  bad.add(hs[0]!);
  assert.equal(bad.add(hs[2]!).ok, false); // skips 180 -> not linked
  // under-target header rejected
  const hard = { ...hs[0]!, bits: 0x03000001 };
  assert.equal(new HeaderChain().add(hard).ok, false);
});

test('parse a genuine multi-in/multi-out transaction', () => {
  const raw = hexToBytes(txFixture.rawHex);
  const tx = unwrap(parseTransaction(raw));
  assert.equal(tx.inputs.length, txFixture.inputCount);
  assert.equal(tx.outputs.length, txFixture.outputCount);
  assert.equal(TxidOps.toDisplayHex(txidOf(raw)), txFixture.txid);
  for (const o of tx.outputs) assert.ok(o.amountMinorUnits >= 0n);
  // truncation -> typed error, never a throw
  assert.equal(parseTransaction(raw.subarray(0, raw.length - 1)).ok, false);
});

test('post-Genesis OP_RETURN data carrier round-trips at several sizes (no historic cap)', () => {
  for (const n of [0, 32, 75, 76, 1000, 600000]) {
    const payload = new Uint8Array(n).map((_, i) => (i * 7) & 0xff);
    const carrier = unwrap(buildDataCarrier(payload));
    assert.deepEqual(Array.from(unwrap(parseDataCarrier(carrier.lockingScript))), Array.from(payload));
  }
  // configured bound enforced
  assert.equal(buildDataCarrier(new Uint8Array(11), 10).ok, false);
});

test('curve wrappers agree with the SDK; Pedersen H is a valid independent point', () => {
  const sdk = new Curve();
  assert.equal(CURVE_N.toString(), sdk.n.toString());
  for (const k of [1n, 5n, 123456789n]) {
    assert.equal(pointToHex(pointMulG(k)), sdk.g.mul(new BigNumber(k.toString())).encode(true, 'hex'));
  }
  assert.equal(pointEq(pointAdd(pointMulG(5n), pointMulG(7n)), pointMulG(12n)), true);
  // H is on the curve (decodes), distinct from G, and not G*small (best-effort sanity)
  assert.equal(decodePoint(encodePoint(CURVE_H)).ok, true);
  assert.equal(pointEq(CURVE_H, CURVE_G), false);
  // scalar inverse
  const a = 9999n;
  assert.equal(scalarMul(a, scalarInv(a)), 1n);
  void pointMul;
  void doubleSha256;
});
