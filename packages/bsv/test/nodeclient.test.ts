import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OfflineNodeClient, TeranodeClient, HashOps, TxidOps, serializeHeader, headerHash } from '@anchorchain/bsv';
import { headersFixture, txFixture, hexToBytes, unwrap, buildHeader } from './load.mjs';

async function offline() {
  const hs = await Promise.all(headersFixture.headers.map(buildHeader));
  const headersByHeight = new Map();
  const headerByHash = new Map();
  hs.forEach((h, i) => {
    headersByHeight.set(headersFixture.headers[i].height, h);
    headerByHash.set(HashOps.toDisplayHex(headerHash(h)), h);
  });
  return new OfflineNodeClient({ headersByHeight, headerByHash, branches: new Map(), submitted: new Set() });
}

test('OfflineNodeClient serves fixtures and reports NodeNotFound', async () => {
  const c = await offline();
  const h = unwrap(await c.headerByHeight(181));
  assert.equal(HashOps.toDisplayHex(h.merkleRoot), headersFixture.headers[2].merkleroot);
  const miss = await c.headerByHeight(999999);
  assert.equal(miss.ok, false);
  // submit returns the txid of the raw bytes
  const raw = hexToBytes(txFixture.rawHex);
  assert.equal(TxidOps.toDisplayHex(unwrap(await c.submit(raw))), txFixture.txid);
});

test('TeranodeClient maps transport failures to typed errors and decodes headers', async () => {
  const transportOf = (scripted) => ({ request: async () => scripted });
  const h0 = await buildHeader(headersFixture.headers[0]);
  let hex = '';
  for (const b of serializeHeader(h0)) hex += b.toString(16).padStart(2, '0');

  const unreachable = new TeranodeClient({ request: async () => { throw new Error('down'); } });
  assert.equal((await unreachable.headerByHeight(1)).ok, false);
  const nf = new TeranodeClient(transportOf({ kind: 'notFound' }));
  const r = await nf.headerByHeight(1);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error.kind, 'NodeNotFound');
  const bad = new TeranodeClient(transportOf({ kind: 'ok', body: 'zz' }));
  assert.equal((await bad.headerByHeight(1)).ok, false);
  const okc = new TeranodeClient(transportOf({ kind: 'ok', body: hex }));
  const got = unwrap(await okc.headerByHeight(1));
  assert.equal(HashOps.toDisplayHex(got.merkleRoot), headersFixture.headers[0].merkleroot);
});
