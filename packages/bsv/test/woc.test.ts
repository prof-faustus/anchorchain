import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { FetchLike, Hash } from '@anchorchain/bsv';
import { FetchTransport, WhatsOnChainClient, HashOps, TxidOps, doubleSha256, concat, fromHex, headerHash } from '@anchorchain/bsv';

// WhatsOnChain client over a stub fetch, using a genuine mainnet block and a
// genuine anchor transaction (height 970699, tx 7cee9e7a...), so paths, JSON
// shapes and the TSC branch are tested without a network.
const BASE = 'https://api.whatsonchain.com/v1/bsv/main';
const BLOCK = {
  hash: '00000000000000000d4d2e6e7e0d9a0978a2b483a43bd4169403b01c7b695c58',
  height: 970699,
  version: 973078528,
  previousblockhash: '00000000000000001d8084ed930209711466389eded63ee993c4c07bea16950f',
  merkleroot: 'bf567fa53e77848cf17b08efc1cfcf771a9df49e7cb00f62e9b1dfe04e773399',
  time: 1791777755,
  bits: '18204c76',
  nonce: 3021713998,
};
const TXID = '7cee9e7aa2f68cc19dbb51eba7815365ef1750d7274b144a2437bfb5d0cc38b2';
const RAW_TX =
  '01000000017ae2a92ede8ea1f9dea7fd5025065f918aa40a83a894bc454f64edccbc14b765020000006b4830450221009fd99a4c9cd6a151a4deae1e645710ad5ee3bb95feb98e141d80b11dfd77980202205cd190665ef25f3abee6c19712e155ef75cefae6d7ad0b8357b2943fc95c0d674121020dfa60de3eaf9c8f415f36d911262745506248dc926f2bfe5e30d6979f31fe1cffffffff02000000000000000039006a0a474f5645524e4f5276310a323032362d31302d313220786e045f363f9ddbf8433d7267cd62f2bd1b718d1578b99e42eeaffeb25687edb2030000000000001976a91497e8975bdb183c38da18a11127da42e8c1c1696388ac00000000';
const TSC = [{
  index: 3064,
  txOrId: TXID,
  target: BLOCK.hash,
  nodes: [
    '5c14a7a8740545b79cad83c6cbb82e1c0605be43336e2a709f8d2a96a66ef338',
    'a36a557d21470093ac28f00cb0e28f1362d3b7d7123dadf141440abe20a8d2e8',
    '094e9a48b7e053b05047dfd18f7a85b7609e44fbc1ed87d70ba0c48d4565147f',
    '5a3b908da5e92a5e35bf0486bb2f94107f19500c3076e13101feab84f694863c',
    'd865128acc259619a63072d14cb07e56ed6271abad6a1d7c4f6c634df503b791',
    'efe9fd7f8c729bc35c08ccf61f0e86b8e416df4e29fb48cb8bf8cc36c4acb242',
    '5ce8d65a8583fa674dddc4b31dca72edf0c0a0c2a8e90eff9d3d49f24af0ccaa',
    'b707421f2e625ee96dcbcf0ec57f83bc694f711641cf5dca6deea1fce655501b',
    '2e389bd61f1343600eb9b56ea02254dc159c66a20d44495160246e521250e101',
    '6503ac81ed7bd135832a728ef4bedcb6b5c312573040cba74cb9f40fc80415d9',
    'edf433a2bc24dcd0aadfa343ab7bc1088ae66e05450c18649d78993d749aff9a',
    'f3d79e77db0c935c9f156f060e334e1add06933358c38dafb6514580b0e05017',
  ],
}];

type Route = { status: number; body: string };
function client(routes: Record<string, Route>, seen: { url: string; body?: string }[] = []): WhatsOnChainClient {
  const fetchFn: FetchLike = async (url, init) => {
    seen.push({ url, body: init?.body });
    const r = routes[url];
    if (r === undefined) return { status: 404, ok: false, text: async () => '404 page not found' };
    return { status: r.status, ok: r.status >= 200 && r.status < 300, text: async () => r.body };
  };
  return new WhatsOnChainClient(new FetchTransport(BASE, { fetchFn }));
}
const json = (v: unknown): Route => ({ status: 200, body: JSON.stringify(v) });
const fold = (leaf: Hash, index: number, siblings: Hash[]): Hash => {
  let cur = leaf;
  let idx = index;
  for (const s of siblings) {
    cur = (idx & 1) === 0 ? doubleSha256(concat(HashOps.toInternalBytes(cur), HashOps.toInternalBytes(s))) : doubleSha256(concat(HashOps.toInternalBytes(s), HashOps.toInternalBytes(cur)));
    idx = idx >> 1;
  }
  return cur;
};
const txidOf = (hex: string) => {
  const b = fromHex(hex);
  if (!b.ok) throw new Error('bad hex');
  return TxidOps.ofTransactionBytes(b.value);
};

test('woc headerByHeight and headerByHash rebuild the genuine header', async () => {
  const c = client({ [`${BASE}/block/height/970699`]: json(BLOCK), [`${BASE}/block/${BLOCK.hash}/header`]: json(BLOCK) });
  const byHeight = await c.headerByHeight(970699);
  assert.equal(byHeight.ok, true);
  assert.equal(byHeight.ok && HashOps.toDisplayHex(headerHash(byHeight.value)), BLOCK.hash);
  const h = HashOps.fromDisplayHex(BLOCK.hash);
  assert.ok(h.ok);
  const byHash = await c.headerByHash(h.value);
  assert.equal(byHash.ok && HashOps.toDisplayHex(byHash.value.merkleRoot), BLOCK.merkleroot);
});

test('woc header JSON that does not hash to its reported hash is refused', async () => {
  const c = client({ [`${BASE}/block/height/970699`]: json({ ...BLOCK, nonce: BLOCK.nonce + 1 }) });
  const r = await c.headerByHeight(970699);
  assert.equal(r.ok, false);
  assert.equal(!r.ok && r.error.kind, 'NodeBadResponse');
  const missing = await client({}).headerByHeight(1);
  assert.equal(!missing.ok && missing.error.kind, 'NodeNotFound');
});

test('woc TSC branch folds the genuine anchor txid to the block merkle root', async () => {
  const c = client({ [`${BASE}/tx/${TXID}/proof/tsc`]: json(TSC), [`${BASE}/block/${BLOCK.hash}/header`]: json(BLOCK) });
  const t = TxidOps.fromDisplayHex(TXID);
  assert.ok(t.ok);
  const b = await c.merkleBranchForTxid(t.value);
  assert.equal(b.ok, true);
  if (!b.ok) return;
  assert.equal(b.value.blockHeight, 970699);
  assert.equal(b.value.index, 3064);
  assert.equal(HashOps.toDisplayHex(fold(TxidOps.asHash(t.value), b.value.index, b.value.branch)), BLOCK.merkleroot);
});

test('woc TSC "*" (pair with itself) is expanded into a concrete sibling', async () => {
  // A three-transaction block: the third tx is paired with itself at the bottom level.
  const ids = ['01', '02', '03'].map((x) => {
    const h = HashOps.fromDisplayHex(x.repeat(32));
    if (!h.ok) throw new Error('bad');
    return h.value;
  });
  const node = (l: Hash, r: Hash) => doubleSha256(concat(HashOps.toInternalBytes(l), HashOps.toInternalBytes(r)));
  const root = node(node(ids[0], ids[1]), node(ids[2], ids[2]));
  const header = { version: 1, prevBlockHash: HashOps.zero(), merkleRoot: root, time: 1700000000, bits: 0x207fffff, nonce: 0 };
  const hash = HashOps.toDisplayHex(headerHash(header));
  const blockJson = { hash, height: 5, version: 1, merkleroot: HashOps.toDisplayHex(root), time: 1700000000, bits: '207fffff', nonce: 0 };
  const txid = '03'.repeat(32);
  const c = client({
    [`${BASE}/tx/${txid}/proof/tsc`]: json([{ index: 2, txOrId: txid, target: hash, nodes: ['*', HashOps.toDisplayHex(node(ids[0], ids[1]))] }]),
    [`${BASE}/block/${hash}/header`]: json(blockJson),
  });
  const t = TxidOps.fromDisplayHex(txid);
  assert.ok(t.ok);
  const b = await c.merkleBranchForTxid(t.value);
  assert.equal(b.ok, true);
  if (!b.ok) return;
  assert.equal(HashOps.toDisplayHex(b.value.branch[0]), txid);
  assert.equal(HashOps.toDisplayHex(fold(TxidOps.asHash(t.value), 2, b.value.branch)), HashOps.toDisplayHex(root));
});

test('woc submit posts {"txhex"} to /tx/raw and requires the txid of the sent tx', async () => {
  const seen: { url: string; body?: string }[] = [];
  const raw = fromHex(RAW_TX);
  assert.ok(raw.ok);
  assert.equal(TxidOps.toDisplayHex(txidOf(RAW_TX)), TXID);
  const good = await client({ [`${BASE}/tx/raw`]: { status: 200, body: `"${TXID}"` } }, seen).submit(raw.value);
  assert.equal(good.ok && TxidOps.toDisplayHex(good.value), TXID);
  assert.equal(seen[0]?.url, `${BASE}/tx/raw`);
  assert.deepEqual(JSON.parse(seen[0]?.body ?? '{}'), { txhex: RAW_TX });
  const other = await client({ [`${BASE}/tx/raw`]: { status: 200, body: `"${'ab'.repeat(32)}"` } }).submit(raw.value);
  assert.equal(!other.ok && other.error.kind, 'NodeBadResponse');
  const rejected = await client({ [`${BASE}/tx/raw`]: { status: 400, body: '"TX decode failed"' } }).submit(raw.value);
  assert.equal(rejected.ok, false);
});

// Network-gated live check against the real API: reads only, broadcasts nothing.
test('woc live header and branch (gated on ANCHORCHAIN_WOC_URL)', { skip: process.env.ANCHORCHAIN_WOC_URL === undefined ? 'set ANCHORCHAIN_WOC_URL=https://api.whatsonchain.com/v1/bsv/main to run' : false }, async () => {
  const c = new WhatsOnChainClient(new FetchTransport(process.env.ANCHORCHAIN_WOC_URL as string));
  const h = await c.headerByHeight(970699);
  assert.equal(h.ok && HashOps.toDisplayHex(headerHash(h.value)), BLOCK.hash);
  const t = TxidOps.fromDisplayHex(TXID);
  assert.ok(t.ok);
  const b = await c.merkleBranchForTxid(t.value);
  assert.equal(b.ok && HashOps.toDisplayHex(fold(TxidOps.asHash(t.value), b.value.index, b.value.branch)), BLOCK.merkleroot);
});
