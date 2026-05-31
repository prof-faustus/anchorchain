// One-time tooling: fetch GENUINE Bitcoin (BSV) data from a public explorer and
// write it as committed fixtures. Reproduction never re-fetches.
//   NODE_OPTIONS=--use-system-ca node scripts/fetch-fixtures.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Transaction } from '@bsv/sdk';

const BASE = 'https://api.whatsonchain.com/v1/bsv/main';
const root = resolve(import.meta.dirname, '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJson(url) {
  for (let a = 0; a < 5; a++) {
    const res = await fetch(url);
    if (res.status === 200) return res.json();
    if (res.status === 404) return null;
    await sleep(800 * (a + 1));
  }
  throw new Error('giving up on ' + url);
}
async function getText(url) {
  for (let a = 0; a < 5; a++) {
    const res = await fetch(url);
    if (res.status === 200) return (await res.text()).trim();
    if (res.status === 404) return null;
    await sleep(800 * (a + 1));
  }
  throw new Error('giving up on ' + url);
}
const bitsToInt = (b) => (typeof b === 'number' ? b >>> 0 : parseInt(b, 16) >>> 0);
async function blockByHeight(h) {
  await sleep(350);
  return getJson(`${BASE}/block/height/${h}`);
}

async function findSmallBlock() {
  for (let h = 175; h <= 5000; h++) {
    const b = await blockByHeight(h);
    if (!b) continue;
    const numTx = b.num_tx ?? (Array.isArray(b.tx) ? b.tx.length : 0);
    if (Array.isArray(b.tx) && b.tx.length === numTx && numTx >= 2 && numTx <= 8) return b;
  }
  return null;
}

async function main() {
  const block = await findSmallBlock();
  if (!block) throw new Error('no small multi-tx block found');
  const h = block.height;
  console.log(`block ${h}, ${block.tx.length} txs, hash ${block.hash}`);

  const consec = [];
  for (const hh of [h - 2, h - 1, h]) {
    const b = hh === h ? block : await blockByHeight(hh);
    consec.push({ height: b.height, version: b.version, previousblockhash: b.previousblockhash, merkleroot: b.merkleroot, time: b.time, bits: bitsToInt(b.bits), nonce: b.nonce, hash: b.hash });
  }

  const tip = await getJson(`${BASE}/chain/info`);
  let multiTx = null;
  for (let back = 6; back < 40 && !multiTx; back++) {
    const b = await blockByHeight(tip.blocks - back);
    if (!b || !Array.isArray(b.tx)) continue;
    for (const txid of b.tx.slice(0, 20)) {
      const hex = await getText(`${BASE}/tx/${txid}/hex`);
      await sleep(250);
      if (!hex) continue;
      const tx = Transaction.fromHex(hex);
      if (tx.inputs.length >= 2 && tx.outputs.length >= 2) {
        multiTx = { txid, hex, blockHeight: b.height };
        break;
      }
    }
  }
  if (!multiTx) throw new Error('no multi-in/out tx found');
  const tx = Transaction.fromHex(multiTx.hex);

  const blockVector = {
    source: `Bitcoin (BSV) mainnet block at height ${h}, retrieved from a public BSV explorer`,
    height: h,
    blockHash: block.hash,
    version: block.version,
    previousBlockHash: block.previousblockhash,
    merkleRoot: block.merkleroot,
    time: block.time,
    bits: bitsToInt(block.bits),
    nonce: block.nonce,
    txids: block.tx,
  };
  const txFixture = {
    source: `Bitcoin (BSV) mainnet transaction ${multiTx.txid}, block height ${multiTx.blockHeight}, from a public BSV explorer`,
    txid: multiTx.txid,
    rawHex: multiTx.hex,
    inputCount: tx.inputs.length,
    outputCount: tx.outputs.length,
    outputs: tx.outputs.map((o, i) => ({ position: i, amountMinorUnits: String(o.satoshis ?? 0), lockingScriptLength: o.lockingScript.toBinary().length })),
  };
  const headersFixture = { source: `Bitcoin (BSV) consecutive headers ${h - 2}..${h}, from a public BSV explorer`, headers: consec };

  mkdirSync(join(root, 'packages', 'bsv', 'test', 'fixtures'), { recursive: true });
  mkdirSync(join(root, 'vectors', 'merkle'), { recursive: true });
  const write = (p, o) => writeFileSync(p, JSON.stringify(o, null, 2) + '\n');
  write(join(root, 'packages', 'bsv', 'test', 'fixtures', 'block.json'), blockVector);
  write(join(root, 'packages', 'bsv', 'test', 'fixtures', 'transaction.json'), txFixture);
  write(join(root, 'packages', 'bsv', 'test', 'fixtures', 'headers.json'), headersFixture);
  write(join(root, 'vectors', 'merkle', 'bsv_block_v1.json'), blockVector);
  console.log('fixtures written.');
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
