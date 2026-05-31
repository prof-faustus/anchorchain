import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { FetchLike } from '@anchorchain/bsv';
import { FetchTransport, TeranodeClient, serializeHeader, HashOps } from '@anchorchain/bsv';

// A stub fetch over a fixed routing table, so the production transport's status
// mapping and the Teranode client's header path are tested without a network.
function stub(routes: Record<string, { status: number; body: string }>): FetchLike {
  return async (url) => {
    const r = routes[url];
    if (r === undefined) return { status: 404, ok: false, text: async () => '' };
    return { status: r.status, ok: r.status >= 200 && r.status < 300, text: async () => r.body };
  };
}

test('node.http FetchTransport maps 2xx/404/5xx/throw correctly', async () => {
  const t = new FetchTransport('https://node.example/', { fetchFn: stub({ 'https://node.example/ok': { status: 200, body: 'hello' }, 'https://node.example/boom': { status: 500, body: 'err' } }) });
  assert.deepEqual(await t.request('/ok'), { kind: 'ok', body: 'hello' });
  assert.deepEqual(await t.request('/missing'), { kind: 'notFound' });
  assert.equal((await t.request('/boom')).kind, 'unreachable');
  const throwT = new FetchTransport('https://node.example', { fetchFn: async () => { throw new Error('dns'); } });
  const r = await throwT.request('/x');
  assert.equal(r.kind === 'unreachable' && r.detail, 'dns');
});

test('node.http TeranodeClient parses a header over the stub transport', async () => {
  const header = { version: 1, prevBlockHash: HashOps.zero(), merkleRoot: HashOps.zero(), time: 1700000000, bits: 0x207fffff, nonce: 7 };
  let hex = '';
  for (const b of serializeHeader(header)) hex += b.toString(16).padStart(2, '0');
  const transport = new FetchTransport('https://node.example', { fetchFn: stub({ 'https://node.example/header/height/100/raw': { status: 200, body: hex } }) });
  const client = new TeranodeClient(transport);
  const got = await client.headerByHeight(100);
  assert.equal(got.ok, true);
  assert.equal(got.ok && got.value.nonce, 7);
  const missing = await client.headerByHeight(999);
  assert.equal(missing.ok, false);
});

// Network-gated live integration: only runs when ANCHORCHAIN_NODE_URL points at a
// Teranode-shaped REST endpoint. Skipped (not failed) otherwise, per the
// genuine-or-pending rule — broadcasting a real anchor tx additionally needs a
// funded key and is out of scope for an automated test.
test('node.http live header fetch (gated on ANCHORCHAIN_NODE_URL)', { skip: process.env.ANCHORCHAIN_NODE_URL === undefined ? 'set ANCHORCHAIN_NODE_URL to a Teranode REST base to run' : false }, async () => {
  const client = new TeranodeClient(new FetchTransport(process.env.ANCHORCHAIN_NODE_URL as string));
  const r = await client.headerByHeight(1);
  assert.equal(r.ok, true);
});
