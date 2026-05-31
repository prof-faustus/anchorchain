import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { BlockHeader } from '@anchorchain/bsv';
import { HashOps, TxidOps, HeaderChain } from '@anchorchain/bsv';
import { merkleRoot, merkleProof, reconstructRoot } from '@anchorchain/merkle';

const block = JSON.parse(readFileSync(join(import.meta.dirname, '..', '..', '..', 'vectors', 'merkle', 'bsv_block_v1.json'), 'utf8'));
const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};

test('14.g genuine SPV: a real BSV block-181 txid proves into the genuine header', () => {
  // genuine header (real difficulty bits and mined nonce) — its PoW must validate
  const header: BlockHeader = {
    version: block.version,
    prevBlockHash: HashOps.fromDisplayHex(block.previousBlockHash).value,
    merkleRoot: HashOps.fromDisplayHex(block.merkleRoot).value,
    time: block.time,
    bits: block.bits,
    nonce: block.nonce,
  };
  const chain = new HeaderChain(block.height);
  assert.equal(chain.add(header).ok, true); // genuine proof-of-work

  // the block's transactions hash to the genuine Merkle root
  const leaves = block.txids.map((t: string) => TxidOps.asHash(unwrap(TxidOps.fromDisplayHex(t))));
  const root = unwrap(merkleRoot(leaves));
  assert.equal(HashOps.toDisplayHex(root), block.merkleRoot);

  // SPV steps 3-4 against real data: a txid -> block-Merkle branch -> the root the
  // genuine header commits to at height 181
  const proof = unwrap(merkleProof(leaves, 0));
  const reconstructed = reconstructRoot(leaves[0], proof);
  const committed = chain.merkleRootAtHeight(block.height);
  assert.notEqual(committed, undefined);
  assert.equal(HashOps.equals(reconstructed, committed!), true);

  // a wrong height has no committed root (fails closed)
  assert.equal(chain.merkleRootAtHeight(block.height + 1), undefined);
});

// PENDING (genuine-or-pending rule): a full OP_RETURN-anchor SPV test against real
// on-chain data needs a genuine post-Genesis BSV block that contains a transaction
// with an OP_RETURN data carrier we can parse end to end. It requires a fixture
// vectors/anchor/bsv_op_return_block_v1.json providing, all genuine:
//   - the block height and 80-byte header (version, prevBlockHash, merkleRoot, time,
//     bits, nonce) so its PoW validates;
//   - the full block txid list (to rebuild the block Merkle root);
//   - the index and raw transaction bytes of the OP_RETURN-carrying transaction;
//   - the exact OP_RETURN output locking-script hex and the carried payload.
// This fixture cannot be fabricated and was not reachable from this environment, so
// the test is pending rather than written against invented data.
test('14.g genuine OP_RETURN anchor parsed from a real block', { skip: 'pending genuine fixture vectors/anchor/bsv_op_return_block_v1.json (see comment for exact fields)' }, () => {
  assert.fail('unreachable while pending');
});
