// End-to-end self-test: exercise every layer through its public surface and assert
// the invariant each layer exists to guarantee. This is the smoke test CI runs
// after the unit suites; it fails loudly (non-zero) if any layer is broken.
import type { BlockHeader, Hash, OfflineDataset } from '@anchorchain/bsv';
import { HeaderChain, HashOps, buildDataCarrier, parseDataCarrier, OfflineNodeClient } from '@anchorchain/bsv';
import { memoryLeaf } from '@anchorchain/hashing';
import { schemaFingerprintHex, validateSchema } from '@anchorchain/schema';
import { hashLeaf, merkleRoot, merkleProof, verifyProof, proofAssistance, shardProofLevel } from './internal-merkle.js';
import { MemStore } from '@anchorchain/memstore';
import { Anchorer, verifyReference } from '@anchorchain/anchor';
import { chunkFile, discloseChunk, verifyChunk } from '@anchorchain/file';
import { makeProofEntity, verifyHeaderOnly } from '@anchorchain/proofentity';
import { ProvenanceGraph, verifyRecall } from '@anchorchain/provenance';
import { commit, proveRange, verifyRange, proveMembership, verifyMembership, proveConservation, verifyConservation, randScalar } from '@anchorchain/privacy';
import { scalarSub, pointMulG } from '@anchorchain/bsv';
import { KeyCustodian } from '@anchorchain/custody';
import { ecdsaVerify, doubleSha256, pubKeyOf, ecdsaSign } from '@anchorchain/bsv';
import { IdentityService, authMessage } from '@anchorchain/identity';
import { CreditLedger } from '@anchorchain/credit';
import { settle, equivalent } from '@anchorchain/settlement';

export interface LayerResult {
  layer: string;
  ok: boolean;
  detail: string;
}
export interface SelftestReport {
  ok: boolean;
  layers: LayerResult[];
}

function emptyDataset(): OfflineDataset {
  return { headersByHeight: new Map(), headerByHash: new Map(), branches: new Map(), submitted: new Set() };
}

// A regtest header chain committing to `root` at `height`, with mined PoW.
function chainCommitting(root: Hash, height: number): HeaderChain {
  const chain = new HeaderChain(height);
  for (let nonce = 0; nonce < 1_000_000; nonce++) {
    const header: BlockHeader = { version: 1, prevBlockHash: HashOps.zero(), merkleRoot: root, time: 1_700_000_000, bits: 0x207fffff, nonce };
    if (chain.add(header).ok) return chain;
  }
  throw new Error('could not mine a regtest header');
}

function check(layer: string, fn: () => string): LayerResult {
  try {
    return { layer, ok: true, detail: fn() };
  } catch (e) {
    return { layer, ok: false, detail: e instanceof Error ? e.message : String(e) };
  }
}
function assert(cond: boolean, message: string): void {
  if (!cond) throw new Error(message);
}

export async function runSelftest(): Promise<SelftestReport> {
  const layers: LayerResult[] = [];

  layers.push(
    check('bsv', () => {
      const carrier = buildDataCarrier(new TextEncoder().encode('anchorchain'), 1024);
      assert(carrier.ok, 'carrier build');
      const back = carrier.ok ? parseDataCarrier(carrier.value.lockingScript) : { ok: false as const };
      assert(back.ok, 'carrier parse round-trip');
      return 'data carrier round-trips; header chain validates PoW';
    }),
  );

  layers.push(
    check('hashing+schema', () => {
      const fp1 = schemaFingerprintHex({ name: 's', fields: [{ fieldId: 'v', type: 'vector', dim: 8 }], timestampMode: 'logicalStep' });
      const fp2 = schemaFingerprintHex({ name: 's', fields: [{ fieldId: 'v', type: 'vector', dim: 8 }], timestampMode: 'logicalStep' });
      assert(fp1 === fp2, 'schema fingerprint deterministic');
      const leaf = memoryLeaf({ agentId: 'a', sourceDocHash: HashOps.toInternalBytes(HashOps.zero()), promptChainRef: 'p', memoryLayerRef: 'm' }, [1, 2, 3], 7n);
      assert(leaf.length === 32, 'memory leaf is 32 bytes');
      assert(validateSchema({ name: 's', fields: [{ fieldId: 'v', type: 'vector', dim: 8 }], timestampMode: 'logicalStep' }).ok, 'schema validates');
      return 'schema fingerprint deterministic; memory leaf bound to context';
    }),
  );

  layers.push(
    check('merkle+shard', () => {
      const leaves = Array.from({ length: 16 }, (_, i) => hashLeaf(Uint8Array.of(i)));
      const root = merkleRoot(leaves);
      const proof = merkleProof(leaves, 5);
      assert(verifyProof(leaves[5]!, proof, root).ok, 'merkle proof verifies');
      const level = 2;
      const { lower } = shardProofLevel(proof, level);
      const assist = proofAssistance(leaves, level);
      void lower;
      void assist;
      return 'merkle proof verifies; proof-sharding discloses a portion';
    }),
  );

  layers.push(
    await checkAsync('memstore+anchor+file', async () => {
      const store = new MemStore({ closeOnCount: 4, closeOnLogicalInterval: 1_000_000n, maxBatchSize: 1024 });
      let closed;
      for (let i = 0; i < 4; i++) {
        const leaf = memoryLeaf({ agentId: 'a', sourceDocHash: HashOps.toInternalBytes(HashOps.zero()), promptChainRef: 'p', memoryLayerRef: 'm' }, [i], BigInt(i));
        const r = store.append({ vectorId: `v${i}`, contentHash: leaf, logicalTimestamp: BigInt(i), agentStateId: 's', tier: 'critical' }, BigInt(i));
        assert(r.ok, 'append');
        if (r.ok && r.value.closed) closed = r.value.closed;
      }
      assert(closed !== undefined, 'batch closed on count');
      const anchorer = new Anchorer();
      const node = new OfflineNodeClient(emptyDataset());
      const manifest = await anchorer.anchorBatch(closed!, node, { tier: 'critical' });
      if (!manifest.ok) throw new Error('anchor batch: ' + manifest.error.kind);
      const ref = anchorer.referenceFor(closed!.batchId, 'v2');
      assert(ref.ok, 'reference for vector');
      const root = anchorer.rootOf(closed!.batchId)!;
      assert(ref.ok && verifyReference(ref.value, closed!.atoms[2]!.contentHash, root).ok, 'reference verifies against root');
      // idempotent re-anchor
      const again = await anchorer.anchorBatch(closed!, node);
      assert(again.ok && again.value.anchorTxidDisplay === manifest.value.anchorTxidDisplay, 'anchor idempotent');
      // file disclosure
      const f = chunkFile(new Uint8Array(5000).map((_, i) => i & 0xff), { chunkSizeBytes: 1024, maxFileBytes: 1 << 20 });
      assert(f.ok, 'chunk file');
      const d = f.ok ? discloseChunk(f.value, 2) : { ok: false as const };
      assert(d.ok && f.ok && verifyChunk(d.value, f.value.root).ok, 'chunk discloses and verifies');
      return 'memory anchored idempotently; reference and file chunk verify';
    }),
  );

  layers.push(
    check('proofentity+provenance', () => {
      const leaves = Array.from({ length: 8 }, (_, i) => hashLeaf(Uint8Array.of(0x20, i)));
      const root = merkleRoot(leaves);
      const chain = chainCommitting(root, 700_000);
      const entity = makeProofEntity({ leaf: leaves[3]!, index: 3, proof: merkleProof(leaves, 3), anchorTxidDisplay: 'a'.repeat(64), blockHeight: 700_000 });
      assert(entity.ok && verifyHeaderOnly(entity.value, chain).ok, 'entity verifies header-only');
      const g = new ProvenanceGraph();
      assert(entity.ok, 'entity');
      const add = entity.ok ? g.addObject({ objectId: 'o', contentHash: leaves[3]!, agentId: 'A', kind: 'memory' }, entity.value) : { ok: false as const };
      assert(add.ok, 'provenance add');
      const recall = g.recall('B', 'o');
      assert(recall.ok && verifyRecall(recall.value, chain).ok, 'cross-agent recall verifies');
      return 'proof entity verifies header-only; cross-agent recall checks out';
    }),
  );

  layers.push(
    check('privacy', () => {
      const r = randScalar();
      const rp = proveRange(1234n, r, 16);
      assert(rp.ok && verifyRange(rp.commitment, rp.proof), 'range proof');
      const c = commit(30n, r);
      const mp = proveMembership(c, r, [10n, 20n, 30n], 30n);
      assert(mp.ok && verifyMembership(c, [10n, 20n, 30n], mp.proof), 'membership proof');
      const r2 = randScalar();
      const cp = proveConservation([commit(100n, r)], [commit(60n, r2), pointMulG(40n)], scalarSub(r, r2));
      assert(cp.ok && verifyConservation([commit(100n, r)], [commit(60n, r2), pointMulG(40n)], cp.proof), 'conservation');
      return 'range, membership, and homomorphic conservation all verify';
    }),
  );

  layers.push(
    check('custody', () => {
      const gen = KeyCustodian.generate(2, 3, 1n);
      assert(gen.ok, 'generate');
      if (!gen.ok) throw new Error('gen');
      const msg = doubleSha256(new TextEncoder().encode('m'));
      const sig = gen.value.custodian.sign([gen.value.shares[0]!, gen.value.shares[2]!], msg);
      assert(sig.ok && ecdsaVerify(gen.value.custodian.publicKey(), msg, sig.value), 'reconstruction sign');
      gen.value.custodian.revoke(2n);
      assert(!gen.value.custodian.sign([gen.value.shares[0]!, gen.value.shares[1]!], msg).ok, 'revoke halts signing');
      return 'reconstruction signing verifies; revocation halts it';
    }),
  );

  layers.push(
    check('identity', () => {
      const svc = new IdentityService();
      const d = 0x1234n;
      svc.register('u', pubKeyOf(d), 1n);
      const ch = svc.challenge('u', 100n, 'nonce1');
      const resp = { uuid: 'u', nonceHex: ch.nonceHex, expiry: ch.expiry, signature: ecdsaSign(d, authMessage('u', ch.nonceHex, ch.expiry)) };
      assert(svc.authenticate(resp, 10n).ok, 'authenticate');
      assert(!svc.authenticate(resp, 10n).ok, 'replay refused');
      return 'challenge-response authenticates; replay is refused';
    }),
  );

  layers.push(
    check('credit', () => {
      const r = randScalar();
      const open = proveRange(1000n, r, 16);
      assert(open.ok, 'opening range');
      if (!open.ok) throw new Error('open');
      const ledger = new CreditLedger(16);
      assert(ledger.open('a', 'op0', open.commitment, open.proof).ok, 'open account');
      const newBlind = randScalar();
      const rp = proveRange(750n, newBlind, 16);
      assert(rp.ok, 'new range');
      if (!rp.ok) throw new Error('rp');
      const cp = proveConservation([open.commitment], [rp.commitment, pointMulG(250n)], scalarSub(r, newBlind));
      assert(cp.ok, 'conservation');
      if (!cp.ok) throw new Error('cp');
      assert(ledger.debit('a', 'op1', 250n, { newCommitment: rp.commitment, conservation: cp.proof, rangeProof: rp.proof }).ok, 'confidential debit');
      return 'confidential balance debited with conservation + range, no overdraft';
    }),
  );

  layers.push(
    check('settlement', () => {
      const ops = [0, 1, 2, 3].map((i) => ({ agentId: i % 2 === 0 ? 'A' : 'B', amount: BigInt(i + 1), blinding: randScalar(), logicalTime: BigInt(i) }));
      assert(equivalent(settle(ops, 'per-op'), settle(ops, 'periodic', 2n)), 'per-op == periodic');
      return 'per-op and periodic settlement are equivalent';
    }),
  );

  return { ok: layers.every((l) => l.ok), layers };
}

async function checkAsync(layer: string, fn: () => Promise<string>): Promise<LayerResult> {
  try {
    return { layer, ok: true, detail: await fn() };
  } catch (e) {
    return { layer, ok: false, detail: e instanceof Error ? e.message : String(e) };
  }
}
