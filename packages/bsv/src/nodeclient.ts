// Node access. OfflineNodeClient serves genuine fixtures deterministically (CI,
// no network). TeranodeClient talks to a Teranode-target node through an injected
// transport; every failure surfaces as a typed NodeError, no unhandled rejection.
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { nodeNotFound, nodeUnreachable, nodeBadResponse } from './errors.js';
import type { Txid } from './txid.js';
import { toDisplayHex as txidDisplay, ofTransactionBytes, fromDisplayHex as txidFromDisplay } from './txid.js';
import type { Hash } from './hash.js';
import { toDisplayHex as hashDisplay, fromDisplayHex as hashFromDisplay } from './hash.js';
import type { BlockHeader } from './header.js';
import { parseHeader, headerHash } from './header.js';
import { fromHex, concat } from './bytes.js';
import { toInternalBytes as hashBytes, zero as zeroHash } from './hash.js';
import { asHash } from './txid.js';
import { doubleSha256 } from './hashing.js';

export interface MerkleBranch {
  branch: Hash[];
  index: number;
  blockHeight: number;
}

export interface NodeClient {
  submit(rawTx: Uint8Array): Promise<Result<Txid, BsvError>>;
  headerByHeight(height: number): Promise<Result<BlockHeader, BsvError>>;
  headerByHash(hash: Hash): Promise<Result<BlockHeader, BsvError>>;
  merkleBranchForTxid(txid: Txid): Promise<Result<MerkleBranch, BsvError>>;
  headersFrom(height: number, count: number): Promise<Result<BlockHeader[], BsvError>>;
}

export interface OfflineDataset {
  headersByHeight: Map<number, BlockHeader>;
  headerByHash: Map<string, BlockHeader>;
  branches: Map<string, MerkleBranch>; // txid display -> branch
  submitted: Set<string>; // raw tx hex accepted offline
}

export class OfflineNodeClient implements NodeClient {
  private readonly data: OfflineDataset;
  constructor(data: OfflineDataset) {
    this.data = data;
  }
  async submit(rawTx: Uint8Array): Promise<Result<Txid, BsvError>> {
    return ok(ofTransactionBytes(rawTx));
  }
  async headerByHeight(height: number): Promise<Result<BlockHeader, BsvError>> {
    const h = this.data.headersByHeight.get(height);
    return h === undefined ? err(nodeNotFound(`header at height ${height}`)) : ok(h);
  }
  async headerByHash(hash: Hash): Promise<Result<BlockHeader, BsvError>> {
    const h = this.data.headerByHash.get(hashDisplay(hash));
    return h === undefined ? err(nodeNotFound(`header ${hashDisplay(hash)}`)) : ok(h);
  }
  async merkleBranchForTxid(txid: Txid): Promise<Result<MerkleBranch, BsvError>> {
    const b = this.data.branches.get(txidDisplay(txid));
    return b === undefined ? err(nodeNotFound(`branch for ${txidDisplay(txid)}`)) : ok(b);
  }
  async headersFrom(height: number, count: number): Promise<Result<BlockHeader[], BsvError>> {
    const out: BlockHeader[] = [];
    for (let i = 0; i < count; i++) {
      const h = this.data.headersByHeight.get(height + i);
      if (h === undefined) return err(nodeNotFound(`header at height ${height + i}`));
      out.push(h);
    }
    return ok(out);
  }
}

export type TransportResult = { kind: 'ok'; body: string } | { kind: 'notFound' } | { kind: 'unreachable'; detail: string };
export interface Transport {
  request(path: string, body?: string): Promise<TransportResult>;
}

// A minimal shape of the fetch Response this transport relies on, so a stub can be
// injected for tests without a real network.
export interface FetchResponseLike {
  status: number;
  ok: boolean;
  text(): Promise<string>;
}
export type FetchLike = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<FetchResponseLike>;

// Production HTTP transport: GET when there is no body, POST otherwise. A 404 maps
// to notFound, any other non-2xx and any thrown error map to unreachable, and a 2xx
// returns the response text. The fetch implementation is injectable (defaults to the
// global fetch) so status mapping is unit-testable offline.
export class FetchTransport implements Transport {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly fetchFn: FetchLike;
  constructor(baseUrl: string, opts?: { headers?: Record<string, string>; fetchFn?: FetchLike }) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.headers = opts?.headers ?? {};
    this.fetchFn = opts?.fetchFn ?? ((url, init) => fetch(url, init) as unknown as Promise<FetchResponseLike>);
  }
  async request(path: string, body?: string): Promise<TransportResult> {
    const url = this.baseUrl + path;
    try {
      const res = body === undefined ? await this.fetchFn(url, { headers: this.headers }) : await this.fetchFn(url, { method: 'POST', headers: { ...this.headers, 'content-type': 'text/plain' }, body });
      if (res.status === 404) return { kind: 'notFound' };
      if (!res.ok) return { kind: 'unreachable', detail: `HTTP ${res.status}` };
      return { kind: 'ok', body: await res.text() };
    } catch (e) {
      return { kind: 'unreachable', detail: e instanceof Error ? e.message : 'fetch failed' };
    }
  }
}

export class TeranodeClient implements NodeClient {
  private readonly transport: Transport;
  constructor(transport: Transport) {
    this.transport = transport;
  }
  private async fetch(path: string, what: string, body?: string): Promise<Result<string, BsvError>> {
    let r: TransportResult;
    try {
      r = await this.transport.request(path, body);
    } catch (e) {
      return err(nodeUnreachable(e instanceof Error ? e.message : 'transport threw'));
    }
    if (r.kind === 'unreachable') return err(nodeUnreachable(r.detail));
    if (r.kind === 'notFound') return err(nodeNotFound(what));
    return ok(r.body);
  }
  async submit(rawTx: Uint8Array): Promise<Result<Txid, BsvError>> {
    let hex = '';
    for (const b of rawTx) hex += b.toString(16).padStart(2, '0');
    const body = await this.fetch('/tx', 'submit', hex);
    if (!body.ok) return err(body.error);
    const t = txidFromDisplay(body.value.trim());
    return t.ok ? ok(t.value) : err(nodeBadResponse('submit did not return a txid'));
  }
  async headerByHeight(height: number): Promise<Result<BlockHeader, BsvError>> {
    return this.decodeHeader(await this.fetch(`/header/height/${height}/raw`, `header at height ${height}`));
  }
  async headerByHash(hash: Hash): Promise<Result<BlockHeader, BsvError>> {
    return this.decodeHeader(await this.fetch(`/header/${hashDisplay(hash)}/raw`, `header ${hashDisplay(hash)}`));
  }
  private decodeHeader(body: Result<string, BsvError>): Result<BlockHeader, BsvError> {
    if (!body.ok) return err(body.error);
    const bytes = fromHex(body.value.trim());
    if (!bytes.ok) return err(nodeBadResponse('header body is not hex'));
    const header = parseHeader(bytes.value);
    return header.ok ? ok(header.value) : err(nodeBadResponse('header body did not parse'));
  }
  async merkleBranchForTxid(txid: Txid): Promise<Result<MerkleBranch, BsvError>> {
    const body = await this.fetch(`/tx/${txidDisplay(txid)}/proof`, `branch for ${txidDisplay(txid)}`);
    if (!body.ok) return err(body.error);
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.value);
    } catch {
      return err(nodeBadResponse('branch body is not JSON'));
    }
    const o = parsed as { branchHex?: unknown; index?: unknown; blockHeight?: unknown };
    if (!Array.isArray(o.branchHex) || typeof o.index !== 'number' || typeof o.blockHeight !== 'number') return err(nodeBadResponse('branch body shape'));
    const branch: Hash[] = [];
    for (const s of o.branchHex) {
      if (typeof s !== 'string') return err(nodeBadResponse('branch entry not a string'));
      const h = hashFromDisplay(s);
      if (!h.ok) return err(nodeBadResponse('branch entry not a hash'));
      branch.push(h.value);
    }
    return ok({ branch, index: o.index, blockHeight: o.blockHeight });
  }
  async headersFrom(height: number, count: number): Promise<Result<BlockHeader[], BsvError>> {
    const out: BlockHeader[] = [];
    for (let i = 0; i < count; i++) {
      const h = await this.headerByHeight(height + i);
      if (!h.ok) return err(h.error);
      out.push(h.value);
    }
    return ok(out);
  }
}

// WhatsOnChain's public REST API (https://api.whatsonchain.com/v1/bsv/<network>).
// Its paths and response shapes differ from a Teranode-shaped endpoint, so it has
// its own client over the same Transport:
//   submit                POST /tx/raw  {"txhex": "..."}   -> "<txid>" (JSON string)
//   header by height      GET  /block/height/<h>            -> block JSON
//   header by hash        GET  /block/<hash>/header         -> header JSON
//   Merkle branch         GET  /tx/<txid>/proof/tsc         -> [{ index, txOrId, target, nodes }]
// Headers arrive as JSON fields, so each is re-serialized and must hash to the hash
// WhatsOnChain reports; a mismatch is a bad response, never a header. In a TSC
// branch "*" means the node is paired with itself; it is expanded here into the
// concrete sibling so the branch folds with reconstructRoot like any other.
export class WhatsOnChainClient implements NodeClient {
  private readonly transport: Transport;
  constructor(transport: Transport) {
    this.transport = transport;
  }
  private async fetch(path: string, what: string, body?: string): Promise<Result<string, BsvError>> {
    let r: TransportResult;
    try {
      r = await this.transport.request(path, body);
    } catch (e) {
      return err(nodeUnreachable(e instanceof Error ? e.message : 'transport threw'));
    }
    if (r.kind === 'unreachable') return err(nodeUnreachable(r.detail));
    if (r.kind === 'notFound') return err(nodeNotFound(what));
    return ok(r.body);
  }
  private async json(path: string, what: string): Promise<Result<unknown, BsvError>> {
    const body = await this.fetch(path, what);
    if (!body.ok) return err(body.error);
    try {
      return ok(JSON.parse(body.value) as unknown);
    } catch {
      return err(nodeBadResponse(`${what}: body is not JSON`));
    }
  }
  async submit(rawTx: Uint8Array): Promise<Result<Txid, BsvError>> {
    let hex = '';
    for (const b of rawTx) hex += b.toString(16).padStart(2, '0');
    const body = await this.fetch('/tx/raw', 'submit', JSON.stringify({ txhex: hex }));
    if (!body.ok) return err(body.error);
    const t = txidFromDisplay(body.value.trim().replace(/^"|"$/g, ''));
    if (!t.ok) return err(nodeBadResponse('submit did not return a txid'));
    // The node must have accepted exactly the transaction that was sent.
    const sent = ofTransactionBytes(rawTx);
    return txidDisplay(t.value) === txidDisplay(sent) ? ok(t.value) : err(nodeBadResponse('submit returned a different txid'));
  }
  async headerByHeight(height: number): Promise<Result<BlockHeader, BsvError>> {
    return this.headerOf(await this.json(`/block/height/${height}`, `header at height ${height}`), height);
  }
  async headerByHash(hash: Hash): Promise<Result<BlockHeader, BsvError>> {
    return this.headerOf(await this.json(`/block/${hashDisplay(hash)}/header`, `header ${hashDisplay(hash)}`));
  }
  private headerOf(body: Result<unknown, BsvError>, height?: number): Result<BlockHeader, BsvError> {
    if (!body.ok) return err(body.error);
    const parsed = wocHeader(body.value);
    if (!parsed.ok) return err(parsed.error);
    if (height !== undefined && parsed.value.height !== height) return err(nodeBadResponse('header is not at the requested height'));
    return ok(parsed.value.header);
  }
  async merkleBranchForTxid(txid: Txid): Promise<Result<MerkleBranch, BsvError>> {
    const what = `branch for ${txidDisplay(txid)}`;
    const body = await this.json(`/tx/${txidDisplay(txid)}/proof/tsc`, what);
    if (!body.ok) return err(body.error);
    const p = (Array.isArray(body.value) ? body.value[0] : body.value) as { index?: unknown; target?: unknown; nodes?: unknown } | undefined;
    if (p === undefined || typeof p.index !== 'number' || typeof p.target !== 'string' || !Array.isArray(p.nodes)) return err(nodeBadResponse(`${what}: not yet in a block, or unexpected shape`));
    // Expand "*" (pair with itself) by folding the running hash up the branch.
    const branch: Hash[] = [];
    let cur = asHash(txid);
    let idx = p.index;
    for (const n of p.nodes) {
      let sib: Hash;
      if (n === '*') sib = cur;
      else {
        const h = typeof n === 'string' ? hashFromDisplay(n) : undefined;
        if (h === undefined || !h.ok) return err(nodeBadResponse(`${what}: branch entry not a hash`));
        sib = h.value;
      }
      branch.push(sib);
      cur = (idx & 1) === 0 ? doubleSha256(concat(hashBytes(cur), hashBytes(sib))) : doubleSha256(concat(hashBytes(sib), hashBytes(cur)));
      idx = idx >> 1;
    }
    // The branch names the block by hash; its height comes from that header.
    const hdr = await this.json(`/block/${p.target}/header`, `header ${p.target}`);
    if (!hdr.ok) return err(hdr.error);
    const parsed = wocHeader(hdr.value);
    if (!parsed.ok) return err(parsed.error);
    if (hashDisplay(headerHash(parsed.value.header)) !== p.target) return err(nodeBadResponse(`${what}: header does not match the branch target`));
    return ok({ branch, index: p.index, blockHeight: parsed.value.height });
  }
  async headersFrom(height: number, count: number): Promise<Result<BlockHeader[], BsvError>> {
    const out: BlockHeader[] = [];
    for (let i = 0; i < count; i++) {
      const h = await this.headerByHeight(height + i);
      if (!h.ok) return err(h.error);
      out.push(h.value);
    }
    return ok(out);
  }
}

// Rebuild a header from WhatsOnChain's JSON and check it hashes to the reported hash.
function wocHeader(v: unknown): Result<{ header: BlockHeader; height: number }, BsvError> {
  const o = v as { hash?: unknown; height?: unknown; version?: unknown; previousblockhash?: unknown; merkleroot?: unknown; time?: unknown; bits?: unknown; nonce?: unknown } | null;
  if (o === null || typeof o !== 'object' || typeof o.hash !== 'string' || typeof o.height !== 'number' || typeof o.version !== 'number' || typeof o.merkleroot !== 'string' || typeof o.time !== 'number' || typeof o.bits !== 'string' || typeof o.nonce !== 'number') {
    return err(nodeBadResponse('header JSON shape'));
  }
  const prev = typeof o.previousblockhash === 'string' ? hashFromDisplay(o.previousblockhash) : ok(zeroHash());
  const root = hashFromDisplay(o.merkleroot);
  if (!prev.ok || !root.ok) return err(nodeBadResponse('header JSON hashes'));
  const header: BlockHeader = { version: o.version >>> 0, prevBlockHash: prev.value, merkleRoot: root.value, time: o.time, bits: parseInt(o.bits, 16), nonce: o.nonce };
  if (hashDisplay(headerHash(header)) !== o.hash) return err(nodeBadResponse('header JSON does not hash to its reported hash'));
  return ok({ header, height: o.height });
}
