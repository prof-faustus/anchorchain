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
import { parseHeader } from './header.js';
import { fromHex } from './bytes.js';

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
