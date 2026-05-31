// The verification TRUST ROOT: an append-only header chain validated by prevHash
// linkage, proof-of-work against bits, and monotonic height. merkleRootAtHeight
// is what every inclusion proof ultimately terminates in.
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { chainNotLinked, chainBadPoW, chainNonMonotonic } from './errors.js';
import type { Hash } from './hash.js';
import { equals, toDisplayHex } from './hash.js';
import type { BlockHeader } from './header.js';
import { headerHash, meetsTarget } from './header.js';

export class HeaderChain {
  private readonly headers: BlockHeader[] = [];
  private readonly byHashMap = new Map<string, number>();
  private readonly byRootMap = new Map<string, number>();
  private readonly startHeight: number;

  constructor(startHeight = 0) {
    this.startHeight = startHeight;
  }

  // Validate-and-append. The first header sets the base; each later header must
  // link to the current tip's hash, meet its target, and extend height by one.
  add(h: BlockHeader): Result<void, BsvError> {
    if (this.headers.length > 0) {
      const tip = this.headers[this.headers.length - 1] as BlockHeader;
      const tipHash = headerHash(tip);
      if (!equals(h.prevBlockHash, tipHash)) return err(chainNotLinked(toDisplayHex(tipHash), toDisplayHex(h.prevBlockHash)));
    }
    if (!meetsTarget(h)) return err(chainBadPoW(toDisplayHex(headerHash(h))));
    const idx = this.headers.length;
    this.headers.push(h);
    this.byHashMap.set(toDisplayHex(headerHash(h)), idx);
    this.byRootMap.set(toDisplayHex(h.merkleRoot), idx);
    return ok(undefined);
  }

  // Explicit monotonic-height guard for callers that assert an expected height.
  addAtHeight(h: BlockHeader, expectedHeight: number): Result<void, BsvError> {
    if (this.startHeight + this.headers.length !== expectedHeight) return err(chainNonMonotonic(this.startHeight + this.headers.length));
    return this.add(h);
  }

  tipHeight(): number {
    return this.startHeight + this.headers.length - 1;
  }
  byHeight(height: number): BlockHeader | undefined {
    return this.headers[height - this.startHeight];
  }
  byHash(hash: Hash): { header: BlockHeader; height: number } | undefined {
    const idx = this.byHashMap.get(toDisplayHex(hash));
    if (idx === undefined) return undefined;
    return { header: this.headers[idx] as BlockHeader, height: this.startHeight + idx };
  }
  // THE TRUST ROOT lookup: the merkle root committed by the header at a height.
  merkleRootAtHeight(height: number): Hash | undefined {
    const h = this.byHeight(height);
    return h?.merkleRoot;
  }
  containsMerkleRoot(root: Hash): { height: number } | undefined {
    const idx = this.byRootMap.get(toDisplayHex(root));
    if (idx === undefined) return undefined;
    return { height: this.startHeight + idx };
  }
}
