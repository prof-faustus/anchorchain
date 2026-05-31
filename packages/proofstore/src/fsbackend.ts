// A disk-backed StoreBackend: each object is a file named by its content key under
// a root directory. The ProofStore wrapping it still rehash-binds on every read, so
// a corrupted or substituted file on disk is caught exactly as for any backend —
// the filesystem is not trusted for integrity, only for availability.
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { StoreBackend } from './index.js';

export class FileBackend implements StoreBackend {
  private readonly root: string;
  constructor(root: string) {
    this.root = root;
    mkdirSync(root, { recursive: true });
  }
  private path(key: string): string {
    return join(this.root, key);
  }
  write(key: string, bytes: Uint8Array): void {
    writeFileSync(this.path(key), bytes);
  }
  read(key: string): Uint8Array | undefined {
    const p = this.path(key);
    return existsSync(p) ? new Uint8Array(readFileSync(p)) : undefined;
  }
  has(key: string): boolean {
    return existsSync(this.path(key));
  }
  keys(): string[] {
    return existsSync(this.root) ? readdirSync(this.root) : [];
  }
}
