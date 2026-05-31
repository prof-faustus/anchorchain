// Independent generator points for the Bulletproofs vectors, derived by a
// nothing-up-my-sleeve hash-to-curve (try-and-increment) so that no discrete-log
// relation among them — or with G and H — is known. This is what makes the
// inner-product commitments binding.
import type { Point } from '@anchorchain/bsv';
import { decodePoint, doubleSha256 } from '@anchorchain/bsv';

const enc = new TextEncoder();

export function hashToPoint(label: string): Point {
  for (let counter = 0; counter < 100000; counter++) {
    const x = doubleSha256(enc.encode(label + ':' + counter));
    for (const prefix of [0x02, 0x03]) {
      const compressed = new Uint8Array(33);
      compressed[0] = prefix;
      compressed.set(x, 1);
      const p = decodePoint(compressed);
      if (p.ok) return p.value;
    }
  }
  throw new Error('hashToPoint: no valid point (unreachable)');
}

export function generatorVector(domain: string, n: number): Point[] {
  return Array.from({ length: n }, (_, i) => hashToPoint(domain + '/' + i));
}

// The single generator U binding the inner product, fixed by domain.
export const BP_U: Point = hashToPoint('anchorchain/bp/U/v1');
