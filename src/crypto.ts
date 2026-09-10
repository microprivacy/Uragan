/**
 * Notes and the Merkle tree. All cryptography comes from micro-zk-proofs
 * (noble family); this file only composes it.
 */
import { randomBytes } from 'node:crypto';
import { bytesToNumberBE, bytesToNumberLE, concatBytes, numberToBytesBE, numberToBytesLE } from '@noble/curves/utils.js';
import { pedersenHash, Point } from 'micro-zk-proofs/pedersen.js';
import { multiHash } from 'micro-zk-proofs/mimcsponge.js';

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** Pedersen hash -> x coordinate of the babyjubjub point, which is what Tornado commits to. */
export const pedersen = (buf: Uint8Array): bigint => Point.decode(pedersenHash(buf)).toAffine().x;

/** MerkleTreeWithHistory.hashLeftRight */
export const hashLeftRight = (l: bigint, r: bigint): bigint => multiHash([l, r], 0n, 1) as bigint;

export const hex32 = (n: bigint): string => '0x' + n.toString(16).padStart(64, '0');

// ---------------------------------------------------------------------------
// Fixed Merkle tree (height 20), matching MerkleTreeWithHistory.sol
// ---------------------------------------------------------------------------
export const TREE_LEVELS = 20;

/** keccak256("tornado") % p, hardcoded in the deployed contract. */
export const ZERO_VALUE =
  21663839004416932945382355908790599225266501822907911457504978515578255421292n;

export type Tree = { root: bigint; layers: bigint[][]; zeros: bigint[] };

export function zeroValues(levels: number = TREE_LEVELS): bigint[] {
  const z: bigint[] = [ZERO_VALUE];
  for (let i = 1; i <= levels; i++) z.push(hashLeftRight(z[i - 1]!, z[i - 1]!));
  return z;
}

/** Build the full tree. `leaves` are commitments in leafIndex order. */
export const buildTree = (leaves: bigint[], levels: number = TREE_LEVELS): Tree =>
  extendTree(undefined, leaves, levels);

/**
 * Bring a tree up to date with `leaves`, recomputing only what changed.
 *
 * The contract's tree is append-only, so a tree built on an earlier leaf set
 * stays valid left of the first leaf that differs -- whether that leaf was
 * appended since, or replaced by a reorg. Only nodes above and right of it are
 * rehashed: about (changed leaves + levels) hashes, versus ~2x the leaf count
 * for a full build (51 s at eth-1's 92k leaves). Takes ownership of `prev`.
 */
export function extendTree(prev: Tree | undefined, leaves: bigint[], levels: number = TREE_LEVELS): Tree {
  const zeros = prev?.zeros ?? zeroValues(levels);
  const layers = prev?.layers ?? Array.from({ length: levels + 1 }, (): bigint[] => []);
  const old = layers[0]!;
  let from = 0;
  while (from < old.length && from < leaves.length && old[from] === leaves[from]) from++;

  layers[0] = leaves.slice();
  for (let lvl = 0; lvl < levels; lvl++) {
    const cur = layers[lvl]!;
    const next = layers[lvl + 1]!;
    const len = Math.ceil(cur.length / 2);
    next.length = len; // leaves can shrink when a reorg drops tip deposits
    for (let i = from >> 1; i < len; i++) {
      next[i] = hashLeftRight(cur[2 * i]!, 2 * i + 1 < cur.length ? cur[2 * i + 1]! : zeros[lvl]!);
    }
    from >>= 1;
  }
  const top = layers[levels]!;
  return { root: top.length ? top[0]! : zeros[levels]!, layers, zeros };
}

/** Binary form for the on-disk cache: per level, a u32 count then 32-byte nodes. */
export function encodeTree(t: Tree): Uint8Array {
  const size = 4 + t.layers.reduce((n, l) => n + 4 + l.length * 32, 0);
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  view.setUint32(0, t.layers.length);
  let o = 4;
  for (const layer of t.layers) {
    view.setUint32(o, layer.length);
    o += 4;
    for (const node of layer) {
      out.set(numberToBytesBE(node, 32), o);
      o += 32;
    }
  }
  return out;
}

export function decodeTree(b: Uint8Array): Tree {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const count = view.getUint32(0);
  const layers: bigint[][] = [];
  let o = 4;
  for (let l = 0; l < count; l++) {
    const len = view.getUint32(o);
    o += 4;
    const layer = new Array<bigint>(len);
    for (let i = 0; i < len; i++, o += 32) layer[i] = bytesToNumberBE(b.subarray(o, o + 32));
    layers.push(layer);
  }
  if (o !== b.length) throw new Error('tree cache is truncated or corrupt');
  const levels = count - 1;
  const zeros = zeroValues(levels);
  const top = layers[levels]!;
  return { root: top.length ? top[0]! : zeros[levels]!, layers, zeros };
}

export function treePath(tree: Tree, index: number, levels: number = TREE_LEVELS) {
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let idx = index;
  for (let lvl = 0; lvl < levels; lvl++) {
    const layer = tree.layers[lvl]!;
    const sibling = idx ^ 1;
    pathIndices.push(idx % 2);
    pathElements.push(sibling < layer.length ? layer[sibling]! : tree.zeros[lvl]!);
    idx = Math.floor(idx / 2);
  }
  return { pathElements, pathIndices };
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------
export type Deposit = {
  nullifier: bigint;
  secret: bigint;
  commitment: bigint;
  nullifierHash: bigint;
};

function fromSecrets(nullifier: bigint, secret: bigint): Deposit & { preimage: Uint8Array } {
  const n = numberToBytesLE(nullifier, 31);
  const preimage = concatBytes(n, numberToBytesLE(secret, 31));
  return {
    nullifier,
    secret,
    preimage,
    commitment: pedersen(preimage),
    nullifierHash: pedersen(n),
  };
}

export type Note = Deposit & { currency: string; amount: string; netId: number; note: string };

export function createNote(currency: string, amount: string, netId: number): Note {
  const d = fromSecrets(bytesToNumberLE(randomBytes(31)), bytesToNumberLE(randomBytes(31)));
  const note = `tornado-${currency}-${amount}-${netId}-0x${Buffer.from(d.preimage).toString('hex')}`;
  return { currency, amount, netId, note, ...d };
}

export function parseNote(note: string): Note {
  const m = /^tornado-([a-zA-Z0-9]+)-([\d.]+)-(\d+)-0x([0-9a-fA-F]{124})$/.exec(note.trim());
  if (!m) throw new Error('invalid note (expected tornado-<currency>-<amount>-<netId>-0x<124 hex>)');
  const [, currency, amount, netId, hex] = m as unknown as [string, string, string, string, string];
  const buf = Buffer.from(hex, 'hex');
  return {
    currency: currency.toLowerCase(),
    amount,
    netId: Number(netId),
    note: note.trim(),
    ...fromSecrets(bytesToNumberLE(buf.subarray(0, 31)), bytesToNumberLE(buf.subarray(31, 62))),
  };
}
