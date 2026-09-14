// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, Uragan: https://app.radicle.at/nodes/seed.radicle.at/rad:z3HZ1BVVrNEhRxGb12hn1VeMEPELZ
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Notes and the Merkle tree. All cryptography comes from micro-zk-proofs
 * (noble family); this file only composes it.
 */
import { bytesToNumberBE, bytesToNumberLE, concatBytes, numberToBytesBE, numberToBytesLE } from '@noble/curves/utils.js'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { multiHash } from 'micro-zk-proofs/mimcsponge.js'
import { Point, pedersenHash } from 'micro-zk-proofs/pedersen.js'

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** Pedersen hash -> x coordinate of the babyjubjub point, which is what Tornado commits to. */
export const pedersen = (buf: Uint8Array): bigint => Point.decode(pedersenHash(buf)).toAffine().x

/** MerkleTreeWithHistory.hashLeftRight */
export const hashLeftRight = (l: bigint, r: bigint): bigint => multiHash([l, r], 0n, 1) as bigint

export const hex32 = (n: bigint): string => `0x${n.toString(16).padStart(64, '0')}`

// ---------------------------------------------------------------------------
// Fixed Merkle tree (height 20), matching MerkleTreeWithHistory.sol
// ---------------------------------------------------------------------------
export const TREE_LEVELS = 20

/** keccak256("tornado") % p, hardcoded in the deployed contract. */
export const ZERO_VALUE = 21663839004416932945382355908790599225266501822907911457504978515578255421292n

export type Tree = { root: bigint; layers: bigint[][]; zeros: bigint[] }

export function zeroValues(levels: number = TREE_LEVELS): bigint[] {
  const z: bigint[] = [ZERO_VALUE]
  for (let i = 1; i <= levels; i++) z.push(hashLeftRight(z[i - 1]!, z[i - 1]!))
  return z
}

/** Build the full tree. `leaves` are commitments in leafIndex order. */
export const buildTree = (leaves: bigint[], levels: number = TREE_LEVELS): Tree => extendTree(undefined, leaves, levels)

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
  const zeros = prev?.zeros ?? zeroValues(levels)
  const layers = prev?.layers ?? Array.from({ length: levels + 1 }, (): bigint[] => [])
  const old = layers[0]!
  let from = 0
  while (from < old.length && from < leaves.length && old[from] === leaves[from]) from++

  layers[0] = leaves.slice()
  for (let lvl = 0; lvl < levels; lvl++) {
    const cur = layers[lvl]!
    const next = layers[lvl + 1]!
    const len = Math.ceil(cur.length / 2)
    next.length = len // leaves can shrink when a reorg drops tip deposits
    for (let i = from >> 1; i < len; i++) {
      next[i] = hashLeftRight(cur[2 * i]!, 2 * i + 1 < cur.length ? cur[2 * i + 1]! : zeros[lvl]!)
    }
    from >>= 1
  }
  const top = layers[levels]!
  return { root: top.length ? top[0]! : zeros[levels]!, layers, zeros }
}

/** Binary form for the on-disk cache: per level, a u32 count then 32-byte nodes. */
export function encodeTree(t: Tree): Uint8Array {
  const size = 4 + t.layers.reduce((n, l) => n + 4 + l.length * 32, 0)
  const out = new Uint8Array(size)
  const view = new DataView(out.buffer)
  view.setUint32(0, t.layers.length)
  let o = 4
  for (const layer of t.layers) {
    view.setUint32(o, layer.length)
    o += 4
    for (const node of layer) {
      out.set(numberToBytesBE(node, 32), o)
      o += 32
    }
  }
  return out
}

export function decodeTree(b: Uint8Array): Tree {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  const count = view.getUint32(0)
  const layers: bigint[][] = []
  let o = 4
  for (let l = 0; l < count; l++) {
    const len = view.getUint32(o)
    o += 4
    const layer = new Array<bigint>(len)
    for (let i = 0; i < len; i++, o += 32) layer[i] = bytesToNumberBE(b.subarray(o, o + 32))
    layers.push(layer)
  }
  if (o !== b.length) throw new Error('tree cache is truncated or corrupt')
  const levels = count - 1
  const zeros = zeroValues(levels)
  const top = layers[levels]!
  return { root: top.length ? top[0]! : zeros[levels]!, layers, zeros }
}

export function treePath(tree: Tree, index: number, levels: number = TREE_LEVELS) {
  const pathElements: bigint[] = []
  const pathIndices: number[] = []
  let idx = index
  for (let lvl = 0; lvl < levels; lvl++) {
    const layer = tree.layers[lvl]!
    const sibling = idx ^ 1
    pathIndices.push(idx % 2)
    pathElements.push(sibling < layer.length ? layer[sibling]! : tree.zeros[lvl]!)
    idx = Math.floor(idx / 2)
  }
  return { pathElements, pathIndices }
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------
export type Deposit = {
  nullifier: bigint
  secret: bigint
  commitment: bigint
  nullifierHash: bigint
}

function fromSecrets(nullifier: bigint, secret: bigint): Deposit & { preimage: Uint8Array } {
  const n = numberToBytesLE(nullifier, 31)
  const preimage = concatBytes(n, numberToBytesLE(secret, 31))
  return {
    nullifier,
    secret,
    preimage,
    commitment: pedersen(preimage),
    nullifierHash: pedersen(n),
  }
}

export type Note = Deposit & { currency: string; amount: string; netId: number; note: string }

/**
 * Known answers: circomlib's Pedersen and MiMC vectors, and zeros[19] as the
 * deployed MerkleTreeWithHistory reports it (which pins ZERO_VALUE and the
 * whole MiMC ladder). Nothing on-chain checks a commitment: one made by a
 * broken hash deposits fine and can never be withdrawn, by any client.
 */
const KNOWN_ANSWERS: [name: string, got: () => bigint, want: bigint][] = [
  [
    'pedersen(zeros62)',
    () => pedersen(new Uint8Array(62)),
    10606596081724992687836412044438397210272029250652246605286526701104132431192n,
  ],
  [
    'pedersen(ff31)',
    () => pedersen(new Uint8Array(31).fill(0xff)),
    11958727323653992140393347419347735936852777297016280498319205036343819833236n,
  ],
  [
    'mimc([1,2])',
    () => hashLeftRight(1n, 2n),
    19814528709687996974327303300007262407299502847885145507292406548098437687919n,
  ],
  ['zeros[19]', () => zeroValues(20)[19]!, 0x198622acbd783d1b0d9064105b1fc8e4d8889de95c4c519b3f635809fe6afc05n],
]

let checked = false

/** Throws unless the hash primitives give their known answers. Runs once per process. */
export function assertPrimitives(): void {
  if (checked) return
  const bad = KNOWN_ANSWERS.filter(([, got, want]) => got() !== want).map(([name]) => name)
  if (bad.length) throw new Error(`crypto self-check failed (${bad.join(', ')}): a dependency is broken, no note made`)
  checked = true
}

/** A fresh note. Refuses to make one unless the primitives check out and the note parses back to itself. */
export function createNote(currency: string, amount: string, netId: number): Note {
  assertPrimitives()
  const d = fromSecrets(bytesToNumberLE(randomBytes(31)), bytesToNumberLE(randomBytes(31)))
  const note = `tornado-${currency}-${amount}-${netId}-0x${bytesToHex(d.preimage)}`
  if (parseNote(note).commitment !== d.commitment) throw new Error('note does not parse back to its commitment')
  return { currency, amount, netId, note, ...d }
}

export function parseNote(note: string): Note {
  const m = /^tornado-([a-zA-Z0-9]+)-([\d.]+)-(\d+)-0x([0-9a-fA-F]{124})$/.exec(note.trim())
  if (!m) throw new Error('invalid note (expected tornado-<currency>-<amount>-<netId>-0x<124 hex>)')
  const [, currency, amount, netId, hex] = m as unknown as [string, string, string, string, string]
  // A fresh Uint8Array, not a Buffer: small Buffers are carved out of one
  // shared pool, which would leave the note's secret readable through any
  // other Buffer's .buffer.
  const bytes = hexToBytes(hex)
  return {
    currency: currency.toLowerCase(),
    amount,
    netId: Number(netId),
    note: note.trim(),
    ...fromSecrets(bytesToNumberLE(bytes.subarray(0, 31)), bytesToNumberLE(bytes.subarray(31, 62))),
  }
}
