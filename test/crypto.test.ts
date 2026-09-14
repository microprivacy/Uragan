// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, Uragan: https://app.radicle.at/nodes/seed.radicle.at/rad:z3HZ1BVVrNEhRxGb12hn1VeMEPELZ
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertPrimitives,
  buildTree,
  createNote,
  decodeTree,
  encodeTree,
  extendTree,
  parseNote,
  treePath,
} from '../src/crypto.ts'

test('hash primitives give their known answers', () => {
  assertPrimitives()
})

test('a note parses back to its commitment and nullifier hash', () => {
  const n = createNote('eth', '0.1', 10)
  const back = parseNote(n.note)
  assert.equal(back.commitment, n.commitment)
  assert.equal(back.nullifierHash, n.nullifierHash)
  assert.equal(back.netId, 10)
})

const leaves = (count: number) => Array.from({ length: count }, (_, i) => BigInt(i) * 1000n + 1n)

test('the incremental tree matches a full build through appends, a reorg and a shrink', () => {
  const reorged = [...leaves(7), 999n] // leaf 7 replaced by another deposit
  let tree = extendTree(undefined, [])
  for (const set of [leaves(1), leaves(5), leaves(8), reorged, leaves(3), leaves(13)]) {
    tree = extendTree(tree, set)
    assert.equal(tree.root, buildTree(set).root)
  }
})

test('the tree cache round-trips', () => {
  const tree = buildTree(leaves(9))
  const back = decodeTree(encodeTree(tree))
  assert.equal(back.root, tree.root)
  assert.deepEqual(treePath(back, 4), treePath(tree, 4))
})
