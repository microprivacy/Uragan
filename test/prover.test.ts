import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { bn254 as curve } from '@noble/curves/bn254.js'
import { bn254, type GrothProof, stringBigints, type VerificationKey } from 'micro-zk-proofs'
import { ARTIFACTS, ASSETS } from '../src/config.ts'
import { buildTree, createNote, treePath } from '../src/crypto.ts'
import { type Proof, prove, witness } from '../src/prover.ts'

const skip = !Object.keys(ARTIFACTS).every((f) => existsSync(join(ASSETS, f))) && 'run `uragan setup` first'

const n = createNote('eth', '0.1', 1)
const tree = buildTree([n.commitment])
const path = treePath(tree, 0)
// root, nullifierHash, recipient, relayer, fee, refund: the order the contract
// hands them to the verifier. Distinct values, so a swap cannot hide.
const inputs = [tree.root, n.nullifierHash, 1n, 2n, 3n, 4n]
const withdrawal = (root = tree.root) => ({
  root,
  nullifierHash: n.nullifierHash,
  recipient: inputs[2],
  relayer: inputs[3],
  fee: inputs[4],
  refund: inputs[5],
  nullifier: n.nullifier,
  secret: n.secret,
  pathElements: path.pathElements,
  pathIndices: path.pathIndices,
})

// Proving takes seconds, so the tests share one proof.
let shared: Promise<Proof> | undefined
const proof = () => (shared ??= prove(witness(withdrawal())))

const verify = (p: GrothProof, publicSignals: bigint[]) => {
  const vk = stringBigints.decode(JSON.parse(readFileSync(join(ASSETS, 'withdraw_verification_key.json'), 'utf8')))
  // Verifying takes no FFT, so the stock bn254 (nqr 5) is fine here.
  return bn254.groth.verifyProof(vk as VerificationKey, { proof: p, publicSignals })
}

test('a witness against a root the note is not under is refused', { skip }, () => {
  const other = buildTree([createNote('eth', '0.1', 1).commitment]).root
  assert.throws(() => witness(withdrawal(other)), /Constraint doesn't match/)
})

test('the proof commits to the withdraw inputs, in the order the contract passes them', { skip }, async () => {
  assert.deepEqual((await proof()).publicSignals, inputs)
})

test('the pinned verifying key accepts the proof, and not for another recipient', { skip }, async () => {
  const { raw, publicSignals } = await proof()
  assert.equal(verify(raw, publicSignals), true)
  const otherRecipient = [...publicSignals]
  otherRecipient[2] = 5n
  assert.equal(verify(raw, otherRecipient), false)
})

test('the packed proof, read the way Verifier.sol reads it, is accepted too', { skip }, async () => {
  const { proof: packed } = await proof()
  assert.match(packed, /^0x[0-9a-f]{512}$/)
  const word = (i: number) => BigInt(`0x${packed.slice(2 + 64 * i, 66 + 64 * i)}`)
  // The verifier rejects any word at or above the base field prime.
  for (let i = 0; i < 8; i++) assert.ok(word(i) < curve.fields.Fp.ORDER, `word ${i} is not a field element`)
  // A = (p0, p1), B = ([p2, p3], [p4, p5]), C = (p6, p7), where a G2
  // coordinate is EIP-197's [imaginary, real].
  const decoded: GrothProof = {
    protocol: 'groth',
    pi_a: [word(0), word(1), 1n],
    pi_b: [
      [word(3), word(2)],
      [word(5), word(4)],
      [1n, 0n],
    ],
    pi_c: [word(6), word(7), 1n],
  }
  assert.equal(verify(decoded, inputs), true)
})
