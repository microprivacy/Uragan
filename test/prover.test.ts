import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { bn254, stringBigints, type VerificationKey } from 'micro-zk-proofs'
import { ASSETS } from '../src/config.ts'
import { buildTree, createNote, treePath } from '../src/crypto.ts'
import { prove, witness } from '../src/prover.ts'

const skip = !existsSync(join(ASSETS, 'withdraw_proving_key.json')) && 'run `uragan setup` first'

test('proofs are accepted by the pinned verifying key', { skip }, async () => {
  const n = createNote('eth', '0.1', 1)
  const tree = buildTree([n.commitment])
  const path = treePath(tree, 0)
  const proof = await prove(
    witness({
      root: tree.root,
      nullifierHash: n.nullifierHash,
      recipient: 1n,
      relayer: 0n,
      fee: 0n,
      refund: 0n,
      nullifier: n.nullifier,
      secret: n.secret,
      pathElements: path.pathElements,
      pathIndices: path.pathIndices,
    }),
  )
  const vk = stringBigints.decode(
    JSON.parse(readFileSync(join(ASSETS, 'withdraw_verification_key.json'), 'utf8')),
  ) as VerificationKey
  // Verifying takes no FFT, so the stock bn254 (nqr 5) is fine here.
  const verify = (publicSignals: bigint[]) => bn254.groth.verifyProof(vk, { proof: proof.raw, publicSignals })

  assert.equal(verify(proof.publicSignals), true)
  const otherRecipient = [...proof.publicSignals]
  otherRecipient[2] = 2n
  assert.equal(verify(otherRecipient), false)
})
