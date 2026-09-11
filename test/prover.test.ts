import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { bn254, stringBigints } from 'micro-zk-proofs'
import { ASSETS } from '../src/config.ts'
import { buildTree, createNote, treePath } from '../src/crypto.ts'
import { prove, witness } from '../src/prover.ts'

const skip = !existsSync(join(ASSETS, 'tornado_no_zeros.params')) && 'run `uragan setup` first'

test('the wasm prover makes proofs the pinned verifying key accepts', { skip }, async () => {
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
  const vk = stringBigints.decode(JSON.parse(readFileSync(join(ASSETS, 'withdraw_verification_key.json'), 'utf8')))
  const verify = (signals: bigint[]) =>
    bn254.groth.verifyProof(
      vk as never,
      stringBigints.decode({ proof: proof.raw, publicSignals: signals.map(String) }) as never,
    )

  assert.equal(verify(proof.publicSignals), true)
  const otherRecipient = [...proof.publicSignals]
  otherRecipient[2] = 2n
  assert.equal(verify(otherRecipient), false)
})
