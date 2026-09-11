/**
 * Witness generation and Groth16 proving, both micro-zk-proofs.
 *
 * Tornado's proving key came out of bellman, which builds its FFT domain from
 * the generator 7. noble defaults to the smallest non-residue, 5: a different
 * root of unity, so H -- and with it pi_c -- comes out wrong and the verifier
 * rejects the proof. Hence nqr: 7.
 */
import { readFileSync } from 'node:fs'
import { availableParallelism } from 'node:os'
import { join } from 'node:path'
// The copy micro-zk-proofs' MSM workers load; package.json pins the same range.
// Points from another copy fail its instanceof checks.
import { bn254 } from '@noble/curves/bn254.js'
import { buildSnark, type GrothProof, type ProvingKey, stringBigints } from 'micro-zk-proofs'
import { initMSM } from 'micro-zk-proofs/msm.js'
import { generateWitness } from 'micro-zk-proofs/witness.js'
import { ASSETS } from './config.ts'

const readJson = (name: string) => JSON.parse(readFileSync(join(ASSETS, name), 'utf8'))

/** Compute the witness for the withdraw circuit. */
export function witness(input: Record<string, unknown>): bigint[] {
  return generateWitness(readJson('withdraw.json'))(input)
}

export type Proof = {
  /** 256 bytes, packed the way the Solidity verifier reads it */
  proof: `0x${string}`
  publicSignals: bigint[]
  /** unpacked, for off-chain verification */
  raw: GrothProof
}

/**
 * websnark's Solidity packing: a0 a1 b01 b00 b11 b10 c0 c1. The G2 coordinates
 * are swapped; the naive order is not on the curve and reverts.
 */
function packProof(p: GrothProof): `0x${string}` {
  const words = [p.pi_a[0], p.pi_a[1], p.pi_b[0][1], p.pi_b[0][0], p.pi_b[1][1], p.pi_b[1][0], p.pi_c[0], p.pi_c[1]]
  return `0x${words.map((w) => w.toString(16).padStart(64, '0')).join('')}`
}

export async function prove(wit: bigint[], threads: number = availableParallelism()): Promise<Proof> {
  const pkey = stringBigints.decode(readJson('withdraw_proving_key.json')) as ProvingKey
  // One thread proves right here. More start micro-zk-proofs' MSM pool -- a
  // worker per core -- and split each MSM over `threads` of them.
  const msm = threads > 1 ? initMSM() : undefined
  try {
    const { groth } = buildSnark(bn254, {
      nqr: 7,
      ...(msm && {
        G1msm: (input) => msm.methods.bn254_msmG1(input, threads),
        G2msm: (input) => msm.methods.bn254_msmG2(input, threads),
      }),
    })
    // Draws the blinding factors r and s -- what makes the proof zero-knowledge.
    const { proof, publicSignals } = await groth.createProof(pkey, wit)
    return { proof: packProof(proof), publicSignals, raw: proof }
  } finally {
    msm?.terminate()
  }
}
