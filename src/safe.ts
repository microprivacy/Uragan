// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, Uragan: https://app.radicle.at/nodes/seed.radicle.at/rad:z3HZ1BVVrNEhRxGb12hn1VeMEPELZ
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Proposing a transaction to a Safe multisig, after omnipin's
 * src/utils/safe: sign the SafeTx (EIP-712) and post it to the Safe
 * Transaction Service, where the Safe's owners confirm and execute it. The
 * signer must be an owner of the Safe, or a proposer the owners registered.
 */
import { bytesToHex } from '@noble/hashes/utils.js'
import { recoverAddressTyped } from 'micro-eth-signer'
import { createContract } from 'micro-eth-signer/abi.js'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { read } from './chain.ts'
import { chainName, safePrefix, UsageError } from './config.ts'
import type { Signer, TypedData } from './signer.ts'

const SAFE = createContract([
  { type: 'function', name: 'nonce', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint256' }] },
  {
    type: 'function',
    name: 'getTransactionHash',
    stateMutability: 'view',
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'data', type: 'bytes' },
      { name: 'operation', type: 'uint8' },
      { name: 'safeTxGas', type: 'uint256' },
      { name: 'baseGas', type: 'uint256' },
      { name: 'gasPrice', type: 'uint256' },
      { name: 'gasToken', type: 'address' },
      { name: 'refundReceiver', type: 'address' },
      { name: '_nonce', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bytes32' }],
  },
] as const)

const ZERO = '0x0000000000000000000000000000000000000000'

/** Where proposals go; URAGAN_SAFE_TX_SERVICE points at a self-hosted service. */
const SERVICE = process.env.URAGAN_SAFE_TX_SERVICE ?? 'https://api.safe.global/tx-service'

/** SafeTx as Safe 1.3.0+ hashes it: the domain is the chain and the Safe. */
const SAFE_TX_TYPES = {
  EIP712Domain: [
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' },
  ],
  SafeTx: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
    { name: 'operation', type: 'uint8' },
    { name: 'safeTxGas', type: 'uint256' },
    { name: 'baseGas', type: 'uint256' },
    { name: 'gasPrice', type: 'uint256' },
    { name: 'gasToken', type: 'address' },
    { name: 'refundReceiver', type: 'address' },
    { name: 'nonce', type: 'uint256' },
  ],
}

/** The Safe's current nonce -- and the check that `safe` is a Safe on this chain at all. */
export async function safeNonce(net: RpcClient, chainId: number, safe: string): Promise<bigint> {
  try {
    return await read(net, safe, SAFE.nonce)
  } catch {
    throw new UsageError(`${safe} is not a Safe on ${chainName(chainId)}`)
  }
}

/** The Safe's on-chain nonce, and the proposals waiting in its queue from there on. */
export type SafeQueue = { nonce: bigint; queued: { nonce: bigint; data: string }[] }

/** What the Safe Transaction Service holds for the Safe, not yet executed. */
export async function safeQueue(net: RpcClient, chainId: number, safe: string): Promise<SafeQueue> {
  const prefix = safePrefix(chainId)
  const nonce = await safeNonce(net, chainId, safe)
  const queued: SafeQueue['queued'] = []
  let url: string | null =
    `${SERVICE}/${prefix}/api/v1/safes/${safe}/multisig-transactions/?executed=false&nonce__gte=${nonce}&limit=100`
  while (url) {
    const res = await fetch(url, { signal: AbortSignal.timeout(30_000) })
    if (!res.ok) throw new Error(`the Safe Transaction Service would not list the Safe's queue (HTTP ${res.status})`)
    const page = (await res.json()) as {
      next: string | null
      results: { nonce: string | number; data: string | null }[]
    }
    for (const r of page.results) queued.push({ nonce: BigInt(r.nonce), data: (r.data ?? '0x').toLowerCase() })
    url = page.next
  }
  return { nonce, queued }
}

/** The queued proposal whose calldata carries `value` as a 32-byte word: a nullifier hash, say. */
export const queuedWith = (q: SafeQueue, value: bigint) =>
  q.queued.find((t) => t.data.includes(value.toString(16).padStart(64, '0')))

/**
 * The nonce for a new proposal: after everything queued. One at a nonce a
 * queued proposal holds could only ever replace it.
 */
export const nextNonce = (q: SafeQueue) => q.queued.reduce((n, t) => (t.nonce >= n ? t.nonce + 1n : n), q.nonce)

export type SafeCall = { to: string; value: bigint; data: Uint8Array }

/**
 * The SafeTx for a plain call at `nonce`, and its hash as the Safe itself
 * computes it. The call is simulated from the Safe first -- on today's state,
 * not on what proposals queued before it would leave -- so one that would
 * revert is refused before anyone signs.
 */
export async function prepareSafeTx(
  net: RpcClient,
  chainId: number,
  safe: string,
  call: SafeCall,
  nonce: bigint,
): Promise<{ typed: TypedData; safeTxHash: string }> {
  const data = `0x${bytesToHex(call.data)}`
  const sim = await net.dryRun({ from: safe, to: call.to, value: call.value, data })
  if (!sim.success) throw new UsageError(`executed by the Safe, the call would revert: ${sim.reason}`)
  const hash = await read(net, safe, SAFE.getTransactionHash, {
    to: call.to,
    value: call.value,
    data: call.data,
    operation: 0n,
    safeTxGas: 0n,
    baseGas: 0n,
    gasPrice: 0n,
    gasToken: ZERO,
    refundReceiver: ZERO,
    _nonce: nonce,
  })
  const message = {
    to: call.to,
    value: call.value,
    data,
    operation: 0,
    safeTxGas: 0n,
    baseGas: 0n,
    gasPrice: 0n,
    gasToken: ZERO,
    refundReceiver: ZERO,
    nonce,
  }
  const typed = {
    types: SAFE_TX_TYPES,
    primaryType: 'SafeTx',
    domain: { chainId: BigInt(chainId), verifyingContract: safe },
    message,
  }
  return { typed, safeTxHash: `0x${bytesToHex(hash)}` }
}

/**
 * Sign the SafeTx and post it to the Safe Transaction Service. Returns the
 * Safe app's queue, where the owners confirm and execute it.
 */
export async function proposeSafeTx(o: {
  net: RpcClient
  chainId: number
  safe: string
  signer: Signer
  call: SafeCall
  nonce: bigint
}): Promise<{ safeTxHash: string; queue: string }> {
  const prefix = safePrefix(o.chainId)
  const { typed, safeTxHash } = await prepareSafeTx(o.net, o.chainId, o.safe, o.call, o.nonce)
  let signature = await o.signer.signTyped(typed)
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature))
    throw new Error(`the signer returned a malformed signature: ${signature}`)
  // Some hardware wallets return v as 0/1; a Safe reads v above 30 as an eth_sign signature.
  const v = Number.parseInt(signature.slice(-2), 16)
  if (v < 27) signature = `${signature.slice(0, -2)}${(v + 27).toString(16)}`
  const signedBy = recoverAddressTyped(signature, typed as never)
  if (signedBy.toLowerCase() !== o.signer.address.toLowerCase()) {
    throw new Error(`the SafeTx came back signed by ${signedBy}, not ${o.signer.address}`)
  }

  const { to, value, data, operation, safeTxGas, baseGas, gasPrice, nonce } = typed.message
  const res = await fetch(`${SERVICE}/${prefix}/api/v1/safes/${o.safe}/multisig-transactions/`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(
      {
        to,
        value,
        data,
        operation,
        safeTxGas,
        baseGas,
        gasPrice,
        nonce,
        contractTransactionHash: safeTxHash,
        sender: o.signer.address,
        signature,
        origin: 'Uragan',
      },
      (_k, v) => (typeof v === 'bigint' ? v.toString() : v),
    ),
  })
  // The service answers in JSON, but proxy and error pages (502s, rate
  // limits) come back as HTML; read text so those still say something useful.
  const text = await res.text()
  if (!res.ok) {
    let why = text.slice(0, 300)
    try {
      const json = JSON.parse(text) as { message?: string; detail?: string }
      why = json.message ?? json.detail ?? text
    } catch {
      // not JSON; the raw text it is
    }
    throw new Error(`the Safe Transaction Service refused the proposal (HTTP ${res.status}): ${why}`)
  }
  return { safeTxHash, queue: `https://app.safe.global/transactions/queue?safe=${prefix}:${o.safe}` }
}
