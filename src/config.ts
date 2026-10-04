// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, Uragan: https://app.radicle.at/nodes/seed.radicle.at/rad:z3HZ1BVVrNEhRxGb12hn1VeMEPELZ
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import INSTANCES from './instances.json' with { type: 'json' }
import RELAYERS from './relayers.json' with { type: 'json' }

/** A mistake in how the command was invoked -- printed without a stack trace. */
export class UsageError extends Error {}

export const HOME = process.env.URAGAN_HOME ?? join(homedir(), '.local/share/uragan')
/**
 * Circuit and keys sit beside the notes rather than in the checkout: installed
 * from a registry, the checkout is somebody's global node_modules -- often
 * unwritable, and emptied by the next upgrade.
 */
export const ASSETS = process.env.URAGAN_ASSETS ?? join(HOME, 'assets')

/**
 * The first eth_getLogs block range. Sync pages through history with ranges it
 * resizes by what comes back (see syncLeaves), so this only sets where it
 * starts: just under the 10k-block cap most public RPCs have.
 */
export const LOG_CHUNK = Number(process.env.URAGAN_CHUNK ?? 9500)

/**
 * Circuit and keys from tornado-core's v2.1 release, pinned by sha256; setup
 * refuses anything else. Every constant of the verifying key is in the
 * bytecode of the verifier deployed at
 * 0xce172ce1F20EC0B3728c9965470eaf994A03557A, and the proving key makes
 * proofs it accepts (test/prover.test.ts).
 */
export const RELEASE = 'https://github.com/tornadocash/tornado-core/releases/download/v2.1'
export const ARTIFACTS: Record<string, string> = {
  'withdraw.json': '3ddd61dbff09caeec82d8edde95c674a3c34f9e66b1fe9f2c8783e72fe536f98',
  'withdraw_verification_key.json': '3eedcf6ec6b5c24219ed19c7a33966fbfa6a03ae7c84124270589091e87cf8d3',
  'withdraw_proving_key.json': '9b1b2e7aed08ab0cc0c511710331ba2941e03162800e59e39dc65cb5f6f79daf',
}

/**
 * Supported chains, each with the public RPC used unless --rpc-url is given.
 * Not the chains' own endpoints: those cap eth_getLogs at 10k blocks and
 * rate-limit hard. These serve archive logs over wide ranges without a key.
 * `safe` is the chain's EIP-3770 short name, which the Safe Transaction
 * Service and the Safe app address it by.
 */
const CHAINS: Record<number, { name: string; rpc: string; safe: string }> = {
  1: { name: 'Ethereum', rpc: 'https://mainnet.gateway.tenderly.co', safe: 'eth' },
  10: { name: 'Optimism', rpc: 'https://optimism.gateway.tenderly.co', safe: 'oeth' },
  137: { name: 'Polygon', rpc: 'https://polygon.gateway.tenderly.co', safe: 'pol' },
  42161: { name: 'Arbitrum', rpc: 'https://arbitrum.gateway.tenderly.co', safe: 'arb1' },
}

export const chainName = (id: number) => CHAINS[id]?.name ?? `chain ${id}`

/**
 * What the Tornado website and tornado-cli send deposits and withdrawals
 * through, so a transaction to it looks like theirs; a call straight to the
 * pool marks the sender as some other client. On Ethereum it is governance's
 * TornadoRouter, which pulls a token pool's tokens itself. Elsewhere it is
 * TornadoProxyLight, which only forwards ETH -- those chains' pools are native.
 */
const ROUTERS: Record<number, { address: string; tokens: boolean }> = {
  1: { address: '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b', tokens: true },
  10: { address: '0x0D5550d52428E7e3175bfc9550207e4ad3859b17', tokens: false },
  137: { address: '0x0D5550d52428E7e3175bfc9550207e4ad3859b17', tokens: false },
  42161: { address: '0x0D5550d52428E7e3175bfc9550207e4ad3859b17', tokens: false },
}

/** The router for a pool, or undefined where the pool is called directly. */
export function routerFor(p: Pool): string | undefined {
  const r = ROUTERS[p.chainId]
  return r && (r.tokens || !p.tokenAddress) ? r.address : undefined
}

/** The chain's EIP-3770 short name, for the Safe Transaction Service and app. */
export function safePrefix(chainId: number): string {
  const prefix = CHAINS[chainId]?.safe
  if (!prefix) throw new UsageError(`no Safe Transaction Service known for ${chainName(chainId)}`)
  return prefix
}

/** Frame's local JSON-RPC: the signer when neither a key nor --rpc-url is given. */
export const FRAME_RPC = 'http://127.0.0.1:1248'

/** A --chain value: a name (ethereum, optimism, polygon, arbitrum) or a chain id. */
export function parseChain(v: string): number {
  if (/^\d+$/.test(v)) return Number(v)
  const hit = Object.entries(CHAINS).find(([, c]) => c.name.toLowerCase() === v.toLowerCase())
  if (!hit) {
    const names = Object.values(CHAINS)
      .map((c) => c.name.toLowerCase())
      .join(', ')
    throw new UsageError(`unknown chain '${v}' -- ${names}, or a chain id`)
  }
  return Number(hit[0])
}

let rpcOverride: string | undefined

export function setRpcUrl(url: string | undefined): void {
  rpcOverride = url
}

export const customRpc = () => rpcOverride !== undefined

/** --rpc-url if given, else the chain's default. */
export function rpcUrl(chain?: number): string {
  if (rpcOverride !== undefined) return rpcOverride
  const url = chain === undefined ? undefined : CHAINS[chain]?.rpc
  if (!url) {
    const known = Object.entries(CHAINS)
      .map(([id, c]) => `${c.name} (${id})`)
      .join(', ')
    throw new UsageError(`no default RPC for chain ${chain} -- supported: ${known}, or pass --rpc-url`)
  }
  return url
}

export type Pool = {
  /** The chain the pool lives on; anything else touching it is refused. */
  chainId: number
  currency: string
  amount: string
  address: string
  deployedBlock: number
  symbol: string
  decimals: number
  /** null for native-coin pools */
  tokenAddress: string | null
}

/**
 * Pool registry: chain id -> pool name -> pool. Names repeat across chains
 * (eth-0.1 is on Ethereum, Optimism and Arbitrum), so the chain always comes
 * from context -- --chain, --rpc-url's chain, or a note's netId.
 * URAGAN_INSTANCES points it at a fork, testnet, or new deployment.
 */
let parsed: Record<string, Record<string, Omit<Pool, 'chainId'>>> | undefined
function registry(): Record<string, Record<string, Omit<Pool, 'chainId'>>> {
  const file = process.env.URAGAN_INSTANCES
  parsed ??= file ? JSON.parse(readFileSync(file, 'utf8')) : INSTANCES
  return parsed!
}

/** Registry chains that work without --rpc-url. */
export const defaultChains = (): number[] =>
  Object.keys(registry())
    .map(Number)
    .filter((id) => id in CHAINS)

export function pools(chainId: number): Record<string, Pool> {
  const chain = registry()[chainId]
  if (!chain) {
    const known = Object.keys(registry())
      .map((id) => `${chainName(Number(id))} (${id})`)
      .join(', ')
    throw new UsageError(`no pools on chain ${chainId} -- supported: ${known}`)
  }
  return Object.fromEntries(Object.entries(chain).map(([key, p]) => [key, { ...p, chainId }]))
}

export function pool(chainId: number, key: string): Pool {
  const p = pools(chainId)[key]
  if (!p) throw new UsageError(`no pool '${key}' on ${chainName(chainId)} (see: uragan pools)`)
  return p
}

export type Relayer = {
  /** the relayer's ENS name in the registry */
  name: string
  url: string
  /** the address it registered; a relayer reporting another is skipped */
  rewardAccount: string
}

/**
 * Default relayers: chain id -> ENS name -> relayer. From the Tornado relayer
 * registry (0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2 on Ethereum) and each
 * name's <chain>-tornado url record, as of September 2026: staked, answering,
 * and paying fees to the address they registered. Relayers come and go, so a
 * withdrawal re-checks every one before picking.
 */
export function defaultRelayers(chainId: number): Relayer[] {
  const all: Record<string, Record<string, Omit<Relayer, 'name'>>> = RELAYERS
  return Object.entries(all[chainId] ?? {}).map(([name, r]) => ({ name, ...r }))
}
