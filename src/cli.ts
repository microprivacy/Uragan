#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, Uragan: https://app.radicle.at/nodes/seed.radicle.at/rad:z3HZ1BVVrNEhRxGb12hn1VeMEPELZ
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * uragan -- a Tornado Cash client.
 *
 * TypeScript run directly by Node (types are stripped at load). Chain access
 * and signing via micro-eth-signer; zk primitives, witnesses and Groth16
 * proofs via micro-zk-proofs.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { availableParallelism } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { parseArgs } from 'node:util'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { addr } from 'micro-eth-signer'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { ADDRESS_ZERO, formatUnits, parseUnits } from 'micro-eth-signer/utils.js'
import {
  assertChain,
  bytes32,
  cachedLeaves,
  dropCache,
  ERC20,
  poolTree,
  read,
  rpc,
  switchChain,
  syncLeaves,
  TORNADO,
  VERIFIER,
} from './chain.ts'
import {
  ARTIFACTS,
  ASSETS,
  chainName,
  customRpc,
  defaultChains,
  defaultRelayers,
  FRAME_RPC,
  HOME,
  type Pool,
  parseChain,
  pool,
  pools,
  RELEASE,
  type Relayer,
  rpcUrl,
  safePrefix,
  setRpcUrl,
  UsageError,
} from './config.ts'
import { assertPrimitives, createNote, hex32, type Note, parseNote, treePath } from './crypto.ts'
import { prove, witness } from './prover.ts'
import { proposeSafeTx, safeNonce } from './safe.ts'
import { makeSigner, type SignerOpts } from './signer.ts'

const log = (s: string) => process.stderr.write(`${s}\n`)
const out = (s: string) => process.stdout.write(`${s}\n`)
// `uragan pools | head`: the reader left, which is not an error.
process.stdout.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EPIPE') process.exit(0)
  throw e
})
const hexBytes = (b: Uint8Array) => `0x${bytesToHex(b)}`
const fromHex = (h: string) => hexToBytes(h.slice(2))

/**
 * The note in the argument, or on stdin when the argument is `-` -- which
 * keeps it out of argv and shell history. Only `-` reads stdin: a command run
 * with stdin left open (ssh without -t, a loop reading a file) must not hang
 * on it, or swallow what it carries.
 */
async function requireNote(arg: string | undefined): Promise<string> {
  if (arg === undefined) throw new UsageError('pass a note, or `-` and pipe it on stdin')
  if (arg !== '-') return arg
  if (process.stdin.isTTY) throw new UsageError('`-` reads the note from stdin, but nothing is piped in')
  let s = ''
  for await (const chunk of process.stdin) s += chunk
  if (!s.trim()) throw new UsageError('stdin was empty -- pipe the note in')
  return s.trim()
}

/**
 * EIP-55: a mixed-case address must carry a valid checksum. A typo'd recipient
 * is bound into the proof and receives the funds irreversibly, so it must be
 * rejected, never "corrected" by re-checksumming.
 */
function checksummed(a: string): string {
  if (!addr.isValid(a)) {
    const hex = /^0x[0-9a-fA-F]{40}$/.test(a)
    throw new UsageError(hex ? `${a} fails its EIP-55 checksum -- probably a typo` : `not an address: ${a}`)
  }
  return addr.addChecksum(a)
}

/** A whole number of base units (wei), or undefined if the flag was not given. */
function baseUnits(flag: string, v: string | undefined): bigint | undefined {
  if (v === undefined) return undefined
  if (!/^\d+$/.test(v)) throw new UsageError(`--${flag} must be a whole number of base units (wei), got '${v}'`)
  return BigInt(v)
}

function intFlag(flag: string, v: string | undefined, fallback: number, min: number, max: number): number {
  if (v === undefined) return fallback
  const n = Number(v)
  if (!/^\d+$/.test(v) || n < min || n > max)
    throw new UsageError(`--${flag} must be an integer from ${min} to ${max}, got '${v}'`)
  return n
}

/**
 * The pool a note belongs to, on the chain the note was made for. A note names
 * its currency, which is not always the registry key: Polygon's pools are
 * keyed pol-100 after the token's rename, while their notes still say matic,
 * the string every other Tornado client reads and writes.
 */
function notePool(n: { currency: string; amount: string; netId: number }): [string, Pool] {
  const hit = Object.entries(pools(n.netId)).find(
    ([, p]) => p.currency.toLowerCase() === n.currency && p.amount === n.amount,
  )
  if (!hit) throw new UsageError(`no pool for ${n.currency} ${n.amount} on ${chainName(n.netId)} (see: uragan pools)`)
  return hit
}

/**
 * An RPC client and the chain it serves. The chain is `chain` if known (a
 * note's, or --chain); else --rpc-url's own; else Ethereum. The RPC is
 * --rpc-url if given, else that chain's public default -- checked either way.
 * `wallet`: a command about to transact asks an --rpc-url wallet on another
 * chain to switch, where anything else is refused.
 */
async function connect(chain?: number, { wallet = false } = {}): Promise<{ net: RpcClient; chainId: number }> {
  if (chain === undefined && customRpc()) {
    const net = rpc(rpcUrl())
    return { net, chainId: Number(await net.chainId()) }
  }
  const chainId = chain ?? 1
  const net = rpc(rpcUrl(chainId))
  await (wallet && customRpc() ? switchChain(net, chainId) : assertChain(net, chainId))
  return { net, chainId }
}

/** A pool by name: on --chain, or the chain --rpc-url is on, or Ethereum. */
async function connectPool(key: string, chain?: number, o = { wallet: false }): Promise<{ net: RpcClient; p: Pool }> {
  const { net, chainId } = await connect(chain, o)
  return { net, p: pool(chainId, key) }
}

/** Refuse to send money to an address that is not the pool the registry claims. */
async function assertPool(net: RpcClient, p: Pool, key: string) {
  let denomination: bigint
  try {
    denomination = await read(net, p.address, TORNADO.denomination)
  } catch {
    throw new UsageError(`no Tornado pool at ${p.address} on ${chainName(p.chainId)} (registry entry ${key})`)
  }
  if (denomination !== parseUnits(p.amount, p.decimals)) {
    throw new UsageError(`${p.address} has denomination ${denomination}, not ${p.amount} ${p.symbol}`)
  }
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------
async function setup() {
  mkdirSync(ASSETS, { recursive: true })
  for (const [name, want] of Object.entries(ARTIFACTS)) {
    const file = join(ASSETS, name)
    if (existsSync(file) && bytesToHex(sha256(readFileSync(file))) === want) {
      log(`have ${name}`)
      continue
    }
    log(`downloading ${name} ...`)
    const res = await fetch(`${RELEASE}/${name}`)
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`)
    const bytes = new Uint8Array(await res.arrayBuffer())
    const got = bytesToHex(sha256(bytes))
    if (got !== want) throw new Error(`${name}: sha256 ${got} does not match the pinned ${want} -- refusing it`)
    writeFileSync(file, bytes)
  }
}

// ---------------------------------------------------------------------------
// pools / verify
// ---------------------------------------------------------------------------

/** The chains `pools` and `verify` cover: the one --chain or --rpc-url names, else all. */
async function networks(chain?: number) {
  if (chain !== undefined || customRpc()) return [await connect(chain)]
  return Promise.all(defaultChains().map((id) => connect(id)))
}

/** Decode a multicall result; undefined when the call failed or hit an address with no code. */
function decoded<T>(r: { success: boolean; data: string }, decode: (b: Uint8Array) => T): T | undefined {
  return r.success && r.data !== '0x' ? decode(fromHex(r.data)) : undefined
}

async function poolsCmd(chain?: number) {
  for (const [c, { net, chainId }] of (await networks(chain)).entries()) {
    const entries = Object.entries(pools(chainId))
    const res = await net.multicall(
      entries.map(([, p]) => ({ to: p.address, data: hexBytes(TORNADO.nextIndex.encodeInput()), allowFailure: true })),
    )
    out(`${c ? '\n' : ''}${chainName(chainId)}`)
    out(`${'POOL'.padEnd(14)} ${'ADDRESS'.padEnd(42)} ${'DEPOSITS'.padStart(9)}`)
    entries.forEach(([key, p], i) => {
      const n = decoded(res[i]!, (b) => TORNADO.nextIndex.decodeOutput(b))
      out(`${key.padEnd(14)} ${p.address.padEnd(42)} ${(n === undefined ? 'no pool' : String(n)).padStart(9)}`)
    })
  }
}

/** Re-check every pool against the chain. A pool with no code is exactly what this is for. */
async function verifyCmd(chain?: number) {
  let bad = 0
  let total = 0
  for (const { net, chainId } of await networks(chain)) {
    const entries = Object.entries(pools(chainId))
    const res = await net.multicall(
      entries.flatMap(([, p]) => [
        { to: p.address, data: hexBytes(TORNADO.denomination.encodeInput()), allowFailure: true },
        { to: p.address, data: hexBytes(TORNADO.levels.encodeInput()), allowFailure: true },
      ]),
    )
    out(chainName(chainId))
    for (const [i, [key, p]] of entries.entries()) {
      total++
      const denom = decoded(res[2 * i]!, (b) => TORNADO.denomination.decodeOutput(b))
      const levels = decoded(res[2 * i + 1]!, (b) => TORNADO.levels.decodeOutput(b))
      const want = parseUnits(p.amount, p.decimals)
      if (denom === want && Number(levels) === 20) {
        out(`  ${key.padEnd(14)} OK`)
        continue
      }
      bad++
      out(
        denom === undefined
          ? `  ${key.padEnd(14)} MISMATCH no Tornado pool at ${p.address}`
          : `  ${key.padEnd(14)} MISMATCH denomination=${denom} want=${want} levels=${levels}`,
      )
    }
  }
  if (bad) throw new Error(`${bad} pool(s) DO NOT match the chain -- do not use them`)
  log(`all ${total} pools verified`)
}

// ---------------------------------------------------------------------------
// note / deposit / sync / status
// ---------------------------------------------------------------------------
async function noteCmd(key: string | undefined, chain?: number) {
  if (!key) throw new UsageError('usage: uragan note <pool>')
  // Offline unless --rpc-url is given, in which case its chain decides.
  const p = pool(customRpc() ? (await connect(chain)).chainId : (chain ?? 1), key)
  out(createNote(p.currency, p.amount, p.chainId).note)
}

/** Where `deposit` saves notes, and what `status` reads without an argument. */
const notesDir = () => join(HOME, 'notes')

/** Save a note in notesDir() unless a file there holds it already; the file it is in. */
function saveNote(n: Note, p: Pool, key: string): { file: string; fresh: boolean } {
  const dir = notesDir()
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const have = readdirSync(dir).find((f) => f.endsWith('.txt') && readFileSync(join(dir, f), 'utf8').trim() === n.note)
  if (have) return { file: join(dir, have), fresh: false }
  const stamp = new Date().toISOString().replace(/[:.]/g, '')
  const file = join(dir, `${stamp}-${chainName(p.chainId).toLowerCase()}-${key}.txt`)
  writeFileSync(file, `${n.note}\n`, { mode: 0o600, flag: 'wx' })
  return { file, fresh: true }
}

/**
 * The pool a deposit goes into. With --note it is the note's own -- a note
 * names its chain, currency and amount -- and <pool> and --chain, needless
 * then, must agree with it: the same pool address can be another chain's pool.
 */
async function depositPool(
  key: string | undefined,
  chain: number | undefined,
  existing: Note | undefined,
): Promise<{ net: RpcClient; p: Pool; key: string }> {
  if (!existing) {
    if (!key) throw new UsageError('usage: uragan deposit <pool>, or uragan deposit --note <note|->')
    return { ...(await connectPool(key, chain, { wallet: true })), key }
  }
  const [name, p] = notePool(existing)
  const where = `${name} on ${chainName(p.chainId)}`
  if (key !== undefined && key !== name) throw new UsageError(`that note is for ${where}, not ${key}`)
  if (chain !== undefined && chain !== p.chainId)
    throw new UsageError(`that note is for ${where}, not ${chainName(chain)}`)
  return { net: (await connect(p.chainId, { wallet: true })).net, p, key: name }
}

async function deposit(keyArg: string | undefined, chain: number | undefined, sig: SignerOpts, noteArg?: string) {
  // --note deposits a note you already hold -- from an attempt that never
  // landed, or made offline by `uragan note` -- instead of making another.
  const existing = noteArg === undefined ? undefined : parseNote(await requireNote(noteArg))
  // Nothing on-chain checks a commitment: one from a broken hash could never
  // be withdrawn. So the self-check guards a note passed in, as it does a new one.
  assertPrimitives()
  const { net, p, key } = await depositPool(keyArg, chain, existing)
  await assertPool(net, p, key)
  if (existing && (await read(net, p.address, TORNADO.commitments, bytes32(existing.commitment)))) {
    throw new UsageError('that note is deposited already -- `uragan status` says whether it is still unspent')
  }
  const signer = await makeSigner(net, p.chainId, sig)
  const amount = parseUnits(p.amount, p.decimals)

  if (p.tokenAddress) {
    const allowance = await read(net, p.tokenAddress, ERC20.allowance, { owner: signer.address, spender: p.address })
    if (allowance < amount) {
      // USDT, among others, reverts when one non-zero allowance is changed to
      // another; a deposit that failed after approving leaves exactly that.
      if (allowance > 0n) {
        log(`resetting the ${p.symbol} allowance to 0 first ...`)
        await signer.send({ to: p.tokenAddress, data: ERC20.approve.encodeInput({ spender: p.address, amount: 0n }) })
      }
      log(`approving ${p.amount} ${p.symbol} ...`)
      await signer.send({ to: p.tokenAddress, data: ERC20.approve.encodeInput({ spender: p.address, amount }) })
    }
  }

  const n = existing ?? createNote(p.currency, p.amount, p.chainId)
  const call = {
    to: p.address,
    value: p.tokenAddress ? 0n : amount,
    data: TORNADO.deposit.encodeInput(bytes32(n.commitment)),
  }
  // Dry-run first, so an empty balance or a bad allowance fails before a note exists.
  try {
    await net.estimateGas({
      from: signer.address,
      to: call.to,
      value: `0x${call.value.toString(16)}`,
      data: hexBytes(call.data),
    })
  } catch (e) {
    throw new UsageError(`the deposit would fail, nothing was sent: ${(e as Error).message}`)
  }

  // Persist the note BEFORE broadcasting. A funded deposit whose note is lost
  // is unrecoverable; an orphan note for a failed deposit is harmless. A note
  // passed with --note counts too: piped from `uragan note`, it is nowhere else.
  const saved = saveNote(n, p, key)
  if (!existing) out(n.note)
  log(
    saved.fresh
      ? `note saved to ${saved.file} -- back it up. Without it the funds are GONE.`
      : `the note is saved already, in ${saved.file}`,
  )

  log(`depositing ${p.amount} ${p.symbol} into ${p.address} from ${signer.address} ...`)
  try {
    log(`deposited: ${await signer.send(call)}`)
  } catch (e) {
    throw new Error(`deposit failed or unconfirmed: ${(e as Error).message}\n  check with: uragan status <note>`)
  }
}

async function syncCmd(key: string | undefined, chain?: number) {
  if (!key) throw new UsageError('usage: uragan sync <pool>')
  const { net, p } = await connectPool(key, chain)
  const leaves = await syncLeaves(net, p, log)
  log(`${key}: ${leaves.length} leaves cached`)
}

/**
 * Every saved note at a glance -- mostly: is anything still unspent? Each
 * note's commitment and nullifier hash goes to the chain's RPC, which sees the
 * whole set in one session; point --rpc-url at your own node if that matters.
 */
async function statusAll() {
  const dir = notesDir()
  const files = (existsSync(dir) ? readdirSync(dir) : []).filter((f) => f.endsWith('.txt')).sort()
  if (!files.length) throw new UsageError(`no notes in ${dir} -- pass a note, or \`-\` and pipe it on stdin`)

  type Readable = { file: string; key: string; pool: Pool; note: Note; state: string }
  const readable: Readable[] = []
  const rows = files.map((file): Readable | { file: string; unreadable: string } => {
    try {
      const note = parseNote(readFileSync(join(dir, file), 'utf8').trim())
      const [key, pool] = notePool(note)
      const r = { file, key, pool, note, state: 'unknown' }
      readable.push(r)
      return r
    } catch (e) {
      return { file, unreadable: (e as Error).message }
    }
  })

  // Two reads a note, batched into one multicall per chain, all chains at
  // once. A chain that fails leaves its notes unknown; the rest still print.
  const chains = [...new Set(readable.map((r) => r.pool.chainId))]
  const results = await Promise.allSettled(
    chains.map(async (chainId) => {
      const mine = readable.filter((r) => r.pool.chainId === chainId)
      const { net } = await connect(chainId)
      const res = await net.multicall(
        mine.flatMap((r) => [
          {
            to: r.pool.address,
            data: hexBytes(TORNADO.commitments.encodeInput(bytes32(r.note.commitment))),
            allowFailure: true,
          },
          {
            to: r.pool.address,
            data: hexBytes(TORNADO.isSpent.encodeInput(bytes32(r.note.nullifierHash))),
            allowFailure: true,
          },
        ]),
      )
      mine.forEach((r, i) => {
        const deposited = decoded(res[2 * i]!, (b) => TORNADO.commitments.decodeOutput(b))
        const spent = decoded(res[2 * i + 1]!, (b) => TORNADO.isSpent.decodeOutput(b))
        if (deposited === undefined || spent === undefined) return // stays unknown
        r.state = !deposited ? 'not deposited' : spent ? 'spent' : 'unspent'
      })
    }),
  )
  results.forEach((r, i) => {
    if (r.status === 'rejected') {
      log(`${chainName(chains[i]!)}: ${(r.reason as Error).message} -- its notes show as unknown`)
    }
  })

  const width = Math.max(4, ...files.map((f) => f.length))
  out(`${'NOTE'.padEnd(width)} ${'POOL'.padEnd(14)} ${'CHAIN'.padEnd(10)} STATE`)
  for (const r of rows) {
    out(
      'unreadable' in r
        ? `${r.file.padEnd(width)} ${'?'.padEnd(14)} ${'?'.padEnd(10)} unreadable: ${r.unreadable}`
        : `${r.file.padEnd(width)} ${r.key.padEnd(14)} ${chainName(r.pool.chainId).padEnd(10)} ${r.state}`,
    )
  }
  const count = (state: string) => readable.filter((r) => r.state === state).length
  log(
    `${rows.length} notes in ${dir}: ${count('unspent')} unspent, ${count('spent')} spent, ` +
      `${count('not deposited')} never deposited`,
  )
}

async function status(noteArg: string | undefined) {
  // No note: every saved note. Stdin is read only for `-`.
  if (noteArg === undefined) return statusAll()
  const n = parseNote(await requireNote(noteArg))
  const [key, p] = notePool(n)
  const { net } = await connect(p.chainId)
  const [deposited, spent, total] = await Promise.all([
    read(net, p.address, TORNADO.commitments, bytes32(n.commitment)),
    read(net, p.address, TORNADO.isSpent, bytes32(n.nullifierHash)),
    read(net, p.address, TORNADO.nextIndex),
  ])
  out(`pool          ${key} on ${chainName(p.chainId)}  (${p.address})`)
  out(`commitment    ${hex32(n.commitment)}`)
  out(`nullifierHash ${hex32(n.nullifierHash)}`)
  out(`deposited     ${deposited}`)
  out(`spent         ${spent}`)
  out(`anonymity set ${total} deposits`)
  const idx = [...cachedLeaves(p)].find(([, c]) => c === n.commitment)?.[0]
  if (idx !== undefined) out(`leaf index    ${idx}  (${Number(total) - idx - 1} deposits since)`)
  else if (deposited)
    log(`(run \`uragan sync ${key} --chain ${chainName(p.chainId).toLowerCase()}\` to see the leaf index)`)
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------
type RelayerStatus = {
  rewardAccount: string
  netId?: number
  tornadoServiceFee?: number | string
  ethPrices?: Record<string, string>
  health?: { status?: string | boolean }
}

const relayerBase = (url: string) => url.replace(/\/$/, '')

async function relayerStatus(url: string): Promise<RelayerStatus> {
  const res = await fetch(`${relayerBase(url)}/status`, { signal: AbortSignal.timeout(10_000) })
  if (!res.ok) throw new Error(`relayer ${url}: HTTP ${res.status}`)
  return (await res.json()) as RelayerStatus
}

/**
 * The cheapest default relayer for a chain that answers, serves that chain,
 * reports itself healthy, and pays fees to the account it registered. A
 * random one among equals, so withdrawals do not all land on one relayer.
 */
async function pickRelayer(chainId: number): Promise<Relayer & { st: RelayerStatus }> {
  const all = defaultRelayers(chainId)
  if (!all.length)
    throw new UsageError(`no default relayers for ${chainName(chainId)} -- pass --relayer URL, or --self`)
  const usable = (
    await Promise.all(
      all.map(async (r) => {
        const st = await relayerStatus(r.url).catch(() => undefined)
        const cut = Number(st?.tornadoServiceFee)
        const ok =
          st &&
          Number(st.netId) === chainId &&
          String(st.health?.status) === 'true' &&
          st.rewardAccount?.toLowerCase() === r.rewardAccount.toLowerCase() &&
          Number.isFinite(cut)
        return ok ? { ...r, st, cut } : undefined
      }),
    )
  ).filter((r) => r !== undefined)
  if (!usable.length) {
    throw new UsageError(
      `none of the ${all.length} default relayers for ${chainName(chainId)} is usable right now -- pass --relayer URL, or --self`,
    )
  }
  const min = Math.min(...usable.map((r) => r.cut))
  const cheapest = usable.filter((r) => r.cut === min)
  return cheapest[Math.floor(Math.random() * cheapest.length)]!
}

/** tornado-cli's fee formula: 500k gas at the current price, plus the relayer's cut of the amount. */
function relayerFee(p: Pool, st: RelayerStatus, gasPrice: bigint, refund: bigint): bigint {
  const amount = parseUnits(p.amount, p.decimals)
  const cut = Number(st.tornadoServiceFee ?? 0)
  if (!Number.isFinite(cut) || cut < 0)
    throw new UsageError(`relayer advertises a nonsensical fee: ${st.tornadoServiceFee}`)
  const feePercent = (amount * BigInt(Math.round(cut * 1e6))) / 100_000_000n
  const expense = gasPrice * 500_000n
  if (!p.tokenAddress) return expense + feePercent
  const price = st.ethPrices?.[p.currency]
  if (!price || !/^\d+$/.test(price) || BigInt(price) === 0n) {
    throw new UsageError(`relayer publishes no usable ETH price for ${p.currency}; pass --fee`)
  }
  return ((expense + refund) * 10n ** BigInt(p.decimals)) / BigInt(price) + feePercent
}

type Job = { status?: string; txHash?: string; failedReason?: string; error?: string }

/**
 * Submit to a relayer and wait until the chain -- not the relayer -- says the
 * note is spent. tornado-relayer reports MINED before it checks whether the
 * transaction reverted, so its word is never taken as success.
 */
async function submitViaRelayer(
  net: RpcClient,
  p: Pool,
  url: string,
  body: object,
  nullifierHash: bigint,
): Promise<string> {
  const spent = () => read(net, p.address, TORNADO.isSpent, bytes32(nullifierHash))
  const base = relayerBase(url)

  const res = await fetch(`${base}/v1/tornadoWithdraw`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  })
  const text = await res.text()
  let reply: { id?: string; error?: string } = {}
  try {
    reply = JSON.parse(text)
  } catch {
    // not JSON; reported below
  }
  if (!res.ok || !reply.id) {
    throw new Error(`relayer rejected the withdrawal (HTTP ${res.status}): ${reply.error ?? text.slice(0, 300)}`)
  }
  log(`relayer job ${reply.id}`)

  const deadline = Date.now() + 30 * 60_000
  let unreachable = 0
  let last = ''
  try {
    while (Date.now() < deadline) {
      await sleep(3000)
      let job: Job
      try {
        const r = await fetch(`${base}/v1/jobs/${reply.id}`, { signal: AbortSignal.timeout(15_000) })
        job = (await r.json()) as Job
        if (!r.ok) throw new Error(job.error ?? `HTTP ${r.status}`)
        unreachable = 0
      } catch {
        // An unreachable relayer says nothing about the job; the chain decides below.
        if (++unreachable >= 10) break
        continue
      }
      if (job.status !== last) {
        last = job.status ?? '?'
        process.stderr.write(`\r  relayer: ${last}          `)
      }
      if (job.status === 'FAILED') {
        if (await spent()) return job.txHash ?? '(spent; relayer reported failure)'
        throw new Error(`relayer failed: ${job.failedReason ?? 'no reason given'} -- the note is NOT spent`)
      }
      // Look, don't wait: a relayer that bumps gas replaces the transaction,
      // and the job then carries the new hash.
      if (job.txHash && (job.status === 'MINED' || job.status === 'CONFIRMED')) {
        const receipt = (await net.call('eth_getTransactionReceipt', job.txHash)) as { status: string } | null
        if (receipt) {
          const ok = BigInt(receipt.status) === 1n
          const isSpent = await spent()
          if (ok && isSpent) return job.txHash
          if (!ok && isSpent) return `(spent by another transaction; the relayer's ${job.txHash} reverted)`
          if (!ok) throw new Error(`the relayer's transaction ${job.txHash} reverted -- the note is NOT spent`)
        }
      }
    }
  } finally {
    if (last) process.stderr.write('\n')
  }
  if (await spent()) return '(spent; the relayer never reported the transaction)'
  throw new Error(
    `could not confirm job ${reply.id} with ${base}. The note is not spent yet -- check \`uragan status\` before retrying.`,
  )
}

type WithdrawOpts = SignerOpts & {
  relayer?: string
  fee?: string
  refund?: string
  maxFeePercent: number
  self?: boolean
  safe?: string
  dryRun?: boolean
  threads: number
}

async function withdraw(noteArg: string | undefined, recipientArg: string | undefined, o: WithdrawOpts) {
  if (!recipientArg) {
    throw new UsageError('usage: uragan withdraw <note|-> <recipient> [--relayer URL | --self | --safe SAFE]')
  }
  if ([o.relayer, o.self, o.safe].filter(Boolean).length > 1) {
    throw new UsageError('--relayer, --self and --safe are exclusive')
  }
  // With --safe the Safe sends the withdrawal, and the signer only proposes it.
  const safe = o.safe === undefined ? undefined : checksummed(o.safe)
  const explicitFee = baseUnits('fee', o.fee)
  const refund = baseUnits('refund', o.refund) ?? 0n
  if (explicitFee !== undefined && (o.self || safe)) {
    throw new UsageError('--fee only applies with a relayer; with --self or --safe there is no one to pay')
  }

  const n = parseNote(await requireNote(noteArg))
  const recipient = checksummed(recipientArg)
  const [, p] = notePool(n)
  // The contract requires msg.value == refund; ETH pools only accept 0.
  if (refund !== 0n && !p.tokenAddress) throw new UsageError('ETH pools require --refund 0 (refund is for token pools)')
  const amount = parseUnits(p.amount, p.decimals)
  const { net } = await connect(p.chainId, { wallet: true })
  // Resolve a --self or --safe signer, and the Safe, before syncing and
  // proving, so a misconfiguration fails in a second rather than after all that work.
  const signer = (o.self || safe) && !o.dryRun ? await makeSigner(net, p.chainId, o) : undefined
  if (safe) {
    safePrefix(p.chainId)
    await safeNonce(net, p.chainId, safe)
  }

  const [spent, deposited] = await Promise.all([
    read(net, p.address, TORNADO.isSpent, bytes32(n.nullifierHash)),
    read(net, p.address, TORNADO.commitments, bytes32(n.commitment)),
  ])
  if (spent) throw new UsageError('note already spent')
  if (!deposited) throw new UsageError('commitment not on chain -- was the deposit mined?')

  let relayer = ADDRESS_ZERO
  let fee = 0n
  let relayerUrl: string | undefined
  if (!o.self && !safe) {
    let st: RelayerStatus
    if (o.relayer) {
      relayerUrl = o.relayer
      st = await relayerStatus(o.relayer)
    } else {
      const picked = await pickRelayer(p.chainId)
      relayerUrl = picked.url
      st = picked.st
      log(`picked ${picked.name} (${picked.url}), the cheapest default relayer answering`)
    }
    if (st.netId !== undefined && Number(st.netId) !== p.chainId) {
      throw new UsageError(
        `relayer ${relayerUrl} serves ${chainName(Number(st.netId))} (${st.netId}), but this note is for ${chainName(p.chainId)} (${p.chainId})`,
      )
    }
    relayer = checksummed(st.rewardAccount)
    if (explicitFee !== undefined) {
      fee = explicitFee
    } else {
      const fees = await net.fees()
      fee = relayerFee(p, st, fees.type === 'eip1559' ? fees.maxFeePerGas : fees.gasPrice, refund)
      // The inputs to that formula are the relayer's own claims. Refuse a fee
      // above the cap unless the user raises it knowingly.
      const bps = (fee * 10_000n) / amount
      if (bps > BigInt(Math.round(o.maxFeePercent * 100))) {
        const pct = (Number(bps) / 100).toFixed(2)
        throw new UsageError(
          `relayer fee ${formatUnits(fee, p.decimals)} ${p.symbol} is ${pct}% of the amount, above --max-fee-percent ` +
            `${o.maxFeePercent}. Pass --max-fee-percent ${Math.ceil(Number(pct))} to accept it, or set --fee yourself.`,
        )
      }
    }
    if (fee >= amount) throw new UsageError(`relayer fee ${fee} is not below the amount ${amount}`)
    log(
      `relayer ${relayer}, fee ${formatUnits(fee, p.decimals)} ${p.symbol} (${(Number((fee * 10_000n) / amount) / 100).toFixed(2)}%)`,
    )
  }

  // The contract accepts only its last 100 roots. If ours is not among them the
  // leaf set is wrong -- a reorg deeper than sync re-scans, or a damaged cache
  // -- and submitting would burn gas on a guaranteed revert. Start over, once.
  const known = (root: bigint) => read(net, p.address, TORNADO.isKnownRoot, bytes32(root))
  let tree = await poolTree(net, p, log)
  if (!(await known(tree.root))) {
    log(`computed root ${hex32(tree.root)} is not one the pool knows; resyncing its leaves from scratch`)
    dropCache(p)
    tree = await poolTree(net, p, log)
    if (!(await known(tree.root))) {
      throw new Error(
        `computed root ${hex32(tree.root)} is still unknown on-chain after a full resync -- the RPC may lag or be ` +
          'wrong; try again later, or another --rpc-url',
      )
    }
  }
  const index = tree.layers[0]!.indexOf(n.commitment)
  if (index < 0) throw new Error('commitment missing from the synced leaves')
  log(`leaf ${index} of ${tree.layers[0]!.length}`)

  const path = treePath(tree, index)
  // Exactly the public inputs the contract derives from the withdraw() arguments.
  const inputs = [tree.root, n.nullifierHash, BigInt(recipient), BigInt(relayer), fee, refund]
  log('computing witness ...')
  const w = witness({
    root: inputs[0],
    nullifierHash: inputs[1],
    recipient: inputs[2],
    relayer: inputs[3],
    fee,
    refund,
    nullifier: n.nullifier,
    secret: n.secret,
    pathElements: path.pathElements,
    pathIndices: path.pathIndices,
  })
  log(`proving on ${o.threads} threads ...`)
  const proof = await prove(w, o.threads)

  // Check with the verifier the pool calls, fed the inputs the contract will
  // compute -- not the prover's echo of them -- before any gas is spent.
  if (proof.publicSignals.length !== 6 || proof.publicSignals.some((s, i) => s !== inputs[i])) {
    throw new Error('the proof commits to different public inputs than the withdraw arguments -- aborting')
  }
  const proofBytes = fromHex(proof.proof)
  const verifierAt = await read(net, p.address, TORNADO.verifier)
  if (!(await read(net, verifierAt, VERIFIER.verifyProof, { proof: proofBytes, input: inputs as never }))) {
    throw new Error('proof rejected by the on-chain verifier -- aborting')
  }
  log('proof verified by the pool verifier')

  const args = {
    _proof: proofBytes,
    _root: bytes32(tree.root),
    _nullifierHash: bytes32(n.nullifierHash),
    _recipient: recipient,
    _relayer: relayer,
    _fee: fee,
    _refund: refund,
  }
  const calldata = TORNADO.withdraw.encodeInput(args)
  if (o.dryRun) {
    out(
      JSON.stringify(
        {
          contract: p.address,
          recipient,
          relayer,
          fee: String(fee),
          refund: String(refund),
          value: String(o.self || safe ? refund : 0n), // the refund rides along as msg.value
          calldata: hexBytes(calldata),
        },
        null,
        2,
      ),
    )
    return
  }

  if (relayerUrl) {
    const hash = await submitViaRelayer(
      net,
      p,
      relayerUrl,
      {
        contract: p.address,
        proof: proof.proof,
        args: [hex32(tree.root), hex32(n.nullifierHash), recipient, relayer, hex32(fee), hex32(refund)],
      },
      n.nullifierHash,
    )
    log(`withdrawn: ${hash}`)
    return
  }

  if (safe) {
    log(`proposing to Safe ${safe} as ${signer!.address} -- the Safe, sending it, is linked to the withdrawal`)
    const { safeTxHash, queue } = await proposeSafeTx({
      net,
      chainId: p.chainId,
      safe,
      signer: signer!,
      call: { to: p.address, value: refund, data: calldata },
    })
    log(`proposed ${safeTxHash}; the owners confirm and execute it at ${queue}`)
    log('the note stays unspent until then -- `uragan status` shows when it is spent')
    return
  }

  log(`submitting from ${signer!.address} -- this links that address to the withdrawal`)
  log(`withdrawn: ${await signer!.send({ to: p.address, value: refund, data: calldata })}`)
}

/** The /status of the relayers given, else of the default relayers on --chain, or on every chain. */
async function relayers(urls: string[], chain?: number) {
  const list = urls.length
    ? urls
    : (chain === undefined ? defaultChains() : [chain]).flatMap((id) => defaultRelayers(id).map((r) => r.url))
  if (!list.length) throw new UsageError(`no default relayers for ${chainName(chain!)} -- pass their URLs`)
  const statuses = await Promise.allSettled(list.map(relayerStatus))
  out(`${'RELAYER'.padEnd(42)} ${'FEE%'.padEnd(6)} ${'CHAIN'.padEnd(6)} ${'UP'.padEnd(4)} REWARD ACCOUNT`)
  for (const [i, u] of list.entries()) {
    const r = statuses[i]!
    if (r.status === 'rejected') {
      out(`${u.padEnd(42)} unreachable (${(r.reason as Error).message})`)
      continue
    }
    const s = r.value
    const up = String(s.health?.status) === 'true' ? 'yes' : 'no'
    out(
      `${u.padEnd(42)} ${String(s.tornadoServiceFee ?? '?').padEnd(6)} ${String(s.netId ?? '?').padEnd(6)} ${up.padEnd(4)} ${s.rewardAccount}`,
    )
  }
}

// ---------------------------------------------------------------------------
const HELP = `uragan -- Tornado Cash from the command line

  setup                        fetch circuit and keys, check their pinned sha256
  pools                        every pool, with live deposit counts
  verify                       re-check every pool address on-chain
  note <pool>                  generate a note offline (no transaction)
  deposit <pool>               generate a note and deposit; --note <note|-> deposits one
                               you already hold, e.g. after an attempt that failed (the note
                               names its pool and chain; it is saved first, like a new one)
  sync <pool>                  pull Deposit events into the leaf cache
  status [note|-]              deposited? spent? leaf index? (no note: every saved note)
  withdraw <note|-> <to>       [--relayer URL] [--fee WEI] | --self | --safe SAFE
                               [--refund WEI] [--dry-run]. No --relayer: the cheapest default
                               relayer that answers. --safe: propose it to that Safe's owners
  relayers [url...]            query relayer /status endpoints (default: the built-in list)

  --chain NAME                 the chain a <pool> is on: ethereum (default), optimism, polygon, arbitrum.
                               Notes carry their own chain
  --rpc-url URL                your own RPC instead of the public default -- a node, or a
                               wallet, which then also signs. Without --chain, its chain is used
  --max-fee-percent N          refuse a relayer-computed fee above N% of the amount (default 5)
  --threads N                  prover threads (default: all cores)

signing (deposit, withdraw --self, and the proposer for --safe) -- a local key, or else a wallet:
  --private-key PK             sign locally (visible in ps while running; prefer the env var)
  URAGAN_PRIVATE_KEY           the same, from the environment
  --account NAME               cast keystore (~/.foundry/keystores/NAME)
  --keystore FILE              any V3 keystore; password from URAGAN_KEYSTORE_PASSWORD or a prompt
  (no key)                     a wallet signs: the one at --rpc-url, else Frame at
                               ${FRAME_RPC}. --from ADDR picks the account

env: URAGAN_HOME, URAGAN_CHUNK, URAGAN_INSTANCES, URAGAN_ASSETS
Pass \`-\` for a note to read it from stdin, keeping it out of argv and shell history.`

const OPTIONS = {
  relayer: { type: 'string' },
  fee: { type: 'string' },
  refund: { type: 'string' },
  'max-fee-percent': { type: 'string' },
  self: { type: 'boolean' },
  safe: { type: 'string' },
  note: { type: 'string' },
  'dry-run': { type: 'boolean' },
  account: { type: 'string' },
  keystore: { type: 'string' },
  chain: { type: 'string' },
  'rpc-url': { type: 'string' },
  'private-key': { type: 'string' },
  from: { type: 'string' },
  threads: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
} as const

try {
  const { values: v, positionals } = parseArgs({ allowPositionals: true, options: OPTIONS })
  const [cmd = 'help', ...rest] = positionals
  setRpcUrl(v['rpc-url'])
  const chain = v.chain === undefined ? undefined : parseChain(v.chain)
  const threads = intFlag('threads', v.threads, availableParallelism(), 1, 256)
  const maxFeePercent = v['max-fee-percent'] === undefined ? 5 : Number(v['max-fee-percent'])
  if (!(maxFeePercent >= 0 && maxFeePercent <= 100))
    throw new UsageError('--max-fee-percent must be a number from 0 to 100')
  const sig: SignerOpts = {
    privateKey: v['private-key'],
    account: v.account,
    keystore: v.keystore,
    from: v.from === undefined ? undefined : checksummed(v.from),
  }

  const commands: Record<string, () => unknown> = {
    setup: () => setup(),
    pools: () => poolsCmd(chain),
    verify: () => verifyCmd(chain),
    note: () => noteCmd(rest[0], chain),
    deposit: () => deposit(rest[0], chain, sig, v.note),
    sync: () => syncCmd(rest[0], chain),
    status: () => status(rest[0]),
    withdraw: () =>
      withdraw(rest[0], rest[1], {
        ...sig,
        relayer: v.relayer,
        fee: v.fee,
        refund: v.refund,
        maxFeePercent,
        self: v.self,
        safe: v.safe,
        dryRun: v['dry-run'],
        threads,
      }),
    relayers: () => relayers(rest, chain),
    help: () => out(HELP),
  }
  const name = v.help ? 'help' : cmd
  if (!Object.hasOwn(commands, name)) throw new UsageError(`unknown command '${name}'\n\n${HELP}`)
  // Flags only some commands read. Anywhere else they would be dropped
  // silently -- and --note on status would turn a query about one note into
  // one about every saved note.
  const only: [keyof typeof v, string[]][] = [
    ['note', ['deposit']],
    ...(['relayer', 'fee', 'refund', 'self', 'safe', 'dry-run', 'max-fee-percent', 'threads'] as const).map(
      (f): [keyof typeof v, string[]] => [f, ['withdraw']],
    ),
    ...(['private-key', 'account', 'keystore', 'from'] as const).map((f): [keyof typeof v, string[]] => [
      f,
      ['deposit', 'withdraw'],
    ]),
  ]
  for (const [flag, cmds] of only) {
    if (name !== 'help' && v[flag] !== undefined && !cmds.includes(name)) {
      throw new UsageError(`--${flag} is for ${cmds.join(' and ')}, not ${name}`)
    }
  }
  await commands[name]!()
} catch (e) {
  // parseArgs rejects an unknown flag or a missing value with ERR_PARSE_ARGS_*:
  // a usage mistake too, so no stack trace either way.
  // Node's own errors carry string codes; JSON-RPC errors carry numbers (4001: rejected in the wallet).
  const code = (e as { code?: unknown }).code
  const usage = e instanceof UsageError || (typeof code === 'string' && code.startsWith('ERR_PARSE_ARGS'))
  log(`error: ${(e as Error).message}`)
  if (process.env.DEBUG) log((e as Error).stack ?? '')
  process.exit(usage ? 2 : 1)
}
