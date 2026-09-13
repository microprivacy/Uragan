/**
 * Everything that touches the chain: JSON-RPC transport, contract bindings,
 * Deposit-log sync, and the cached Merkle tree. Uses micro-eth-signer.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { STATUS_CODES } from 'node:http'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { createContract, events } from 'micro-eth-signer/abi.js'
import { isTransientRpcError, RpcClient, withRetry } from 'micro-eth-signer/net.js'
import { chainName, HOME, LOG_CHUNK, type Pool, UsageError } from './config.ts'
import { decodeTree, encodeTree, extendTree, type Tree } from './crypto.ts'

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** A provider's eth_getLogs block-range cap. Carries no code, so it is never retried as transient. */
export class RangeLimitError extends Error {}

/**
 * Known wordings of "that block range is too big". Checked before the retry
 * layer sees the error: some providers reuse code -32005 for both range and
 * rate limits, and a range error retried 9 times is 40 s wasted per chunk.
 */
const RANGE_LIMIT =
  /block range|blocks? range|ranges? over|range \d+ exceeds|more than \d+ (blocks|results)|query returned more than|log response size|limited to .*range/i

/** Never retried and never timed out: the wallet may already have signed, or may be waiting on a human. */
const NOT_IDEMPOTENT = new Set(['eth_sendTransaction', 'eth_signTypedData_v4', 'wallet_switchEthereumChain'])
const REQUEST_TIMEOUT_MS = 60_000

const urls = new WeakMap<RpcClient, string>()

/** The endpoint behind a client, for messages. */
export const urlOf = (net: RpcClient) => urls.get(net) ?? 'the RPC'

/**
 * JSON-RPC over fetch -- RpcClient only needs `call`. Errors throw; they never
 * read as a value. Transient failures (429s, dropped connections, 5xx) are
 * retried with backoff, except the wallet's own methods: a retry after the
 * wallet already acted would send a second transaction, or ask its user twice.
 * `retry: false` is for a local wallet, where a refused connection means it is
 * not running and backing off would only delay saying so.
 */
export function rpc(url: string, { retry = true } = {}): RpcClient {
  let id = 0
  const once = async (method: string, params: unknown[]) => {
    let res: Response
    let text: string
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }, (_k, v) =>
          typeof v === 'bigint' ? `0x${v.toString(16)}` : v,
        ),
        signal: NOT_IDEMPOTENT.has(method) ? undefined : AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      text = await res.text()
    } catch (e) {
      if ((e as Error).name === 'TimeoutError') {
        const msg = `${method}: ETIMEDOUT after ${REQUEST_TIMEOUT_MS / 1000}s`
        // A log query that runs this long is too wide: split it, don't repeat it.
        if (method === 'eth_getLogs') throw new RangeLimitError(msg)
        // isTransientRpcError does not count a request timeout, but it is as
        // transient as a dropped connection -- say so in words it recognises.
        throw new Error(msg)
      }
      throw e
    }
    // A provider that times out a log query ("Request timeout on the free
    // plan", 408, 504) is saying the range is too heavy, not that it is down.
    const tooWide = (s: string, status?: number) =>
      RANGE_LIMIT.test(s) ||
      (method === 'eth_getLogs' && (status === 408 || status === 504 || /time[sd]? ?out/i.test(s)))
    if (!res.ok) {
      // The canonical reason phrase, not res.statusText: HTTP/2 has none, and
      // the retry layer recognises 502/503/504 by these words.
      const msg = `${method}: HTTP ${res.status} ${STATUS_CODES[res.status] ?? ''} ${text.slice(0, 200)}`
      throw tooWide(text, res.status) ? new RangeLimitError(msg) : new Error(msg)
    }
    const body = JSON.parse(text) as { result?: unknown; error?: { message: string; code?: number; data?: unknown } }
    if (body.error) {
      const msg = `${method}: ${body.error.message}`
      if (tooWide(body.error.message)) throw new RangeLimitError(msg)
      throw Object.assign(new Error(msg), body.error)
    }
    return body.result
  }
  const client = new RpcClient({
    call: (method: string, ...params: unknown[]) =>
      !retry || NOT_IDEMPOTENT.has(method)
        ? once(method, params)
        : withRetry(() => once(method, params), undefined, method),
  })
  urls.set(client, url)
  return client
}

/**
 * Refuse to act on a chain through an RPC on another. The same pool address
 * can hold a different pool there, or nothing at all.
 */
export async function assertChain(net: RpcClient, chainId: number): Promise<void> {
  const got = Number(await net.chainId())
  if (got !== chainId) {
    throw new UsageError(
      `${urlOf(net)} is on ${chainName(got)} (${got}), not ${chainName(chainId)} (${chainId}) -- use an RPC for ${chainName(chainId)}`,
    )
  }
}

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------
export const TORNADO_ABI = [
  {
    type: 'function',
    name: 'deposit',
    stateMutability: 'payable',
    inputs: [{ name: '_commitment', type: 'bytes32' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'withdraw',
    stateMutability: 'payable',
    inputs: [
      { name: '_proof', type: 'bytes' },
      { name: '_root', type: 'bytes32' },
      { name: '_nullifierHash', type: 'bytes32' },
      { name: '_recipient', type: 'address' },
      { name: '_relayer', type: 'address' },
      { name: '_fee', type: 'uint256' },
      { name: '_refund', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'isSpent',
    stateMutability: 'view',
    inputs: [{ name: '_nullifierHash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'function',
    name: 'commitments',
    stateMutability: 'view',
    inputs: [{ name: '', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'function',
    name: 'isKnownRoot',
    stateMutability: 'view',
    inputs: [{ name: '_root', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  { type: 'function', name: 'nextIndex', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint32' }] },
  {
    type: 'function',
    name: 'denomination',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  { type: 'function', name: 'levels', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint32' }] },
  { type: 'function', name: 'verifier', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
  {
    type: 'event',
    name: 'Deposit',
    inputs: [
      { name: 'commitment', type: 'bytes32', indexed: true },
      { name: 'leafIndex', type: 'uint32', indexed: false },
      { name: 'timestamp', type: 'uint256', indexed: false },
    ],
  },
] as const

export const VERIFIER_ABI = [
  {
    type: 'function',
    name: 'verifyProof',
    stateMutability: 'view',
    inputs: [
      { name: 'proof', type: 'bytes' },
      { name: 'input', type: 'uint256[6]' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const

export const ERC20_ABI = [
  {
    type: 'function',
    name: 'approve',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'function',
    name: 'allowance',
    stateMutability: 'view',
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    outputs: [{ name: '', type: 'uint256' }],
  },
] as const

/** The ABIs, bound once. Calldata comes from these; view calls go through `read`. */
export const TORNADO = createContract(TORNADO_ABI)
export const VERIFIER = createContract(VERIFIER_ABI)
export const ERC20 = createContract(ERC20_ABI)

type ViewMethod<A, R> = { encodeInput: (args: A) => Uint8Array; decodeOutput: (b: Uint8Array) => R }

/** eth_call a view method of one of the contracts above, at `to`. */
export async function read<A, R>(net: RpcClient, to: string, method: ViewMethod<A, R>, args?: A): Promise<R> {
  const data = `0x${bytesToHex(method.encodeInput(args as A))}`
  const result = (await net.ethCall({ to, data })) as string
  return method.decodeOutput(hexToBytes(result.slice(2)))
}

const depositEvent = events(TORNADO_ABI).Deposit

/** Throws if n does not fit, rather than silently truncating like a hex round-trip would. */
export const bytes32 = (n: bigint): Uint8Array => numberToBytesBE(n, 32)

// ---------------------------------------------------------------------------
// Leaf sync
// ---------------------------------------------------------------------------

/**
 * Blocks behind the head that every sync re-scans, so a reorg or an RPC whose
 * log index lags its block number heals on the next run instead of leaving a
 * permanent hole.
 */
const REORG_MARGIN = 12
const SYNC_CONCURRENCY = 4

/**
 * eth_getLogs has no cursor, so sync pages by block range and sizes each page
 * by what the last one returned: double below PAGE_SMALL logs; above
 * PAGE_LARGE (~630 bytes each), shrink to what would have held PAGE_SMALL. Sparse L2 history (a few thousand deposits
 * over 500M blocks) takes a handful of pages; busy Ethereum ranges stay at a
 * few MB per response. Providers can fail silently on huge ones -- one
 * returned an empty list for a 43 MB result.
 */
const PAGE_SMALL = 2000
const PAGE_LARGE = 8000

/** Keyed by chain and contract: a fork or testnet registry can reuse the same pool names. */
const cacheBase = (pool: Pool) => join(HOME, 'cache', `${pool.chainId}-${pool.address.toLowerCase()}`)

type Leaf = { commitment: bigint; block: number }

/** `<leafIndex> <commitment> <block>` per line. Later lines win, so a re-scan after a reorg overrides. */
function loadLeaves(pool: Pool): Map<number, Leaf> {
  const leaves = new Map<number, Leaf>()
  const file = `${cacheBase(pool)}.leaves`
  if (!existsSync(file)) return leaves
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const [i, c, b] = line.split(' ')
    if (i && c && b) leaves.set(Number(i), { commitment: BigInt(c), block: Number(b) })
  }
  return leaves
}

const leafLine = (i: number, l: Leaf) => `${i} 0x${l.commitment.toString(16)} ${l.block}`

/** The cached commitments for a pool, by leaf index. */
export const cachedLeaves = (pool: Pool): Map<number, bigint> =>
  new Map([...loadLeaves(pool)].map(([i, l]) => [i, l.commitment]))

const writeAtomic = (file: string, data: string | Uint8Array) => {
  writeFileSync(`${file}.tmp`, data)
  renameSync(`${file}.tmp`, file)
}

type Range = [from: number, to: number]

/**
 * All commitments in a pool, in leafIndex order, synced incrementally into
 * $URAGAN_HOME/cache. Fetches several block ranges at once, splits ranges a
 * provider rejects as too wide, and stops as soon as it holds every leaf below
 * nextIndex() -- most pools stopped receiving deposits years ago.
 */
export async function syncLeaves(net: RpcClient, pool: Pool, log: (s: string) => void): Promise<bigint[]> {
  mkdirSync(join(HOME, 'cache'), { recursive: true })
  const file = `${cacheBase(pool)}.leaves`
  const markFile = `${cacheBase(pool)}.block`
  // Everything up to the mark is final. A leaf above it was fetched within
  // REORG_MARGIN of the head and may since have been reorged out -- possibly
  // replaced by another deposit at the same index, which a count of leaves
  // cannot tell apart. Drop those and fetch them again.
  const mark = existsSync(markFile) ? Number(readFileSync(markFile, 'utf8')) : pool.deployedBlock - 1
  const leaves = loadLeaves(pool)
  let changed = false
  for (const [i, l] of leaves) {
    if (l.block > mark) {
      leaves.delete(i)
      changed = true
    }
  }

  const want = Number(await read(net, pool.address, TORNADO.nextIndex))
  const head = await net.height()
  // Only leaves below `want` count toward completion: a deposit that lands
  // mid-scan sits above it and must not make us stop with a hole below.
  let have = 0
  for (const i of leaves.keys()) if (i < want) have++
  const topics = depositEvent.topics({ commitment: null, leafIndex: null, timestamp: null })
  const fetchRange = async ([fromBlock, toBlock]: Range) => {
    const logs = await net.ethLogs(topics, { address: pool.address, fromBlock, toBlock })
    const lines: string[] = []
    for (const l of logs) {
      const d = depositEvent.decode(l.topics, l.data)
      const i = Number(d.leafIndex)
      const leaf = { commitment: bytesToNumberBE(d.commitment), block: l.blockNumber }
      if (i < want && !leaves.has(i)) have++
      leaves.set(i, leaf)
      lines.push(leafLine(i, leaf))
    }
    if (lines.length) appendFileSync(file, `${lines.join('\n')}\n`)
    return lines.length
  }

  // The page size: resized by PAGE_SMALL / PAGE_LARGE, and never above the
  // ceiling -- half of the smallest range the provider refused as too wide.
  let chunk = LOG_CHUNK
  let ceiling = Infinity

  /** Scan from `start` toward the head until every leaf below `want` is held. */
  const scan = async (start: number) => {
    if (have >= want || start > head) return
    log(`syncing ${want - have} leaves from block ${start} (${SYNC_CONCURRENCY} ranges at a time)`)
    const pending: Range[] = []
    let cursor = start
    const nextRange = (): Range | undefined => {
      if (pending.length) return pending.shift()
      if (cursor > head) return undefined
      const r: Range = [cursor, Math.min(cursor + chunk - 1, head)]
      cursor = r[1] + 1
      return r
    }
    // The resume mark only advances over a contiguous run of finished ranges,
    // and never past the reorg margin.
    const finished = new Map<number, number>()
    let contiguous = start - 1
    let failure: unknown
    let failedRange: Range = [start, head]
    // A provider still rate-limiting after withRetry's backoff gets half the
    // workers; the sync gives up only when one worker is refused too.
    let workers = SYNC_CONCURRENCY
    const worker = async (id: number) => {
      for (let r = nextRange(); r && failure === undefined && have < want; r = nextRange()) {
        try {
          const n = await fetchRange(r)
          if (n) changed = true
          // Judge the page that came back, not the newest size: with several
          // in flight, stale small pages would otherwise keep doubling it.
          const width = r[1] - r[0] + 1
          if (n < PAGE_SMALL && width >= chunk) chunk = Math.min(chunk * 2, ceiling)
          else if (n > PAGE_LARGE) chunk = Math.min(chunk, Math.max(1, Math.floor((width * PAGE_SMALL) / n)))
        } catch (e) {
          if (e instanceof RangeLimitError && r[1] > r[0]) {
            const width = r[1] - r[0] + 1
            const size = Math.ceil(width / 4)
            const parts: Range[] = []
            for (let s = r[0]; s <= r[1]; s += size) parts.push([s, Math.min(s + size - 1, r[1])])
            pending.unshift(...parts)
            ceiling = Math.min(ceiling, Math.max(1, Math.floor(width / 2)))
            chunk = Math.min(chunk, size)
            continue
          }
          if (isTransientRpcError(e) && workers > 1) {
            pending.unshift(r)
            workers = Math.max(1, workers >> 1)
            process.stderr.write(`\n  the RPC is rate-limiting; slowing to ${workers} request(s) at a time\n`)
            if (id >= workers) return
            continue
          }
          failure = e
          failedRange = r
          return
        }
        finished.set(r[0], r[1])
        while (finished.has(contiguous + 1)) {
          const end = finished.get(contiguous + 1)!
          finished.delete(contiguous + 1)
          contiguous = end
        }
        writeFileSync(markFile, String(Math.min(contiguous, head - REORG_MARGIN)))
        process.stderr.write(`\r  block ${contiguous} / ${head}   leaves ${have} / ${want}   range ${chunk}      `)
        if (id >= workers) return
      }
    }
    await Promise.all(Array.from({ length: SYNC_CONCURRENCY }, (_, id) => worker(id)))
    process.stderr.write('\n')
    if (failure !== undefined) {
      const why = isTransientRpcError(failure)
        ? 'the RPC keeps refusing (rate limit or outage)'
        : 'this RPC cannot serve these logs (no archive data, or a fault on its side)'
      throw new Error(
        `eth_getLogs for blocks ${failedRange[0]}-${failedRange[1]} failed -- ${why}: ${(failure as Error).message}\n` +
          '  progress is saved; run it again, or continue with another RPC',
      )
    }
  }

  await scan(mark + 1)
  // Scanned to the head yet still short: the RPC's log index can lag its
  // block number. Give the tip a few more looks.
  for (let attempt = 0; have < want && attempt < 3; attempt++) {
    await sleep(3000)
    const tip = await net.height()
    if (await fetchRange([Math.max(pool.deployedBlock, tip - REORG_MARGIN), tip])) changed = true
  }
  // Still short: the leaf file was lost or edited, or the RPC returned an
  // incomplete page (a flaky one does, now and then). The chain is the source
  // of truth -- rescan everything once, with the page size starting over.
  if (have < want) {
    log('leaves are missing; rescanning from the deployment block')
    chunk = LOG_CHUNK
    await scan(pool.deployedBlock)
  }

  // The tree is only right if leaves are exactly 0..want-1 with no holes.
  const ordered: bigint[] = []
  for (let i = 0; i < want; i++) {
    const l = leaves.get(i)
    if (l === undefined) {
      throw new Error(`leaf ${i} is missing after syncing to block ${head}; try again later (the RPC may lag)`)
    }
    ordered.push(l.commitment)
  }
  // Compact: re-scans append duplicates, and a reorg can leave superseded lines.
  if (changed) {
    const lines = [...leaves].sort(([a], [b]) => a - b).map(([i, l]) => leafLine(i, l))
    writeAtomic(file, `${lines.join('\n')}\n`)
  }
  return ordered
}

/**
 * The pool's Merkle tree at nextIndex(): leaves synced, then the cached tree
 * extended with only what changed since last time. A full build is ~51 s at
 * eth-1's size; after that, a withdrawal rehashes only new leaves.
 */
export async function poolTree(net: RpcClient, pool: Pool, log: (s: string) => void): Promise<Tree> {
  const leaves = await syncLeaves(net, pool, log)
  const file = `${cacheBase(pool)}.tree`
  let prev: Tree | undefined
  if (existsSync(file)) {
    try {
      prev = decodeTree(readFileSync(file))
    } catch {
      log('tree cache unreadable; rebuilding')
    }
  }
  const before = prev && { n: prev.layers[0]!.length, root: prev.root }
  if (!prev && leaves.length > 5000)
    log(`building the Merkle tree over ${leaves.length} leaves (first time only, ~1 min) ...`)
  const tree = extendTree(prev, leaves)
  if (!before || before.n !== leaves.length || before.root !== tree.root) writeAtomic(file, encodeTree(tree))
  return tree
}
