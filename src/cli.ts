#!/usr/bin/env node
/**
 * uragan -- a Tornado Cash client.
 *
 * TypeScript run directly by Node (types are stripped at load). Chain access
 * and signing via micro-eth-signer, zk primitives and witnesses via
 * micro-zk-proofs, Groth16 proving via the wasm build in prover/.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { addr } from 'micro-eth-signer';
import type { RpcClient } from 'micro-eth-signer/net.js';
import { formatUnits, parseUnits } from 'micro-eth-signer/utils.js';
import { bn254, stringBigints } from 'micro-zk-proofs';
import {
  assertChain, bytes32, cachedLeaves, ERC20, poolTree, read, rpc, syncLeaves, TORNADO, VERIFIER,
} from './chain.ts';
import {
  ARTIFACTS, ASSETS, chainName, customRpc, defaultChains, HOME, parseChain, type Pool, pool, pools, RELEASE, rpcUrl,
  setRpcUrl, UsageError,
} from './config.ts';
import {
  buildTree, createNote, hashLeftRight, hex32, parseNote, pedersen, treePath, zeroValues, ZERO_VALUE,
} from './crypto.ts';
import { prove, witness } from './prover.ts';
import { makeSigner, type SignerOpts } from './signer.ts';

const log = (s: string) => process.stderr.write(s + '\n');
const out = (s: string) => process.stdout.write(s + '\n');
// `uragan pools | head`: the reader left, which is not an error.
process.stdout.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EPIPE') process.exit(0);
  throw e;
});
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const hexBytes = (b: Uint8Array) => '0x' + Buffer.from(b).toString('hex');
const fromHex = (h: string) => Buffer.from(h.slice(2), 'hex');
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/** A note from the argument, or from stdin when the argument is `-`. Stdin keeps it out of argv and shell history. */
async function readNote(arg: string | undefined): Promise<string> {
  if (arg && arg !== '-') return arg;
  if (process.stdin.isTTY) throw new UsageError('pass a note, or `-` and pipe it on stdin');
  let s = '';
  for await (const chunk of process.stdin) s += chunk;
  return s.trim();
}

/**
 * EIP-55: a mixed-case address must carry a valid checksum. A typo'd recipient
 * is bound into the proof and receives the funds irreversibly, so it must be
 * rejected, never "corrected" by re-checksumming.
 */
function checksummed(a: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) throw new UsageError(`not an address: ${a}`);
  if (!addr.isValid(a)) throw new UsageError(`${a} fails its EIP-55 checksum -- probably a typo`);
  return addr.addChecksum(a);
}

/** A whole number of base units (wei), or undefined if the flag was not given. */
function baseUnits(flag: string, v: string | undefined): bigint | undefined {
  if (v === undefined) return undefined;
  if (!/^\d+$/.test(v)) throw new UsageError(`--${flag} must be a whole number of base units (wei), got '${v}'`);
  return BigInt(v);
}

function intFlag(flag: string, v: string | undefined, fallback: number, min: number, max: number): number {
  if (v === undefined) return fallback;
  const n = Number(v);
  if (!/^\d+$/.test(v) || n < min || n > max) throw new UsageError(`--${flag} must be an integer from ${min} to ${max}, got '${v}'`);
  return n;
}

const noteKey = (n: { currency: string; amount: string }) => `${n.currency}-${n.amount}`;

/** The pool a note belongs to, on the chain the note was made for. */
function notePool(n: { currency: string; amount: string; netId: number }): [string, Pool] {
  const key = noteKey(n);
  return [key, pool(n.netId, key)];
}

/**
 * An RPC client and the chain it serves. The chain is `chain` if known (a
 * note's, or --chain); else --rpc-url's own; else Ethereum. The RPC is
 * --rpc-url if given, else that chain's public default -- checked either way.
 */
async function connect(chain?: number): Promise<{ net: RpcClient; chainId: number }> {
  if (chain === undefined && customRpc()) {
    const net = rpc(rpcUrl());
    return { net, chainId: Number(await net.chainId()) };
  }
  const chainId = chain ?? 1;
  const net = rpc(rpcUrl(chainId));
  await assertChain(net, chainId);
  return { net, chainId };
}

/** A pool by name: on --chain, or the chain --rpc-url is on, or Ethereum. */
async function connectPool(key: string, chain?: number): Promise<{ net: RpcClient; p: Pool }> {
  const { net, chainId } = await connect(chain);
  return { net, p: pool(chainId, key) };
}

/** Refuse to send money to an address that is not the pool the registry claims. */
async function assertPool(net: RpcClient, p: Pool, key: string) {
  let denomination: bigint;
  try {
    denomination = await read(net, p.address, TORNADO.denomination);
  } catch {
    throw new UsageError(`no Tornado pool at ${p.address} on ${chainName(p.chainId)} (registry entry ${key})`);
  }
  if (denomination !== parseUnits(p.amount, p.decimals)) {
    throw new UsageError(`${p.address} has denomination ${denomination}, not ${p.amount} ${p.symbol}`);
  }
}

// ---------------------------------------------------------------------------
// setup / selftest
// ---------------------------------------------------------------------------
async function setup() {
  mkdirSync(ASSETS, { recursive: true });
  for (const [name, want] of Object.entries(ARTIFACTS)) {
    const file = join(ASSETS, name);
    if (existsSync(file) && sha256(readFileSync(file)) === want) {
      log(`have ${name}`);
      continue;
    }
    log(`downloading ${name} ...`);
    const res = await fetch(`${RELEASE}/${name}`);
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const got = sha256(buf);
    if (got !== want) throw new Error(`${name}: sha256 ${got} does not match the pinned ${want} -- refusing it`);
    writeFileSync(file, buf);
  }
  await selftest(availableParallelism());
}

async function selftest(threads: number) {
  const checks: [string, boolean][] = [];
  const t = (name: string, got: unknown, want: unknown) => checks.push([name, String(got) === String(want)]);

  // circomlib vectors; zeros[19] is what the deployed MerkleTreeWithHistory
  // reports, so it pins the whole MiMC ladder.
  t('pedersen(zeros62)', pedersen(new Uint8Array(62)),
    '10606596081724992687836412044438397210272029250652246605286526701104132431192');
  t('pedersen(ff31)', pedersen(new Uint8Array(31).fill(0xff)),
    '11958727323653992140393347419347735936852777297016280498319205036343819833236');
  t('mimc([1,2])', hashLeftRight(1n, 2n),
    '19814528709687996974327303300007262407299502847885145507292406548098437687919');
  t('ZERO_VALUE', ZERO_VALUE,
    '21663839004416932945382355908790599225266501822907911457504978515578255421292');
  t('zeros[19] vs deployed', hex32(zeroValues(20)[19]!),
    '0x198622acbd783d1b0d9064105b1fc8e4d8889de95c4c519b3f635809fe6afc05');
  t('note roundtrip', parseNote('tornado-eth-0.1-1-0x' + '00'.repeat(62)).commitment, pedersen(new Uint8Array(62)));

  // The whole proving stack, offline: prove a synthetic withdrawal and check it
  // against the pinned verification key with micro-zk-proofs' verifier.
  const n = createNote('eth', '0.1', 1);
  const tree = buildTree([n.commitment]);
  const path = treePath(tree, 0);
  const p = await prove(
    witness({
      root: tree.root, nullifierHash: n.nullifierHash, recipient: 1n, relayer: 0n, fee: 0n, refund: 0n,
      nullifier: n.nullifier, secret: n.secret, pathElements: path.pathElements, pathIndices: path.pathIndices,
    }),
    threads,
  );
  const vk = stringBigints.decode(JSON.parse(readFileSync(join(ASSETS, 'withdraw_verification_key.json'), 'utf8')));
  const proofOk = bn254.groth.verifyProof(
    vk as never,
    stringBigints.decode({ proof: p.raw, publicSignals: p.publicSignals.map(String) }) as never,
  );
  t('prove + verify offline', proofOk, true);

  for (const [name, ok] of checks) log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (checks.some(([, ok]) => !ok)) throw new Error('selftest FAILED -- do not use this build');
  log(`selftest: all ${checks.length} passed`);
}

// ---------------------------------------------------------------------------
// pools / verify
// ---------------------------------------------------------------------------

/** The chains `pools` and `verify` cover: the one --chain or --rpc-url names, else all. */
async function networks(chain?: number) {
  if (chain !== undefined || customRpc()) return [await connect(chain)];
  return Promise.all(defaultChains().map((id) => connect(id)));
}

/** Decode a multicall result; undefined when the call failed or hit an address with no code. */
function decoded<T>(r: { success: boolean; data: string }, decode: (b: Uint8Array) => T): T | undefined {
  return r.success && r.data !== '0x' ? decode(fromHex(r.data)) : undefined;
}

async function poolsCmd(chain?: number) {
  for (const [c, { net, chainId }] of (await networks(chain)).entries()) {
    const entries = Object.entries(pools(chainId));
    const res = await net.multicall(
      entries.map(([, p]) => ({ to: p.address, data: hexBytes(TORNADO.nextIndex.encodeInput()), allowFailure: true })),
    );
    out(`${c ? '\n' : ''}${chainName(chainId)}`);
    out(`${'POOL'.padEnd(14)} ${'ADDRESS'.padEnd(42)} ${'DEPOSITS'.padStart(9)}`);
    entries.forEach(([key, p], i) => {
      const n = decoded(res[i]!, (b) => TORNADO.nextIndex.decodeOutput(b));
      out(`${key.padEnd(14)} ${p.address.padEnd(42)} ${(n === undefined ? 'no pool' : String(n)).padStart(9)}`);
    });
  }
}

/** Re-check every pool against the chain. A pool with no code is exactly what this is for. */
async function verifyCmd(chain?: number) {
  let bad = 0;
  let total = 0;
  for (const { net, chainId } of await networks(chain)) {
    const entries = Object.entries(pools(chainId));
    const res = await net.multicall(
      entries.flatMap(([, p]) => [
        { to: p.address, data: hexBytes(TORNADO.denomination.encodeInput()), allowFailure: true },
        { to: p.address, data: hexBytes(TORNADO.levels.encodeInput()), allowFailure: true },
      ]),
    );
    out(chainName(chainId));
    entries.forEach(([key, p], i) => {
      total++;
      const denom = decoded(res[2 * i]!, (b) => TORNADO.denomination.decodeOutput(b));
      const levels = decoded(res[2 * i + 1]!, (b) => TORNADO.levels.decodeOutput(b));
      const want = parseUnits(p.amount, p.decimals);
      if (denom === want && Number(levels) === 20) return out(`  ${key.padEnd(14)} OK`);
      bad++;
      out(denom === undefined
        ? `  ${key.padEnd(14)} MISMATCH no Tornado pool at ${p.address}`
        : `  ${key.padEnd(14)} MISMATCH denomination=${denom} want=${want} levels=${levels}`);
    });
  }
  if (bad) throw new Error(`${bad} pool(s) DO NOT match the chain -- do not use them`);
  log(`all ${total} pools verified`);
}

// ---------------------------------------------------------------------------
// note / deposit / sync / status
// ---------------------------------------------------------------------------
async function noteCmd(key: string | undefined, chain?: number) {
  if (!key) throw new UsageError('usage: uragan note <pool>');
  // Offline unless --rpc-url is given, in which case its chain decides.
  const p = pool(customRpc() ? (await connect(chain)).chainId : (chain ?? 1), key);
  out(createNote(p.currency, p.amount, p.chainId).note);
}

async function deposit(key: string | undefined, chain: number | undefined, sig: SignerOpts) {
  if (!key) throw new UsageError('usage: uragan deposit <pool>');
  const { net, p } = await connectPool(key, chain);
  await assertPool(net, p, key);
  const signer = await makeSigner(net, sig);
  const amount = parseUnits(p.amount, p.decimals);

  if (p.tokenAddress) {
    const allowance = await read(net, p.tokenAddress, ERC20.allowance, { owner: signer.address, spender: p.address });
    if (allowance < amount) {
      // USDT, among others, reverts when one non-zero allowance is changed to
      // another; a deposit that failed after approving leaves exactly that.
      if (allowance > 0n) {
        log(`resetting the ${p.symbol} allowance to 0 first ...`);
        await signer.send({ to: p.tokenAddress, data: ERC20.approve.encodeInput({ spender: p.address, amount: 0n }) });
      }
      log(`approving ${p.amount} ${p.symbol} ...`);
      await signer.send({ to: p.tokenAddress, data: ERC20.approve.encodeInput({ spender: p.address, amount }) });
    }
  }

  const n = createNote(p.currency, p.amount, p.chainId);
  const call = { to: p.address, value: p.tokenAddress ? 0n : amount, data: TORNADO.deposit.encodeInput(bytes32(n.commitment)) };
  // Dry-run first, so an empty balance or a bad allowance fails before a note exists.
  try {
    await net.estimateGas({ from: signer.address, to: call.to, value: `0x${call.value.toString(16)}`, data: hexBytes(call.data) });
  } catch (e) {
    throw new UsageError(`the deposit would fail, nothing was sent: ${(e as Error).message}`);
  }

  // Persist the note BEFORE broadcasting. A funded deposit whose note is lost
  // is unrecoverable; an orphan note for a failed deposit is harmless.
  const dir = join(HOME, 'notes');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = join(dir, `${new Date().toISOString().replace(/[:.]/g, '')}-${chainName(p.chainId).toLowerCase()}-${key}.txt`);
  writeFileSync(file, n.note + '\n', { mode: 0o600 });
  out(n.note);
  log(`note saved to ${file} -- back it up. Without it the funds are GONE.`);

  log(`depositing ${p.amount} ${p.symbol} into ${p.address} from ${signer.address} ...`);
  try {
    log(`deposited: ${await signer.send(call)}`);
  } catch (e) {
    throw new Error(`deposit failed or unconfirmed: ${(e as Error).message}\n  check with: uragan status <note>`);
  }
}

async function syncCmd(key: string | undefined, chain?: number) {
  if (!key) throw new UsageError('usage: uragan sync <pool>');
  const { net, p } = await connectPool(key, chain);
  const leaves = await syncLeaves(net, p, log);
  log(`${key}: ${leaves.length} leaves cached`);
}

async function status(noteArg: string | undefined) {
  const n = parseNote(await readNote(noteArg));
  const [key, p] = notePool(n);
  const { net } = await connect(p.chainId);
  const [deposited, spent, total] = await Promise.all([
    read(net, p.address, TORNADO.commitments, bytes32(n.commitment)),
    read(net, p.address, TORNADO.isSpent, bytes32(n.nullifierHash)),
    read(net, p.address, TORNADO.nextIndex),
  ]);
  out(`pool          ${key} on ${chainName(p.chainId)}  (${p.address})`);
  out(`commitment    ${hex32(n.commitment)}`);
  out(`nullifierHash ${hex32(n.nullifierHash)}`);
  out(`deposited     ${deposited}`);
  out(`spent         ${spent}`);
  out(`anonymity set ${total} deposits`);
  const idx = [...cachedLeaves(p)].find(([, c]) => c === n.commitment)?.[0];
  if (idx !== undefined) out(`leaf index    ${idx}  (${Number(total) - idx - 1} deposits since)`);
  else if (deposited) log(`(run \`uragan sync ${key} --chain ${chainName(p.chainId).toLowerCase()}\` to see the leaf index)`);
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------
type RelayerStatus = {
  rewardAccount: string;
  netId?: number;
  tornadoServiceFee?: number | string;
  ethPrices?: Record<string, string>;
  health?: { status?: string | boolean };
};

const relayerBase = (url: string) => url.replace(/\/$/, '');

async function relayerStatus(url: string): Promise<RelayerStatus> {
  const res = await fetch(`${relayerBase(url)}/status`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`relayer ${url}: HTTP ${res.status}`);
  return (await res.json()) as RelayerStatus;
}

/** tornado-cli's fee formula: 500k gas at the current price, plus the relayer's cut of the amount. */
function relayerFee(p: Pool, st: RelayerStatus, gasPrice: bigint, refund: bigint): bigint {
  const amount = parseUnits(p.amount, p.decimals);
  const cut = Number(st.tornadoServiceFee ?? 0);
  if (!Number.isFinite(cut) || cut < 0) throw new UsageError(`relayer advertises a nonsensical fee: ${st.tornadoServiceFee}`);
  const feePercent = (amount * BigInt(Math.round(cut * 1e6))) / 100_000_000n;
  const expense = gasPrice * 500_000n;
  if (!p.tokenAddress) return expense + feePercent;
  const price = st.ethPrices?.[p.currency];
  if (!price || !/^\d+$/.test(price) || BigInt(price) === 0n) {
    throw new UsageError(`relayer publishes no usable ETH price for ${p.currency}; pass --fee`);
  }
  return ((expense + refund) * 10n ** BigInt(p.decimals)) / BigInt(price) + feePercent;
}

type Job = { status?: string; txHash?: string; failedReason?: string; error?: string };

/**
 * Submit to a relayer and wait until the chain -- not the relayer -- says the
 * note is spent. tornado-relayer reports MINED before it checks whether the
 * transaction reverted, so its word is never taken as success.
 */
async function submitViaRelayer(
  net: RpcClient, p: Pool, url: string, body: object, nullifierHash: bigint,
): Promise<string> {
  const spent = () => read(net, p.address, TORNADO.isSpent, bytes32(nullifierHash));
  const base = relayerBase(url);

  const res = await fetch(`${base}/v1/tornadoWithdraw`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  let reply: { id?: string; error?: string } = {};
  try {
    reply = JSON.parse(text);
  } catch {
    // not JSON; reported below
  }
  if (!res.ok || !reply.id) {
    throw new Error(`relayer rejected the withdrawal (HTTP ${res.status}): ${reply.error ?? text.slice(0, 300)}`);
  }
  log(`relayer job ${reply.id}`);

  const deadline = Date.now() + 30 * 60_000;
  let unreachable = 0;
  let last = '';
  try {
    while (Date.now() < deadline) {
      await sleep(3000);
      let job: Job;
      try {
        const r = await fetch(`${base}/v1/jobs/${reply.id}`, { signal: AbortSignal.timeout(15_000) });
        job = (await r.json()) as Job;
        if (!r.ok) throw new Error(job.error ?? `HTTP ${r.status}`);
        unreachable = 0;
      } catch {
        // An unreachable relayer says nothing about the job; the chain decides below.
        if (++unreachable >= 10) break;
        continue;
      }
      if (job.status !== last) process.stderr.write(`\r  relayer: ${(last = job.status ?? '?')}          `);
      if (job.status === 'FAILED') {
        if (await spent()) return job.txHash ?? '(spent; relayer reported failure)';
        throw new Error(`relayer failed: ${job.failedReason ?? 'no reason given'} -- the note is NOT spent`);
      }
      // Look, don't wait: a relayer that bumps gas replaces the transaction,
      // and the job then carries the new hash.
      if (job.txHash && (job.status === 'MINED' || job.status === 'CONFIRMED')) {
        const receipt = (await net.call('eth_getTransactionReceipt', job.txHash)) as { status: string } | null;
        if (receipt) {
          const ok = BigInt(receipt.status) === 1n;
          const isSpent = await spent();
          if (ok && isSpent) return job.txHash;
          if (!ok && isSpent) return `(spent by another transaction; the relayer's ${job.txHash} reverted)`;
          if (!ok) throw new Error(`the relayer's transaction ${job.txHash} reverted -- the note is NOT spent`);
        }
      }
    }
  } finally {
    if (last) process.stderr.write('\n');
  }
  if (await spent()) return '(spent; the relayer never reported the transaction)';
  throw new Error(`could not confirm job ${reply.id} with ${base}. The note is not spent yet -- check \`uragan status\` before retrying.`);
}

type WithdrawOpts = SignerOpts & {
  relayer?: string;
  fee?: string;
  refund?: string;
  maxFeePercent: number;
  self?: boolean;
  dryRun?: boolean;
  threads: number;
};

async function withdraw(noteArg: string | undefined, recipientArg: string | undefined, o: WithdrawOpts) {
  if (!recipientArg) throw new UsageError('usage: uragan withdraw <note|-> <recipient> (--relayer URL | --self)');
  if (!o.relayer && !o.self) {
    throw new UsageError(
      'choose how to submit: --relayer URL (recommended), or --self, which pays gas from your own key and links it to this withdrawal',
    );
  }
  if (o.relayer && o.self) throw new UsageError('--relayer and --self are exclusive');
  const explicitFee = baseUnits('fee', o.fee);
  const refund = baseUnits('refund', o.refund) ?? 0n;
  if (explicitFee !== undefined && !o.relayer) throw new UsageError('--fee only applies with --relayer; with --self there is no one to pay');

  const n = parseNote(await readNote(noteArg));
  const recipient = checksummed(recipientArg);
  const [key, p] = notePool(n);
  // The contract requires msg.value == refund; ETH pools only accept 0.
  if (refund !== 0n && !p.tokenAddress) throw new UsageError('ETH pools require --refund 0 (refund is for token pools)');
  const amount = parseUnits(p.amount, p.decimals);
  const { net } = await connect(p.chainId);
  // Resolve a --self signer before syncing and proving, so a misconfigured
  // wallet or key fails in a second rather than after all that work.
  const signer = o.self && !o.dryRun ? await makeSigner(net, o) : undefined;

  const [spent, deposited] = await Promise.all([
    read(net, p.address, TORNADO.isSpent, bytes32(n.nullifierHash)),
    read(net, p.address, TORNADO.commitments, bytes32(n.commitment)),
  ]);
  if (spent) throw new UsageError('note already spent');
  if (!deposited) throw new UsageError('commitment not on chain -- was the deposit mined?');

  let relayer = ZERO_ADDRESS;
  let fee = 0n;
  if (o.relayer) {
    const st = await relayerStatus(o.relayer);
    if (st.netId !== undefined && Number(st.netId) !== p.chainId) {
      throw new UsageError(
        `relayer ${o.relayer} serves ${chainName(Number(st.netId))} (${st.netId}), but this note is for ${chainName(p.chainId)} (${p.chainId})`,
      );
    }
    relayer = checksummed(st.rewardAccount);
    if (explicitFee !== undefined) {
      fee = explicitFee;
    } else {
      const fees = await net.fees();
      fee = relayerFee(p, st, fees.type === 'eip1559' ? fees.maxFeePerGas : fees.gasPrice, refund);
      // The inputs to that formula are the relayer's own claims. Refuse a fee
      // above the cap unless the user raises it knowingly.
      const bps = (fee * 10_000n) / amount;
      if (bps > BigInt(Math.round(o.maxFeePercent * 100))) {
        const pct = (Number(bps) / 100).toFixed(2);
        throw new UsageError(
          `relayer fee ${formatUnits(fee, p.decimals)} ${p.symbol} is ${pct}% of the amount, above --max-fee-percent ` +
            `${o.maxFeePercent}. Pass --max-fee-percent ${Math.ceil(Number(pct))} to accept it, or set --fee yourself.`,
        );
      }
    }
    if (fee >= amount) throw new UsageError(`relayer fee ${fee} is not below the amount ${amount}`);
    log(`relayer ${relayer}, fee ${formatUnits(fee, p.decimals)} ${p.symbol} (${(Number((fee * 10_000n) / amount) / 100).toFixed(2)}%)`);
  }

  const tree = await poolTree(net, p, log);
  const index = tree.layers[0]!.findIndex((c) => c === n.commitment);
  if (index < 0) throw new Error('commitment missing from the synced leaves');
  log(`leaf ${index} of ${tree.layers[0]!.length}`);
  // The contract accepts only its last 100 roots. If ours is not among them the
  // leaf set is wrong, and submitting would burn gas on a guaranteed revert.
  if (!(await read(net, p.address, TORNADO.isKnownRoot, bytes32(tree.root)))) {
    throw new Error(`computed root ${hex32(tree.root)} is not known on-chain -- the leaf cache is stale or corrupt`);
  }

  const path = treePath(tree, index);
  // Exactly the public inputs the contract derives from the withdraw() arguments.
  const inputs = [tree.root, n.nullifierHash, BigInt(recipient), BigInt(relayer), fee, refund];
  log('computing witness ...');
  const w = witness({
    root: inputs[0], nullifierHash: inputs[1], recipient: inputs[2], relayer: inputs[3], fee, refund,
    nullifier: n.nullifier, secret: n.secret, pathElements: path.pathElements, pathIndices: path.pathIndices,
  });
  log(`proving on ${o.threads} threads ...`);
  const proof = await prove(w, o.threads);

  // Check with the verifier the pool calls, fed the inputs the contract will
  // compute -- not the prover's echo of them -- before any gas is spent.
  if (proof.publicSignals.length !== 6 || proof.publicSignals.some((s, i) => s !== inputs[i])) {
    throw new Error('the proof commits to different public inputs than the withdraw arguments -- aborting');
  }
  const proofBytes = fromHex(proof.proof);
  const verifierAt = await read(net, p.address, TORNADO.verifier);
  if (!(await read(net, verifierAt, VERIFIER.verifyProof, { proof: proofBytes, input: inputs as never }))) {
    throw new Error('proof rejected by the on-chain verifier -- aborting');
  }
  log('proof verified by the pool verifier');

  const args = {
    _proof: proofBytes, _root: bytes32(tree.root), _nullifierHash: bytes32(n.nullifierHash),
    _recipient: recipient, _relayer: relayer, _fee: fee, _refund: refund,
  };
  const calldata = TORNADO.withdraw.encodeInput(args);
  if (o.dryRun) {
    out(JSON.stringify({
      contract: p.address, recipient, relayer, fee: String(fee), refund: String(refund),
      value: String(o.self ? refund : 0n), // the refund rides along as msg.value
      calldata: hexBytes(calldata),
    }, null, 2));
    return;
  }

  if (o.relayer) {
    const hash = await submitViaRelayer(net, p, o.relayer, {
      contract: p.address,
      proof: proof.proof,
      args: [hex32(tree.root), hex32(n.nullifierHash), recipient, relayer, hex32(fee), hex32(refund)],
    }, n.nullifierHash);
    log(`withdrawn: ${hash}`);
    return;
  }

  log(`submitting from ${signer!.address} -- this links that address to the withdrawal`);
  log(`withdrawn: ${await signer!.send({ to: p.address, value: refund, data: calldata })}`);
}

async function relayers(urls: string[]) {
  if (!urls.length) throw new UsageError('usage: uragan relayers <url>...');
  out(`${'RELAYER'.padEnd(38)} ${'FEE%'.padEnd(6)} ${'CHAIN'.padEnd(6)} ${'UP'.padEnd(4)} REWARD ACCOUNT`);
  for (const u of urls) {
    try {
      const s = await relayerStatus(u);
      const up = String(s.health?.status) === 'true' ? 'yes' : 'no';
      out(`${u.padEnd(38)} ${String(s.tornadoServiceFee ?? '?').padEnd(6)} ${String(s.netId ?? '?').padEnd(6)} ${up.padEnd(4)} ${s.rewardAccount}`);
    } catch (e) {
      out(`${u.padEnd(38)} unreachable (${(e as Error).message})`);
    }
  }
}

// ---------------------------------------------------------------------------
const HELP = `uragan -- Tornado Cash from the command line

  setup                        fetch + verify circuit and keys, run selftest
  selftest                     crypto vectors, plus an offline prove + verify
  pools                        every pool, with live deposit counts
  verify                       re-check every pool address on-chain
  note <pool>                  generate a note offline (no transaction)
  deposit <pool>               generate a note and deposit
  sync <pool>                  pull Deposit events into the leaf cache
  status <note|->              deposited? spent? leaf index?
  withdraw <note|-> <to>       --relayer URL [--fee WEI] | --self   [--refund WEI] [--dry-run]
  relayers <url>...            query relayer /status endpoints

  --chain NAME                 the chain a <pool> is on: ethereum (default), optimism, arbitrum.
                               Notes carry their own chain
  --rpc-url URL                your own RPC instead of the public default -- a node, or a
                               wallet like Frame to sign. Without --chain, its chain is used
  --max-fee-percent N          refuse a relayer-computed fee above N% of the amount (default 5)
  --threads N                  prover threads (default: all cores)

signing (deposit, withdraw --self) -- a local key, or else the wallet at --rpc-url:
  --private-key PK             sign locally (visible in ps while running; prefer the env var)
  URAGAN_PRIVATE_KEY           the same, from the environment
  --account NAME               cast keystore (~/.foundry/keystores/NAME)
  --keystore FILE              any V3 keystore; password from URAGAN_KEYSTORE_PASSWORD or a prompt
  (no key)                     eth_sendTransaction to --rpc-url; the wallet signs.
                               --from ADDR picks the account (Frame: http://127.0.0.1:1248)

env: URAGAN_HOME, URAGAN_CHUNK, URAGAN_INSTANCES, URAGAN_ASSETS
Pass \`-\` for a note to read it from stdin, keeping it out of argv and shell history.`;

const OPTIONS = {
  relayer: { type: 'string' },
  fee: { type: 'string' },
  refund: { type: 'string' },
  'max-fee-percent': { type: 'string' },
  self: { type: 'boolean' },
  'dry-run': { type: 'boolean' },
  account: { type: 'string' },
  keystore: { type: 'string' },
  chain: { type: 'string' },
  'rpc-url': { type: 'string' },
  'private-key': { type: 'string' },
  from: { type: 'string' },
  threads: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
} as const;

async function main() {
  let parsed;
  try {
    parsed = parseArgs({ allowPositionals: true, options: OPTIONS });
  } catch (e) {
    throw new UsageError((e as Error).message); // unknown flag, missing value
  }
  const { values: v, positionals } = parsed;
  const [cmd, ...rest] = positionals;
  setRpcUrl(v['rpc-url']);
  const chain = v.chain === undefined ? undefined : parseChain(v.chain);
  const threads = intFlag('threads', v.threads, availableParallelism(), 1, 256);
  const maxFeePercent = v['max-fee-percent'] === undefined ? 5 : Number(v['max-fee-percent']);
  if (!(maxFeePercent >= 0 && maxFeePercent <= 100)) throw new UsageError('--max-fee-percent must be a number from 0 to 100');
  const sig: SignerOpts = {
    privateKey: v['private-key'], account: v.account, keystore: v.keystore,
    from: v.from === undefined ? undefined : checksummed(v.from),
  };

  switch (v.help ? 'help' : cmd) {
    case 'setup': return setup();
    case 'selftest': return selftest(threads);
    case 'pools': return poolsCmd(chain);
    case 'verify': return verifyCmd(chain);
    case 'note': return noteCmd(rest[0], chain);
    case 'deposit': return deposit(rest[0], chain, sig);
    case 'sync': return syncCmd(rest[0], chain);
    case 'status': return status(rest[0]);
    case 'withdraw':
      return withdraw(rest[0], rest[1], {
        ...sig, relayer: v.relayer, fee: v.fee, refund: v.refund, maxFeePercent,
        self: v.self, dryRun: v['dry-run'], threads,
      });
    case 'relayers': return relayers(rest);
    case undefined:
    case 'help': return out(HELP);
    default: throw new UsageError(`unknown command '${cmd}'\n\n${HELP}`);
  }
}

main().catch((e: Error) => {
  log(`error: ${e.message}`);
  if (process.env.DEBUG) log(e.stack ?? '');
  process.exit(e instanceof UsageError ? 2 : 1);
});
