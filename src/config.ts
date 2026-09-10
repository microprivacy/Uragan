import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** A mistake in how the command was invoked -- printed without a stack trace. */
export class UsageError extends Error {}

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const ASSETS = process.env.URAGAN_ASSETS ?? join(ROOT, 'assets');
export const HOME = process.env.URAGAN_HOME ?? join(homedir(), '.local/share/uragan');

/**
 * The first eth_getLogs block range. Sync pages through history with ranges it
 * resizes by what comes back (see syncLeaves), so this only sets where it
 * starts: just under the 10k-block cap most public RPCs have.
 */
export const LOG_CHUNK = Number(process.env.URAGAN_CHUNK ?? 9500);

/**
 * Circuit and proving key from tornado-core's v2.1 release, pinned by sha256.
 * These exact bytes reproduce the verifying key deployed at
 * 0xce172ce1F20EC0B3728c9965470eaf994A03557A; setup refuses anything else.
 */
export const RELEASE = 'https://github.com/tornadocash/tornado-core/releases/download/v2.1';
export const ARTIFACTS: Record<string, string> = {
  'withdraw.json': '3ddd61dbff09caeec82d8edde95c674a3c34f9e66b1fe9f2c8783e72fe536f98',
  'withdraw_verification_key.json': '3eedcf6ec6b5c24219ed19c7a33966fbfa6a03ae7c84124270589091e87cf8d3',
  'tornado_no_zeros.params': 'ef0dbd36c0ad4e7f5e5cf0283f8cfba9eca8f9b6f67a8c786aafbc9665283050',
};

/**
 * Supported chains, each with the public RPC used unless --rpc-url is given.
 * Not the chains' own endpoints: those cap eth_getLogs at 10k blocks and
 * rate-limit hard. These serve archive logs over wide ranges without a key.
 */
const CHAINS: Record<number, { name: string; rpc: string }> = {
  1: { name: 'Ethereum', rpc: 'https://mainnet.gateway.tenderly.co' },
  10: { name: 'Optimism', rpc: 'https://optimism.gateway.tenderly.co' },
  42161: { name: 'Arbitrum', rpc: 'https://arbitrum.gateway.tenderly.co' },
};

export const chainName = (id: number) => CHAINS[id]?.name ?? `chain ${id}`;

/** A --chain value: a name (ethereum, optimism, arbitrum) or a chain id. */
export function parseChain(v: string): number {
  if (/^\d+$/.test(v)) return Number(v);
  const hit = Object.entries(CHAINS).find(([, c]) => c.name.toLowerCase() === v.toLowerCase());
  if (!hit) {
    const names = Object.values(CHAINS).map((c) => c.name.toLowerCase()).join(', ');
    throw new UsageError(`unknown chain '${v}' -- ${names}, or a chain id`);
  }
  return Number(hit[0]);
}

let rpcOverride: string | undefined;

export function setRpcUrl(url: string | undefined): void {
  rpcOverride = url;
}

export const customRpc = () => rpcOverride !== undefined;

/** --rpc-url if given, else the chain's default. */
export function rpcUrl(chain?: number): string {
  if (rpcOverride !== undefined) return rpcOverride;
  const url = chain === undefined ? undefined : CHAINS[chain]?.rpc;
  if (!url) {
    const known = Object.entries(CHAINS).map(([id, c]) => `${c.name} (${id})`).join(', ');
    throw new UsageError(`no default RPC for chain ${chain} -- supported: ${known}, or pass --rpc-url`);
  }
  return url;
}

export type Pool = {
  /** The chain the pool lives on; anything else touching it is refused. */
  chainId: number;
  currency: string;
  amount: string;
  address: string;
  deployedBlock: number;
  symbol: string;
  decimals: number;
  /** null for native-coin pools */
  tokenAddress: string | null;
};

/**
 * Pool registry: chain id -> pool name -> pool. Names repeat across chains
 * (eth-0.1 is on Ethereum, Optimism and Arbitrum), so the chain always comes
 * from context -- --chain, --rpc-url's chain, or a note's netId.
 * URAGAN_INSTANCES points it at a fork, testnet, or new deployment.
 */
function registry(): Record<string, Record<string, Omit<Pool, 'chainId'>>> {
  const file = process.env.URAGAN_INSTANCES ?? join(ROOT, 'src/instances.json');
  return JSON.parse(readFileSync(file, 'utf8'));
}

/** Registry chains that work without --rpc-url. */
export const defaultChains = (): number[] => Object.keys(registry()).map(Number).filter((id) => id in CHAINS);

export function pools(chainId: number): Record<string, Pool> {
  const chain = registry()[chainId];
  if (!chain) {
    const known = Object.keys(registry()).map((id) => `${chainName(Number(id))} (${id})`).join(', ');
    throw new UsageError(`no pools on chain ${chainId} -- supported: ${known}`);
  }
  return Object.fromEntries(Object.entries(chain).map(([key, p]) => [key, { ...p, chainId }]));
}

export function pool(chainId: number, key: string): Pool {
  const p = pools(chainId)[key];
  if (!p) throw new UsageError(`no pool '${key}' on ${chainName(chainId)} (see: uragan pools)`);
  return p;
}
