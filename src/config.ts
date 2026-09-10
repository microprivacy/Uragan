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
 * Most public RPCs cap eth_getLogs at 10k blocks, so stay just under. Raise it
 * if your provider allows wider ranges -- it is the single biggest sync speedup.
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

let rpcOverride: string | undefined;

/** --rpc-url, which takes precedence over ETH_RPC_URL. */
export function setRpcUrl(url: string | undefined): void {
  rpcOverride = url;
}

export function rpcUrl(): string {
  const url = rpcOverride ?? process.env.ETH_RPC_URL;
  if (!url) throw new UsageError('no RPC: pass --rpc-url URL or set ETH_RPC_URL');
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
  /** null for native-ETH pools */
  tokenAddress: string | null;
};

/** Pool registry. URAGAN_INSTANCES points it at a fork, testnet, or new deployment. */
export function pools(): Record<string, Pool> {
  const file = process.env.URAGAN_INSTANCES ?? join(ROOT, 'src/instances.json');
  return JSON.parse(readFileSync(file, 'utf8'));
}

export function pool(key: string): Pool {
  const p = pools()[key];
  if (!p) throw new UsageError(`unknown pool '${key}' (see: uragan pools)`);
  return p;
}
