/**
 * Transaction signing, the way `cast send` does it: either a local key, or the
 * wallet behind the RPC URL.
 *
 * Local key -- sign here and broadcast raw:
 *   --private-key PK             visible in /proc/<pid>/cmdline while running
 *                                and saved in shell history
 *   URAGAN_PRIVATE_KEY           the same key, kept out of argv
 *   --account NAME | --keystore  Web3 Secret Storage (V3) keystore -- the format
 *                                `cast wallet import` writes to ~/.foundry/keystores
 *
 * No key -- send eth_sendTransaction to --rpc-url and let the wallet sign
 * (Frame, a hardware-wallet bridge, anvil). --from picks the account; by
 * default it is the wallet's first.
 */
import { openSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { ReadStream } from 'node:tty';
import { addr, Transaction } from 'micro-eth-signer';
import { privFromLegacyKeystore } from 'micro-eth-signer/keystore.js';
import type { RpcClient } from 'micro-eth-signer/net.js';
import { urlOf } from './chain.ts';
import { UsageError } from './config.ts';

export type Call = { to: string; value?: bigint; data?: Uint8Array };

export type Signer = {
  address: string;
  /** Send, wait for the receipt, and return the hash. Throws if it reverts. */
  send(call: Call): Promise<string>;
};

export type SignerOpts = { privateKey?: string; account?: string; keystore?: string; from?: string };

const hexData = (d?: Uint8Array) => (d ? `0x${Buffer.from(d).toString('hex')}` : '0x');

/**
 * Resolve the signer up front -- including the wallet's account -- so a
 * misconfiguration fails before anything is created or sent.
 */
export async function makeSigner(net: RpcClient, o: SignerOpts): Promise<Signer> {
  const pk = o.privateKey ?? process.env.URAGAN_PRIVATE_KEY;
  if (pk) return localSigner(net, pk.startsWith('0x') ? pk : `0x${pk}`);
  if (o.account || o.keystore) {
    const file = o.keystore ?? join(homedir(), '.foundry/keystores', o.account!);
    const keystore = JSON.parse(readFileSync(file, 'utf8'));
    try {
      // nonStrict: accept keystores whose JSON keys vary in case, as some tools write them
      return localSigner(net, await privFromLegacyKeystore(keystore, await password(file), true));
    } catch (e) {
      if (e instanceof UsageError) throw e;
      throw new UsageError(`cannot decrypt ${file}: ${(e as Error).message}`);
    }
  }
  return walletSigner(net, o.from);
}

/** Long enough for a congested block or two; past this the tx was likely dropped or replaced. */
const RECEIPT_TIMEOUT_MS = 15 * 60_000;

async function confirm(net: RpcClient, hash: string): Promise<string> {
  let receipt;
  try {
    receipt = await net.waitForReceipt(hash, { timeoutMs: RECEIPT_TIMEOUT_MS });
  } catch (e) {
    throw new Error(
      `transaction ${hash} was not mined within ${RECEIPT_TIMEOUT_MS / 60_000} min -- it may have been ` +
        `dropped or replaced (e.g. "speed up" in a wallet), or may still land: ${(e as Error).message}`,
    );
  }
  if (!receipt.status) throw new Error(`transaction ${hash} reverted`);
  return hash;
}

function localSigner(net: RpcClient, privateKey: string | Uint8Array): Signer {
  const address = addr.fromPrivateKey(privateKey);
  return {
    address,
    async send({ to, value = 0n, data }) {
      // micro-eth-signer fills nonce, gas and fees. 'ethers_v6' is only the name
      // of its fee formula (ethers is not involved): maxFee = 2 x base fee + tip.
      // The default formula caps at 1.2 x, which a couple of full blocks outgrow,
      // leaving the tx stuck. The cap is a ceiling -- you still pay base + tip.
      const prepared = await net.prepare({ from: address, to, value, data: hexData(data) }, 'ethers_v6');
      const tx = Transaction.prepare({
        ...prepared,
        gasLimit: (prepared.gasLimit * 12n) / 10n, // unused gas is refunded; an undershoot reverts
      }).signBy(privateKey);
      const hash = tx.hash;
      try {
        await net.broadcast(tx);
      } catch (e) {
        // A broadcast retried after the node already took it fails -- "already
        // known" while pending, "nonce too low" once mined. Whatever the
        // wording: if the node has the transaction, wait for it.
        if (!(await net.call('eth_getTransactionByHash', hash).catch(() => null))) throw e;
      }
      return confirm(net, hash);
    },
  };
}

async function walletSigner(net: RpcClient, from?: string): Promise<Signer> {
  let accounts: string[] = [];
  try {
    accounts = ((await net.call('eth_accounts')) as string[]).map((a) => a.toLowerCase());
  } catch {
    // a plain node may not implement eth_accounts at all
  }
  const picked = from ?? accounts[0];
  if (!picked) {
    throw new UsageError(
      `no private key given, and ${urlOf(net)} has no accounts to sign with.\n` +
        '  pass --private-key / --account, or point --rpc-url at a wallet (Frame: http://127.0.0.1:1248)',
    );
  }
  if (from && accounts.length && !accounts.includes(from.toLowerCase())) {
    throw new UsageError(`${urlOf(net)} does not hold ${from}; it has ${accounts.join(', ')}`);
  }
  const address = addr.addChecksum(picked);
  return {
    address,
    async send({ to, value = 0n, data }) {
      // The wallet fills in nonce, gas and fees, and asks its user to approve.
      const hash = (await net.call('eth_sendTransaction', {
        from: address,
        to,
        value: `0x${value.toString(16)}`,
        data: hexData(data),
      })) as string;
      return confirm(net, hash);
    },
  };
}

/** URAGAN_KEYSTORE_PASSWORD, else a no-echo prompt on /dev/tty (stdin may be carrying the note). */
async function password(file: string): Promise<string> {
  const env = process.env.URAGAN_KEYSTORE_PASSWORD;
  if (env !== undefined) return env;
  let tty: ReadStream;
  try {
    tty = new ReadStream(openSync('/dev/tty', 'r'));
  } catch {
    throw new UsageError('no terminal for a password prompt; set URAGAN_KEYSTORE_PASSWORD');
  }
  process.stderr.write(`password for ${file}: `);
  tty.setRawMode(true);
  return new Promise((ok, fail) => {
    let pass = '';
    tty.on('data', (buf: Buffer) => {
      for (const ch of buf.toString('utf8')) {
        if (ch === '\r' || ch === '\n') {
          tty.setRawMode(false);
          tty.destroy();
          process.stderr.write('\n');
          return ok(pass);
        }
        if (ch === '\u0003') {
          tty.setRawMode(false);
          tty.destroy();
          return fail(new UsageError('aborted'));
        }
        if (ch === '\u007f' || ch === '\b') pass = pass.slice(0, -1);
        else pass += ch;
      }
    });
  });
}
