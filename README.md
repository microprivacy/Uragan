# Uragan

Lightweight and modern CLI for Tornado Cash.

## Features

- Ethereum, Optimism and Arbitrum: all 27 pools
- Withdraw via a relayer (the cheapest that answers, by default), yourself, or a Safe
- Sign with Frame, a private key, a keystore or any wallet RPC
- Local multithreaded prover in pure JS (~10 s)
- Proofs checked on-chain before sending
- Resumable, reorg-safe sync
- 3 dependencies, no build step

## Install

Requires Node ≥ 22.18.

```sh
pnpm install
ln -s $PWD/src/cli.ts ~/.local/bin/uragan
uragan setup   # download circuit + keys, check their pinned sha256
```

## Usage

```sh
uragan pools
uragan deposit eth-0.1 --chain optimism
uragan status - < note.txt
uragan withdraw - 0xRecipient < note.txt
```

Public RPCs are used by default, and Frame signs unless you pass a key. `--rpc-url` swaps in your own node, or a wallet that then also signs.
Withdrawals go through the cheapest default relayer that answers; `--relayer URL` names one, `--self` pays the gas yourself,
and `--safe SAFE` proposes the withdrawal to a Safe's owners, signed by Frame or your key.
Back up every note: it is the only way to withdraw. Run `uragan help` for all commands and options.

## License

GPL-3.0
