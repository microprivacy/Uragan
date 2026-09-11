# Uragan

Lightweight and modern CLI for Tornado Cash.

## Features

- Ethereum, Optimism and Arbitrum: all 27 pools
- Withdraw via relayer or yourself
- Sign with a private key, keystore or wallet RPC
- Local multithreaded WASM prover (~3 s)
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
uragan withdraw - 0xRecipient --relayer https://relayer.example < note.txt
```

Public RPCs are used by default; pass `--rpc-url` for your own node, or a wallet like Frame to sign.
Back up every note: it is the only way to withdraw. Run `uragan help` for all commands and options.

## License

GPL-3.0
