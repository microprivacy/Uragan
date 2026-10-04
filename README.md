# Uragan

Lightweight and modern CLI for Tornado Cash.

## Features

- Ethereum, Optimism, Polygon and Arbitrum: all 31 pools
- Withdraw via a relayer (the cheapest that answers, by default), yourself, or a Safe
- Sign with Frame, a private key, a keystore or any wallet RPC
- Local multithreaded prover in pure JS (~10 s)
- Proofs checked on-chain before sending
- Resumable, reorg-safe sync
- 3 dependencies, bundled in: an install adds one package
- Node runs the sources as they are; only the published bundle is built

## Install

Requires Node ≥ 22.18.

```sh
pnpm i -g uragan
uragan setup   # download circuit + keys, check their pinned sha256
```

## Usage

```sh
uragan pools
uragan deposit eth-0.1 --chain optimism
uragan status
uragan withdraw - 0xRecipient < note.txt
```

Public RPCs are used by default, and Frame signs unless you pass a key. `--rpc-url` swaps in your own node, or a wallet that then also signs.
Withdrawals go through the cheapest default relayer that answers; `--relayer URL` names one, `--self` pays the gas yourself,
and `--safe SAFE` proposes the withdrawal to a Safe's owners, signed by Frame or your key.
Back up every note: it is the only way to withdraw. Run `uragan help` for all commands and options.

## License

MPL-2.0
