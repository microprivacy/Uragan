# Uragan

Lightweight and modern CLI for Tornado Cash.

## Features

- All 19 Ethereum mainnet pools: ETH, DAI, cDAI, USDC, USDT, WBTC
- Deposit, withdraw, check a note's status, list pools with live deposit counts
- Withdraw through a relayer or submit it yourself
- Relayer fees capped (`--max-fee-percent`, default 5%), and the outcome is confirmed on-chain rather than taken from the relayer
- Sign with a private key, a Foundry keystore, or any wallet RPC such as Frame
- Proofs generated locally by a multithreaded Groth16 prover in WebAssembly, in about 3 s, with no Rust or native build needed
- Every proof is checked against the pool's on-chain verifier before any gas is spent
- Circuit and proving key pinned by sha256 to the official tornado-core v2.1 release
- Chain id, pool, denomination and EIP-55 checksums verified before any funds move
- Notes saved to disk before a deposit is broadcast, and read from stdin to keep them out of shell history
- Fast, resumable sync: parallel log fetching, automatic range splitting for capped RPCs, rate-limit retries, a reorg-safe cache and an incremental Merkle tree
- Offline `selftest` that proves and verifies a withdrawal
- Three runtime dependencies (micro-eth-signer, micro-zk-proofs, @noble/curves); TypeScript runs directly on Node

## Install

Requires Node ≥ 22.18.

```sh
pnpm install
ln -s $PWD/src/cli.ts ~/.local/bin/uragan
uragan setup   # download and verify circuit + keys, run selftest
```

## Usage

```sh
export ETH_RPC_URL=https://your-rpc

uragan pools
uragan deposit eth-0.1
uragan status - < note.txt
uragan withdraw - 0xRecipient --relayer https://relayer.example < note.txt
```

Back up every note: it is the only way to withdraw. Run `uragan help` for all commands and options.

## License

GPL-3.0
