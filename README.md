# Uragan

A Tornado Cash client for the command line. TypeScript on Node, noble
cryptography, and a Groth16 prover compiled to WebAssembly.

Wallet UIs still refuse to touch these contracts because of a sanctions listing
that no longer exists. The contracts are immutable and on-chain; this talks to
them directly.

```
src/            TypeScript, run directly by Node (types stripped at load)
  micro-eth-signer   RPC, ABI, transaction signing
  micro-zk-proofs    Pedersen, MiMC, circom witness generation
prover/         upstream zkutil for wasm32 with shared-memory threads
```

## Which domain is the real one?

**Neither `tornado.cash` nor `tornadocash.space`. Do not use either.**

`tornado.cash` was allowed to expire after the 2022 sanctions, was re-registered
by an attacker, and served a phishing frontend that harvested withdrawal notes —
draining 1,010 ETH from a single user in August 2026, with roughly 4,000 ETH
taken by similar operations over the preceding year. The contracts are fine; the
*frontend* is what steals your note.

The only root of trust is on-chain. `tornadocash.eth` is owned by the TORN
governance contract, so its contenthash can only be changed by a DAO vote:

```console
$ set nd (cast namehash tornadocash.eth)
$ set reg 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e

$ cast call $reg "owner(bytes32)(address)" $nd
0x5efda50f22d34F262c29268506C5Fa42cB56A1Ce      # TORN governance
$ cast call 0x5efda50f22d34F262c29268506C5Fa42cB56A1Ce "torn()(address)"
0x77777FeDdddFfC19Ff86DB637967013e6C6A116C      # the real TORN token

$ cast call (cast call $reg "resolver(bytes32)(address)" $nd) "contenthash(bytes32)(bytes)" $nd
0xe30101701220c3a350e49a11cfc9cab672331d51ad1b723e0d3db9cd73a316ebaa7788595fe8
```

That contenthash is IPFS CID `bafybeigduniojgqrz7e4vntsgmovdli3oi7a2pnzzvz2gfxlvj3yqwk75a`.
This client never opens a frontend; that is a one-time check for the web UI.

`github.com/tornadocash` is the genuine source org, but every repo is **archived
and frozen at August 2022**. This client pins its circuit and keys to that
org's `tornado-core` v2.1 release by sha256.

Sanctions status: OFAC delisted Tornado Cash in March 2025 following
*Van Loon v. Treasury*. Interacting with it is not sanctions-evasion. Plenty of
exchanges and analytics vendors still flag deposits from these pools, which is a
separate, real consideration — that is a counterparty problem, not a legal one.

## Setup

Requires Node ≥ 22.18 and pnpm. No Rust — the prover ships prebuilt.

```console
$ pnpm install
$ ln -s $PWD/src/cli.ts ~/.local/bin/uragan
$ uragan setup                # fetch + sha256-check circuit and keys, run selftest
$ set -x ETH_RPC_URL https://your-rpc
```

`setup` pulls three files (~29 MB) from the `tornado-core` v2.1 release — the
circuit, the production trusted-setup key, and the verification key — and
refuses any whose sha256 differs from the value pinned in `src/config.ts`. It
then runs `selftest`, which proves a synthetic withdrawal and verifies it
offline.

Node only strips TypeScript types for files outside `node_modules`, so link the
command to a checkout rather than installing it as a package. Node follows the
symlink to the real file, so imports resolve from the checkout.

## Use

```console
$ uragan pools                    # pools with live deposit counts
$ uragan verify                   # re-check every pool address on-chain
$ uragan note eth-0.1             # generate a note, no transaction
$ uragan deposit eth-0.1
$ uragan status -  < note.txt     # deposited? spent? leaf index?
$ uragan withdraw - 0xRecipient --relayer https://...  < note.txt
$ uragan withdraw - 0xRecipient --self --dry-run      < note.txt
```

Pass `-` for a note to read it from stdin. An argument lands in your shell
history and in `/proc/<pid>/cmdline`, which any local user can read.

Every pool in the registry carries the chain it lives on, and every command
checks the RPC's chain id against it first. On the wrong chain a pool address
is just an empty account: a deposit there would succeed as a plain transfer and
the funds would be gone. `deposit` also confirms the address holds a Tornado
pool of the expected denomination, and dry-runs the deposit before it creates a
note. For token pools it approves exactly the denomination, first resetting a
stale non-zero allowance to 0, since USDT reverts any change from one non-zero
allowance to another.

Addresses must pass their EIP-55 checksum if they are mixed-case. A typo'd
recipient is bound into the proof and paid irreversibly, so it is rejected
rather than "fixed".

### RPC and signing

`--rpc-url URL` sets the endpoint for everything — reads, log sync, and
transactions — and takes precedence over `ETH_RPC_URL`.

`deposit` and `withdraw --self` send transactions, signed one of two ways,
like `cast send`:

- **A local key** — signed here and broadcast raw:
  - `--private-key PK` — convenient, but readable by other local users in
    `/proc/<pid>/cmdline` while it runs, and saved in your shell history
  - `URAGAN_PRIVATE_KEY` — the same key, kept out of argv
  - `--account NAME` — a `cast wallet import` keystore in `~/.foundry/keystores`
  - `--keystore FILE` — any Web3 Secret Storage (V3) keystore, decrypted by
    micro-eth-signer; the password comes from `URAGAN_KEYSTORE_PASSWORD` or a
    no-echo prompt on `/dev/tty`
- **No key — the wallet at `--rpc-url`** signs, via `eth_sendTransaction`. It
  fills in gas and fees and asks you to approve. `--from ADDR` picks the
  account; the default is the wallet's first.

```console
$ uragan deposit eth-0.1 --rpc-url http://127.0.0.1:1248     # Frame signs
```

The signer is resolved before anything else happens, so a missing account or a
wrong keystore password fails without creating a note. Everything goes through
that one RPC, including `sync` — so if your wallet's upstream node caps
`eth_getLogs`, syncing a large pool is limited by it.

Transient RPC failures (429s, dropped connections, 502/503/504, a request
hanging past 60 s) are retried with backoff. `eth_sendTransaction` is the
exception: a retry after the wallet already sent would send twice. A raw
broadcast that errors is checked against the node before it is reported as a
failure, because a retried broadcast of a transaction the node already took
comes back as "already known" or "nonce too low".

Locally signed transactions pay at most 2× the base fee plus the tip. That is a
ceiling, so a couple of full blocks cannot strand them, and you are charged only
the actual base fee plus the tip.

### Withdrawing

`withdraw` makes you choose how the transaction gets submitted:

- `--relayer URL` — a third party submits it and takes a fee out of the
  withdrawal. The recipient never needs gas, so it stays unlinked. This is the
  reason to use Tornado at all. The fee defaults to tornado-cli's formula
  (500k gas at the current price, plus the relayer's advertised cut). The
  inputs to that formula are the relayer's own claims, so a result above
  `--max-fee-percent` of the amount (default 5) is refused. Raise the cap
  knowingly, or set the fee yourself with `--fee WEI`.
- `--self` — you submit it. **This pays gas from your own key, which publicly
  links that key to the withdrawal.** `--self --dry-run` needs no key at all:
  it prints the calldata and the `value` to send.

`--refund WEI` is ETH forwarded to the recipient of a token withdrawal, so it
can pay gas later. It applies to token pools only.

A relayer's word is never taken as success. tornado-relayer reports `MINED`
before it checks whether the transaction reverted, so `withdraw` polls the job
and then asks the chain. It reports success only once `isSpent()` is true, and
reports a reverted relayer transaction as "NOT spent". A job that says `FAILED`
is double-checked the same way, and so is a relayer that stops answering. The
job's transaction hash is re-read on every poll, because relayers replace
transactions to bump gas.

Withdrawal needs the pool's full leaf set to rebuild the Merkle tree. The first
`sync` of a large pool takes a while: public RPCs cap `eth_getLogs` at ~10k
blocks, so `eth-1` (92k deposits over 16M blocks) is about 1,800 requests, and
the RPC must serve archive logs. Sync runs four ranges at a time. It splits any
range the provider rejects as too wide, resumes where it stopped, and stops as
soon as it holds `nextIndex()` leaves — most pools went quiet years ago. If
your provider allows wider ranges:

```console
$ set -x URAGAN_CHUNK 100000
```

The cache lives in `$URAGAN_HOME/cache/<chainId>-<pool address>.*`:

- **`.leaves`** — each leaf with the block it came from.
- **`.block`** — the resume mark. It never passes 12 blocks behind the head, and
  leaves above it count as provisional, so each sync fetches them again. A
  reorg that swaps the deposit at an index heals on the next run, because a
  count of leaves could not tell the difference. If leaves are missing below the
  mark (a lost or edited file), sync rescans from the pool's deployment.
- **`.tree`** — the Merkle tree. The first build for `eth-1` takes about a
  minute; after that a withdrawal rehashes only the leaves that changed. Before
  proving, the root is checked with `isKnownRoot()`.

## The prover

Tornado's circuit is circom 1.x, and its proving key exists only in formats
from 2019–2020. `prover/` is [zkutil](https://github.com/poma/zkutil) — the
bellman-based prover by a Tornado author — compiled to `wasm32-unknown-unknown`
with shared-memory threads. It is upstream source plus two small patches,
applied to pristine crates.io sources by `prover/build.sh`:

- **`clap-v3` 3.0.0-beta.1** — one-line cfg. It declared its wasm32 `OsStr`
  fallback but implemented it only for windows. zkutil's library never calls
  clap; it just has to compile.
- **`bellman_ce` 0.3.5** — its thread pool (`src/multicore.rs` only) swapped
  from a futures pool and crossbeam to rayon, so the host can supply the
  threads. No curve or field code changes. A proof for a fixed seed is
  byte-identical at every thread count.

Each rayon thread is a Node worker running an instance of the same module over
shared memory (`src/prover.ts`). The module imports only its memory. The
Groth16 blinding factors come from a 32-byte seed the host passes in from
`node:crypto`, so the entropy source is visible and testable rather than buried
in 2019 `rand`.

A withdrawal proof takes ~3 s on 16 threads (8 s on one). What remains is mostly
serde parsing the 19 MB circuit JSON on every proof.

`tornado_prover.wasm` is committed so users need no Rust. To rebuild it you need
a nightly toolchain with `rust-src` and the wasm32 target — std must be rebuilt
with atomics — and `prover/build.sh` prints the toolchain it used alongside the
sha256.

### Why not micro-zk-proofs for proving too

It implements Groth16, but its legacy `polsA/polsB/polsC` prover produces
proofs that **its own verifier rejects** when given Tornado's published proving
key. Isolated by differential test: the same witness — byte-identical between
the two implementations — yields a valid proof through zkutil and an invalid
one through `createProof`. Ruled out packing order, point negation, field
naming, polynomial layout, the `null` entries in `C`, the 786 + 9,611 points at
infinity, and `hExps` length. Its own `setup -> prove -> verify` roundtrip
passes and its verifier accepts a zkutil proof, so the defect is specific to
consuming external old-snarkjs keys — most likely an FFT root-of-unity mismatch,
which would corrupt only `H` (and so `pi_c`) while leaving the proof
structurally valid. It is also ~17x slower here.

## Verification

Trusting a downloaded proving key is exactly the sort of thing that loses money,
so the claims here are checkable:

**The proving key matches the deployed verifier.** zkutil regenerates, from
`tornado_no_zeros.params`, the verifying key deployed at
`0xce172ce1F20EC0B3728c9965470eaf994A03557A` — all 8 sampled constants
(`alfa1`, `delta2`, `IC[0]`, `IC[6]`, …) appear in its bytecode.

**Every proof is checked before it costs gas.** `withdraw` checks the computed
root with `isKnownRoot()`, so a stale leaf cache fails loudly instead of
reverting on-chain. It then checks that the proof's public inputs are exactly
the ones the contract will derive from the `withdraw()` arguments, calls the
pool's own `verifier()` with them and the packed proof, and aborts if it
returns false.

**The primitives match the chain.** `verify` re-checks all 19 pool
denominations and tree heights. `selftest` checks Pedersen, MiMC and the
`zeros[19]` value the deployed contract reports, then proves and verifies a
withdrawal offline. A Merkle root built from real scanned Deposit events
reproduced the contract's `getLastRoot()` exactly.

**It works end to end on a mainnet fork.** The full flow was exercised against
byte-identical clones of the real `eth-0.1`, `dai-100` and `usdt-100` pools on
an anvil fork:

- deposits through all three signers (key, keystore, wallet RPC)
- withdrawals via `--self` and via a relayer
- USDT deposits over a stale non-zero allowance, and a token withdrawal with an
  ETH refund
- relayers that lie: `MINED` on a reverted transaction, `FAILED` on one that
  landed, and one that goes silent after submitting
- an RPC proxy that answers every third request with a 429, caps log ranges at
  1,000 blocks, and returns a 502 after forwarding the raw transaction
- a reorg that replaces a cached leaf with a different deposit
- a refused double-spend

Every recipient received exactly the denomination, less the relayer fee.

### Testing on a fork

Two traps, both of which bit while testing:

- **Clone a pool from its creation transaction and you get its *launch*
  state.** The 2019 pools shipped with an operator who later swapped in the
  trusted-setup verifier and then renounced the role. Replay that history on the
  clone (`updateVerifier`, `changeOperator(0)`) or no valid proof will verify.
  The operator differs from pool to pool; read `operator()` from the clone and
  impersonate that address.
- **anvil's default accounts are compromised on mainnet.** Their keys are
  public, and all four are EIP-7702-delegated to a sweeper that forwards any
  incoming ETH elsewhere — a fork inherits that. Use them only to *send*; give
  every recipient and relayer a fresh address.

## Safety notes

- **The note is the money.** `deposit` writes it to `$URAGAN_HOME/notes/` with
  mode 0600 *before* broadcasting, but back it up. Lose it and the funds are
  unrecoverable — there is no reset.
- **Never paste a note into a website.** That is precisely how the phishing
  sites above drained people. This client only ever sends a *proof*.
- Depositing and withdrawing the same unusual amount, or withdrawing right
  after depositing, deanonymizes you regardless of the cryptography. Anonymity
  comes from the size of the set and the time you sit in it — see `pools`.
- `--self` links your gas-paying key to the withdrawal. Prefer a relayer.
- If a withdrawal errors out, run `uragan status` before retrying. The error
  says whether the note is spent, but the chain is the authority.

## Layout

```
src/cli.ts              commands
src/chain.ts            RPC transport, contract bindings, Deposit-log sync
src/crypto.ts           notes and the Merkle tree
src/prover.ts           witness + threaded wasm host
src/prover-worker.ts    rayon / coordinator worker
src/signer.ts           private key, keystore, external wallet
src/instances.json      the 19 mainnet pools with their chain id, verified on-chain
prover/                 Rust shim, patches, build.sh, tornado_prover.wasm
assets/                 circuit + keys (downloaded by setup, gitignored)
```

Environment:

| Variable | Purpose |
| --- | --- |
| `ETH_RPC_URL` | the RPC, unless `--rpc-url` is given |
| `URAGAN_PRIVATE_KEY` | local signing key |
| `URAGAN_KEYSTORE_PASSWORD` | keystore password |
| `URAGAN_HOME` | notes and cache; default `~/.local/share/uragan` |
| `URAGAN_CHUNK` | `eth_getLogs` block range |
| `URAGAN_INSTANCES` | an alternative pool registry, e.g. for a fork or testnet; entries use the shape of `src/instances.json`, including `chainId` |
| `URAGAN_ASSETS` | where circuit and keys live |

## License

GPL-3.0, matching tornado-core. micro-zk-proofs, micro-eth-signer and zkutil are
MIT.
