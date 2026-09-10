/**
 * Witness generation (micro-zk-proofs) and Groth16 proving (prover/*.wasm).
 *
 * The prover is upstream zkutil compiled to wasm32-unknown-unknown with
 * shared-memory threads; see prover/build.sh. It imports only its memory.
 * Each rayon thread is a Node worker running an instance of the same module
 * over that shared memory.
 *
 * Roles:
 *   main         instantiates first -- winning the module's data/TLS init --
 *                allocates every thread's stack + TLS, starts the workers, and
 *                never blocks on the proof itself
 *   rayon        one per pool thread (prover-worker.ts)
 *   coordinator  calls prove() (prover-worker.ts), so a trapped rayon thread
 *                surfaces as an error on main instead of a hang
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { generateWitness } from 'micro-zk-proofs/witness.js';
import { ASSETS, ROOT } from './config.ts';
import { type Exports, MEMORY, readString } from './prover-wasm.ts';

const RAYON_STACK = 2 << 20;
const COORD_STACK = 8 << 20; // prove() parses 19 MB of circuit JSON on this stack
const WASM = join(ROOT, 'prover/tornado_prover.wasm');

let circuitBytes: Buffer | undefined;
const circuit = () => (circuitBytes ??= readFileSync(join(ASSETS, 'withdraw.json')));

/** Compute the witness for the withdraw circuit. */
export function witness(input: Record<string, unknown>): bigint[] {
  return generateWitness(JSON.parse(circuit().toString('utf8')))(input);
}

export type RawProof = { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol?: string };

export type Proof = {
  /** 256 bytes, packed the way the Solidity verifier reads it */
  proof: `0x${string}`;
  publicSignals: bigint[];
  /** snarkjs-style JSON, for off-chain verification */
  raw: RawProof;
};

/**
 * websnark's Solidity packing: a0 a1 b01 b00 b11 b10 c0 c1. The G2 coordinates
 * are swapped; the naive order is not on the curve and reverts.
 */
function packProof(p: RawProof): `0x${string}` {
  const words = [p.pi_a[0], p.pi_a[1], p.pi_b[0]![1], p.pi_b[0]![0], p.pi_b[1]![1], p.pi_b[1]![0], p.pi_c[0], p.pi_c[1]];
  return `0x${words.map((w) => BigInt(w!).toString(16).padStart(64, '0')).join('')}`;
}

export async function prove(wit: bigint[], threads: number = availableParallelism()): Promise<Proof> {
  // rayon treats 0 as "pick a default", which here means a pool no worker ever
  // adopts, and build_global() would then wait for it forever.
  if (!Number.isInteger(threads) || threads < 1) throw new Error(`prover: threads must be a positive integer, got ${threads}`);
  const module = await WebAssembly.compile(readFileSync(WASM));
  const memory = new WebAssembly.Memory({ ...MEMORY, shared: true });
  // First instance: wins the init flag, so it owns the static stack and TLS.
  const x = new WebAssembly.Instance(module, { env: { memory } }).exports as unknown as Exports;

  const thread = (stackSize: number) => {
    const stack = x.alloc_aligned(stackSize, 16);
    return { stackTop: stack + stackSize, tls: x.alloc_aligned(x.__tls_size.value, x.__tls_align.value) };
  };
  const put = (bytes: Uint8Array): [number, number] => {
    const ptr = x.alloc(bytes.length);
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  };
  const spawn = (data: object) =>
    new Worker(new URL('./prover-worker.ts', import.meta.url), { workerData: { module, memory, ...data } });

  const workers: Worker[] = [];
  try {
    // 1. rayon threads first: build_global() blocks until every one is running.
    for (let i = 0; i < threads; i++) workers.push(spawn({ role: 'rayon', ...thread(RAYON_STACK) }));
    await Promise.all(workers.map((w) => new Promise((ok, fail) => (w.once('message', ok), w.once('error', fail)))));
    if (x.init_threads(threads) !== 0) throw new Error('prover: init_threads failed');

    // 2. inputs, then the coordinator. The seed drives the Groth16 blinding
    //    factors -- it is what makes the proof zero-knowledge.
    const args = [
      ...put(circuit()),
      ...put(readFileSync(join(ASSETS, 'tornado_no_zeros.params'))),
      ...put(Buffer.from(JSON.stringify(wit.map(String)))),
      put(randomBytes(32))[0],
    ];
    const coordinator = spawn({ role: 'coordinator', ...thread(COORD_STACK), args });
    workers.push(coordinator);
    const done = await new Promise<{ packed?: bigint; error?: string }>((ok, fail) => {
      coordinator.once('message', ok);
      // A trapped rayon thread never answers; without this the proof would hang.
      for (const w of workers) w.once('error', fail);
    });
    if (done.error !== undefined) throw new Error(`prover: ${done.error}`);

    const out = JSON.parse(readString(memory, done.packed!)) as { proof: RawProof; public: string[] };
    return { proof: packProof(out.proof), publicSignals: out.public.map(BigInt), raw: out.proof };
  } finally {
    await Promise.all(workers.map((w) => w.terminate()));
  }
}
