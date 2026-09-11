/** Wasm plumbing shared by the prover host and its workers -- no heavy imports. */

/** Pinned by prover/build.sh (--initial-memory / --max-memory). */
export const MEMORY = { initial: 256, maximum: 32768 }

export type Exports = {
  __stack_pointer: WebAssembly.Global
  __tls_size: WebAssembly.Global
  __tls_align: WebAssembly.Global
  __wasm_init_tls: (tls: number) => void
  alloc: (len: number) => number
  alloc_aligned: (size: number, align: number) => number
  init_threads: (n: number) => number
  worker_run: () => void
  last_error: () => bigint
  prove: (cPtr: number, cLen: number, pPtr: number, pLen: number, wPtr: number, wLen: number, seedPtr: number) => bigint
}

export const utf8 = new TextDecoder()

/** Decode a `(ptr << 32) | len` result. SharedArrayBuffer views can't be decoded directly, so copy. */
export const readString = (memory: WebAssembly.Memory, packed: bigint): string => {
  const ptr = Number(packed >> 32n)
  const len = Number(packed & 0xffffffffn)
  return utf8.decode(new Uint8Array(memory.buffer, ptr, len).slice())
}

/**
 * Instantiate the module on this thread and give it its own stack and TLS
 * before any Rust runs. Every instance starts with __stack_pointer at the top
 * of the main thread's static stack and __tls_base = 0; running code first
 * would scribble over main's live frames. The start function that runs during
 * instantiation touches neither.
 */
export function adopt(module: WebAssembly.Module, memory: WebAssembly.Memory, stackTop: number, tls: number): Exports {
  const x = new WebAssembly.Instance(module, { env: { memory } }).exports as unknown as Exports
  x.__stack_pointer.value = stackTop
  x.__wasm_init_tls(tls)
  return x
}
