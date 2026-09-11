/**
 * Worker side of the threaded prover (see prover.ts). Two roles:
 *   rayon        adopt a stack + TLS, then serve rayon's pool forever
 *   coordinator  call prove(), which fans out over that pool
 */
import { parentPort, workerData } from 'node:worker_threads'
import { adopt, readString } from './prover-wasm.ts'

const { role, module, memory, stackTop, tls, args } = workerData as {
  role: 'rayon' | 'coordinator'
  module: WebAssembly.Module
  memory: WebAssembly.Memory
  stackTop: number
  tls: number
  args: number[]
}

const x = adopt(module, memory, stackTop, tls)

if (role === 'rayon') {
  parentPort!.postMessage('parked')
  x.worker_run() // never returns
} else {
  try {
    parentPort!.postMessage({ packed: x.prove(...(args as Parameters<typeof x.prove>)) })
  } catch (e) {
    x.__stack_pointer.value = stackTop // a trap leaves it mid-unwind
    const err = x.last_error()
    const msg = err ? readString(memory, err) : (e as Error).message
    parentPort!.postMessage({ error: msg })
  }
}
