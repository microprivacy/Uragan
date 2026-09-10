//! Tornado Cash Groth16 prover as a wasm32-unknown-unknown module.
//!
//! A thin export shim over upstream zkutil. No WASI and no wasm-bindgen: the
//! host copies inputs into linear memory with `alloc`, calls `prove`, and reads
//! a JSON result back. The only import is the shared memory itself.
//!
//! Threads: bellman's pool is rayon (see the patched bellman_ce). The host
//! runs each rayon thread as a Node worker over the same shared memory; see
//! `init_threads` for the handshake.
//!
//! The Groth16 blinding factors are drawn from a 32-byte seed the host passes
//! in, so the entropy source lives on the host side where it can be seen and
//! tested -- not inside this module.

use std::io::Cursor;
use std::sync::{Condvar, Mutex};

use bellman_ce::pairing::bn256::Bn256;
use rand::{ChaChaRng, SeedableRng};
use zkutil::circom_circuit::{
    load_params, proof_to_json, prove as groth16_prove, r1cs_from_json, witness_from_json,
    CircomCircuit,
};

/// Last panic message from any thread. Global rather than thread-local: a
/// panic on a rayon worker must be readable from whichever thread reports it.
static LAST_ERROR: Mutex<Option<Box<[u8]>>> = Mutex::new(None);

/// rayon threads waiting for a host thread to adopt them; see `init_threads`.
static QUEUE: Mutex<Vec<rayon::ThreadBuilder>> = Mutex::new(Vec::new());
static QUEUED: Condvar = Condvar::new();

/// Build rayon's global pool with `n` threads. wasm cannot create threads, so
/// the spawn handler only queues each one for a host thread to adopt.
///
/// Ordering matters: `build_global` blocks until every thread is running
/// (rayon's `wait_until_primed`). So the host must first start `n` workers --
/// each instantiating this module over the same shared memory, setting its own
/// stack and TLS, then parking in `worker_run` -- and only then call this.
/// Returns 0 on success.
///
/// Must run before the first proof: bellman sizes its work to the pool, and
/// rayon's default pool would try to spawn OS threads and fail.
#[no_mangle]
pub extern "C" fn init_threads(n: usize) -> i32 {
    std::panic::set_hook(Box::new(|info| {
        if let Ok(mut e) = LAST_ERROR.lock() {
            *e = Some(info.to_string().into_bytes().into_boxed_slice());
        }
    }));
    let built = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .spawn_handler(|thread| {
            QUEUE.lock().unwrap().push(thread);
            QUEUED.notify_one();
            Ok(())
        })
        .build_global();
    if built.is_ok() { 0 } else { -1 }
}

/// Park until `init_threads` queues a rayon thread, adopt it, and serve the
/// pool until it shuts down.
#[no_mangle]
pub extern "C" fn worker_run() {
    let thread = {
        let mut queue = QUEUE.lock().unwrap();
        loop {
            if let Some(t) = queue.pop() {
                break t;
            }
            queue = QUEUED.wait(queue).unwrap();
        }
    };
    thread.run();
}

/// Aligned, zeroed memory for per-thread stacks and TLS blocks. Never freed:
/// they live as long as the pool.
#[no_mangle]
pub extern "C" fn alloc_aligned(size: usize, align: usize) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(size, align).expect("bad layout");
    unsafe { std::alloc::alloc_zeroed(layout) }
}

/// Pack a boxed byte slice as `(ptr << 32) | len` and leak it to the host.
fn leak(bytes: Box<[u8]>) -> u64 {
    let len = bytes.len() as u64;
    let ptr = Box::into_raw(bytes) as *mut u8 as u64;
    (ptr << 32) | len
}

/// Allocate `len` zeroed bytes in linear memory for the host to fill.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// Free a buffer from `alloc`, or a result returned by `prove` / `last_error`.
///
/// # Safety
/// `ptr`/`len` must describe exactly one live allocation made by this module.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
}

/// The message of the last panic, packed like `prove`'s result; 0 if none.
/// A panic surfaces to the host as a bare `unreachable` trap, so this is the
/// only way to learn what actually went wrong.
#[no_mangle]
pub extern "C" fn last_error() -> u64 {
    LAST_ERROR.lock().ok().and_then(|mut e| e.take()).map_or(0, leak)
}

/// Prove. Inputs are the circuit JSON (circom 1.x), the bellman params file,
/// the witness JSON, and a 32-byte seed. Returns UTF-8 JSON
/// `{"proof":{...},"public":[...]}` packed as `(ptr << 32) | len`.
///
/// # Safety
/// Each pointer must address the stated number of bytes; `seed_ptr` needs 32.
#[no_mangle]
pub unsafe extern "C" fn prove(
    circuit_ptr: *const u8,
    circuit_len: usize,
    params_ptr: *const u8,
    params_len: usize,
    witness_ptr: *const u8,
    witness_len: usize,
    seed_ptr: *const u8,
) -> u64 {
    let bytes = |ptr: *const u8, len: usize| std::slice::from_raw_parts(ptr, len);

    let seed: Vec<u32> = bytes(seed_ptr, 32)
        .chunks(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    let rng = ChaChaRng::from_seed(&seed[..]);

    let params = load_params(Cursor::new(bytes(params_ptr, params_len)));
    let circuit = CircomCircuit::<Bn256> {
        r1cs: r1cs_from_json(Cursor::new(bytes(circuit_ptr, circuit_len))),
        witness: Some(witness_from_json::<Bn256, _>(Cursor::new(bytes(
            witness_ptr,
            witness_len,
        )))),
        wire_mapping: None,
    };
    let public = circuit.get_public_inputs_json();
    let proof = groth16_prove(circuit, &params, rng).expect("proving failed");
    let json = format!(
        "{{\"proof\":{},\"public\":{}}}",
        proof_to_json(&proof).expect("proof serialization failed"),
        public
    );
    leak(json.into_bytes().into_boxed_slice())
}
