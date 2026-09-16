use pqc_slh_dsa::{SlhDsa, SlhDsaKeyGenSeed, SlhDsaParameterSet, SlhDsaPreHash};
use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MESSAGE: &[u8] = b"PQC-rs SLH-DSA S6 heap audit";
const CONTEXT: &[u8] = b"s6-memory";

struct CountingAllocator;

static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && TRACKING.load(Ordering::Relaxed) {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && TRACKING.load(Ordering::Relaxed) {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if TRACKING.load(Ordering::Relaxed) {
            record_deallocation(layout.size());
        }
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, old_layout, new_size) };
        if !new_pointer.is_null() && TRACKING.load(Ordering::Relaxed) {
            record_deallocation(old_layout.size());
            record_allocation(new_size);
        }
        new_pointer
    }
}

fn record_allocation(size: usize) {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    ALLOCATED_BYTES.fetch_add(size, Ordering::Relaxed);
    let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;

    let mut peak = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
    while live > peak {
        match PEAK_LIVE_BYTES.compare_exchange_weak(
            peak,
            live,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

fn record_deallocation(size: usize) {
    DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    DEALLOCATED_BYTES.fetch_add(size, Ordering::Relaxed);
    LIVE_BYTES.fetch_sub(size, Ordering::Relaxed);
}

fn reset_counters() {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    DEALLOCATIONS.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    DEALLOCATED_BYTES.store(0, Ordering::Relaxed);
    LIVE_BYTES.store(0, Ordering::Relaxed);
    PEAK_LIVE_BYTES.store(0, Ordering::Relaxed);
}

#[derive(Clone, Copy, Serialize)]
struct HeapMeasurement {
    allocations: usize,
    deallocations: usize,
    allocated_bytes: usize,
    deallocated_bytes: usize,
    live_bytes_at_snapshot: usize,
    peak_live_bytes: usize,
}

fn snapshot() -> HeapMeasurement {
    HeapMeasurement {
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
        deallocations: DEALLOCATIONS.load(Ordering::Relaxed),
        allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        deallocated_bytes: DEALLOCATED_BYTES.load(Ordering::Relaxed),
        live_bytes_at_snapshot: LIVE_BYTES.load(Ordering::Relaxed),
        peak_live_bytes: PEAK_LIVE_BYTES.load(Ordering::Relaxed),
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> (T, HeapMeasurement) {
    reset_counters();
    TRACKING.store(true, Ordering::SeqCst);

    let result = operation();

    TRACKING.store(false, Ordering::SeqCst);
    let measurement = snapshot();

    (result, measurement)
}

const PARAMETER_SETS: [SlhDsaParameterSet; 12] = [
    SlhDsaParameterSet::Sha2_128s,
    SlhDsaParameterSet::Sha2_128f,
    SlhDsaParameterSet::Sha2_192s,
    SlhDsaParameterSet::Sha2_192f,
    SlhDsaParameterSet::Sha2_256s,
    SlhDsaParameterSet::Sha2_256f,
    SlhDsaParameterSet::Shake128s,
    SlhDsaParameterSet::Shake128f,
    SlhDsaParameterSet::Shake192s,
    SlhDsaParameterSet::Shake192f,
    SlhDsaParameterSet::Shake256s,
    SlhDsaParameterSet::Shake256f,
];

#[derive(Serialize)]
struct Record<'a> {
    parameter_set: &'a str,
    operation: &'a str,
    allocations: usize,
    deallocations: usize,
    allocated_bytes: usize,
    deallocated_bytes: usize,
    live_bytes_at_snapshot: usize,
    peak_live_bytes: usize,
}

fn emit(parameter_set: SlhDsaParameterSet, operation: &'static str, m: HeapMeasurement) {
    let record = Record {
        parameter_set: parameter_set.name(),
        operation,
        allocations: m.allocations,
        deallocations: m.deallocations,
        allocated_bytes: m.allocated_bytes,
        deallocated_bytes: m.deallocated_bytes,
        live_bytes_at_snapshot: m.live_bytes_at_snapshot,
        peak_live_bytes: m.peak_live_bytes,
    };

    println!(
        "{}",
        serde_json::to_string(&record).expect("heap measurement must serialize")
    );
}

fn main() {
    for parameter_set in PARAMETER_SETS {
        let parameters = parameter_set.parameters();
        let slh_dsa = SlhDsa::new(parameter_set);

        let seed_bytes = vec![0x42_u8; parameters.keygen_seed_bytes];
        let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes)
            .expect("deterministic key-generation seed must be valid");

        let (key_pair, keygen_measurement) = measure(|| {
            slh_dsa
                .keygen_from_seed(&seed)
                .expect("deterministic key generation must succeed")
        });

        assert_eq!(
            key_pair.public_key().as_bytes().len(),
            parameters.public_key_bytes
        );
        assert_eq!(
            key_pair.private_key().as_bytes().len(),
            parameters.private_key_bytes
        );

        emit(parameter_set, "keygen_from_seed", keygen_measurement);

        let (signature, sign_measurement) = measure(|| {
            slh_dsa
                .sign_deterministic(key_pair.private_key(), MESSAGE, CONTEXT)
                .expect("deterministic Pure SLH-DSA signing must succeed")
        });

        assert_eq!(signature.as_bytes().len(), parameters.signature_bytes);

        emit(parameter_set, "pure_sign_deterministic", sign_measurement);

        let (verified, verify_measurement) = measure(|| {
            slh_dsa
                .verify(key_pair.public_key(), MESSAGE, CONTEXT, &signature)
                .expect("Pure SLH-DSA verification must complete")
        });

        assert!(verified, "generated Pure SLH-DSA signature must verify");

        emit(parameter_set, "pure_verify", verify_measurement);

        let (hash_signature, hash_sign_measurement) = measure(|| {
            slh_dsa
                .hash_sign_deterministic(
                    key_pair.private_key(),
                    MESSAGE,
                    CONTEXT,
                    SlhDsaPreHash::Sha2_256,
                )
                .expect("deterministic HashSLH-DSA signing must succeed")
        });

        assert_eq!(hash_signature.as_bytes().len(), parameters.signature_bytes);

        emit(
            parameter_set,
            "hash_sign_deterministic",
            hash_sign_measurement,
        );

        let (hash_verified, hash_verify_measurement) = measure(|| {
            slh_dsa
                .hash_verify(
                    key_pair.public_key(),
                    MESSAGE,
                    CONTEXT,
                    SlhDsaPreHash::Sha2_256,
                    &hash_signature,
                )
                .expect("HashSLH-DSA verification must complete")
        });

        assert!(hash_verified, "generated HashSLH-DSA signature must verify");

        emit(parameter_set, "hash_verify", hash_verify_measurement);
    }
}
