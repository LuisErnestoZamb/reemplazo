//! Entropy: a boot-time jitter pool feeding an audited CSPRNG, shared
//! by every protocol that needs unpredictable bytes — DNS transaction
//! ids and source ports, TCP initial sequence numbers and source
//! ports, and (via [`embassy_crypto::rng_impl!`]) the TLS 1.3
//! ClientHello random and ECDH private keys.
//!
//! Design:
//! - The pool collects `rdtsc` samples — one per received frame
//!   (arrival time carries host/network jitter) plus a boot spin — up
//!   to [`CAP`] entries.
//! - The CSPRNG seed is SHA-256 over the pool (audited hash, no
//!   hand-rolled mixer) and feeds `rand_chacha`'s ChaCha12 — the `rand`
//!   project's `StdRng` construction, audited, `no_std`.
//!
//! Documented limits (not hidden bugs): the Core2 Duo T7400 has no
//! RDRAND/RDSEED, so this is *best-effort* boot entropy — it defeats
//! constant or per-boot-fixed secrets, but the entropy is not
//! quantified. Interrupts are armed before the network chain
//! (`arm_interrupts` in main.rs), so IRQ0 preemption perturbs every
//! `rdtsc` sample the pool absorbs; explicitly sampling
//! interrupt-arrival times into the pool (and reseeding after boot)
//! arrives with the entropy milestone. The pool is one-shot (samples
//! after [`CAP`] are dropped).

use embassy_crypto::Sha256;
// Force-link the RustCrypto driver registrations (SHA-256, HMAC-SHA256,
// AES-128-GCM, P-256 ECDH/ECDSA) that define embassy-crypto's extern
// symbols — the embassy idiom for "linked but not named by any item".
use embassy_crypto_rustcrypto as _;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore as _, SeedableRng as _};

/// Maximum pool entries. 512 × 8 bytes = 4 KiB of seed material.
const CAP: usize = 512;
/// Domain separation for the seed hash (versioned, protocol-named).
const SEED_LABEL: &[u8] = b"reemplazo entropy seed v1";

static mut POOL: [u64; CAP] = [0; CAP];
static mut LEN: usize = 0;
static mut SEEDED: bool = false;
static mut CSPRNG: core::mem::MaybeUninit<ChaCha12Rng> = core::mem::MaybeUninit::uninit();

/// Non-constant identifier for protocol state (DNS ids/ports, TCP ISNs
/// and ports): four bytes from the seeded CSPRNG. See the module docs
/// for the entropy caveats.
pub(crate) fn boot_entropy() -> u32 {
    let mut b = [0u8; 4];
    rng_fill(&mut b);
    u32::from_le_bytes(b)
}

/// Record one received frame's arrival jitter. Called from the e1000 RX
/// path for every frame, before the TLS handshake seeds the CSPRNG.
pub(crate) fn note_rx() {
    // SAFETY: single-core; the only handler in play (IRQ0's tick
    // counter) never touches POOL/LEN, so `absorb` cannot reenter.
    unsafe { absorb(rdtsc()) }
}

/// Fill `buf` from the seeded CSPRNG — the entry point behind
/// `embassy_crypto::rng_fill_bytes` (TLS randomness).
fn rng_fill(buf: &mut [u8]) {
    ensure_seeded();
    // SAFETY: `ensure_seeded` just initialized CSPRNG exactly once, on
    // this single core, and nothing deinitializes it.
    unsafe {
        (*core::ptr::addr_of_mut!(CSPRNG))
            .assume_init_mut()
            .fill_bytes(buf);
    }
}

/// Seed the CSPRNG once: top the pool up with boot jitter, hash it
/// with SHA-256, and write the ChaCha12 state.
fn ensure_seeded() {
    // SAFETY: single-core boot path; SEEDED flips false → true here and
    // never back, so the initialization below runs exactly once.
    unsafe {
        if *core::ptr::addr_of!(SEEDED) {
            return;
        }
        for _ in 0..CAP {
            let t = rdtsc();
            absorb(t);
            core::hint::spin_loop();
        }
        let len = *core::ptr::addr_of!(LEN);
        let mut h = Sha256::new();
        h.update(SEED_LABEL);
        // SAFETY: LEN <= CAP by absorb's bound, so this slice is inside
        // POOL; it is read-only and nothing else runs concurrently.
        let bytes = core::slice::from_raw_parts(
            core::ptr::addr_of!(POOL).cast::<u8>(),
            len * core::mem::size_of::<u64>(),
        );
        h.update(bytes);
        let seed = h.finalize();
        (*core::ptr::addr_of_mut!(CSPRNG)).write(ChaCha12Rng::from_seed(seed));
        *core::ptr::addr_of_mut!(SEEDED) = true;
    }
}

/// Push one sample into the pool; drops samples past [`CAP`] (one-shot
/// pool — see the module docs).
///
/// # Safety
/// Caller must serialize access to POOL/LEN (single-core, see callers).
unsafe fn absorb(sample: u64) {
    // SAFETY: uphold the caller's contract; LEN is only ever <= CAP.
    let len = unsafe { *core::ptr::addr_of!(LEN) };
    if len < CAP {
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(POOL).cast::<u64>().add(len), sample);
            *core::ptr::addr_of_mut!(LEN) = len + 1;
        }
    }
}

/// The timestamp counter (baseline x86, present on the Core2 Duo T7400
/// and QEMU's CPU): raw jitter source for the pool.
fn rdtsc() -> u64 {
    // SAFETY: `rdtsc` writes only EAX/EDX and cannot alias memory — no
    // preconditions beyond the CPU existing.
    let (lo, hi): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        )
    }
    ((hi as u64) << 32) | lo as u64
}

/// embassy-crypto's global RNG driver: TLS asks for its ClientHello
/// random and ECDH private keys through this.
struct KernelRng;

impl embassy_crypto::driver::Rng for KernelRng {
    fn fill_bytes(buf: &mut [u8]) {
        rng_fill(buf);
    }
}

embassy_crypto::rng_impl!(KernelRng);
