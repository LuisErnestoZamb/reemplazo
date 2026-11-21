//! Boot-time jitter shared by the network protocols that need
//! non-constant identifiers: DNS transaction ids/source ports and TCP
//! initial sequence numbers/source ports.

/// Cheap boot-time jitter from the timestamp counter.
///
/// This is *not* a CSPRNG: it makes protocol identifiers non-constant
/// across boots, which is what defeats off-path guessing (RFC 5452 §3
/// for DNS — a fixed id+port lets an attacker spoof replies without
/// seeing the query; RFC 6528 §3 for TCP ISNs — a predictable ISN lets
/// an attacker inject segments into a connection). A real CSPRNG
/// seeded from interrupt timing arrives with the entropy milestone;
/// until then treat this as defense in depth, not a claim of
/// cryptographic randomness.
pub(crate) fn boot_entropy() -> u32 {
    // SAFETY: `rdtsc` is baseline x86 (present on the Core2 Duo T7400
    // target and on QEMU's CPU), writes only EAX/EDX, and cannot alias
    // memory — no preconditions beyond the CPU existing.
    let (lo, hi): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        )
    }
    lo ^ hi.rotate_left(16)
}
