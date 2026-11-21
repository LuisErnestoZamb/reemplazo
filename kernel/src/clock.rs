//! Monotonic time for the network stack: milliseconds derived from
//! the PIT tick counter.
//!
//! smoltcp reads this on every `Interface::poll` for its timers (TCP
//! retransmission ≥1 s, DHCP/DNS seconds, neighbor lifetimes seconds,
//! delayed-ACK 10 ms — which may fire one tick late at 100 Hz,
//! harmless). The clock therefore only needs to be *monotonic and
//! advancing*, which the 100 Hz PIT provides — and only while IRQ0 is
//! armed, i.e. [`crate::main`]'s `arm_interrupts` must run before the
//! network chain (it does; `INT_OK` proof stays late).

use crate::pit;
use smoltcp::time::Instant;

/// The stack's idea of "now". `Instant` is an i64 of microseconds;
/// we have10 ms ticks, so whole milliseconds is all we can claim.
pub fn now() -> Instant {
    Instant::from_millis(now_ms() as i64)
}

/// Whole milliseconds since boot — operation deadlines (DHCP/DNS/TCP
/// waits) use this instead of the old spin-count budgets.
pub fn now_ms() -> u64 {
    pit::ticks() * 1000 / pit::HZ
}
