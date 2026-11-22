//! Host-side adversarial suite for the user ELF parser.
//!
//! The parser itself is `kernel/src/userland/elf.rs` (core-only, no kernel
//! glue); this wrapper includes the very same source into a std test crate
//! so `cargo xtask check`'s host-test phase runs its `#[cfg(test)]` cases.
//! Kernel cross-builds see the file as a `no_std` module with no tests.

#[path = "../../kernel/src/userland/elf.rs"]
mod elf;
