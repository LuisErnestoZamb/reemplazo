//! Pure network helpers shared with the kernel: the slirp constants
//! the boot assertions pin, strict IPv4 text parsing for the shell's
//! `ping`, and the HTTP/1.1 response layer (`http` — `httparse` head
//! parsing plus the RFC 9112 body framer). No I/O, no allocator,
//! every length bounds-checked — host-testable like `bootinfo`/`mbi`
//! and `pci`.
//!
//! The TCP/IP wire protocols themselves are **smoltcp**'s job since
//! the migration (docs/smoltcp-eval.md): this crate's frame builders,
//! DHCP/DNS message codecs and TCP state machine were replaced by the
//! audited, upstream-tested stack — roughly −2300 lines here.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod http;

/// QEMU user-net (slirp) guest address — the DHCP smoke asserts the
/// lease hands out exactly this.
pub const SLIRP_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
/// slirp gateway: next hop for anything off-subnet, and the peer of
/// the boot's ARP/ICMP proofs.
pub const SLIRP_GATEWAY: [u8; 4] = [10, 0, 2, 2];
/// slirp's built-in DNS forwarder (the DHCP smoke asserts the lease
/// hands out this same server).
pub const SLIRP_DNS: [u8; 4] = [10, 0, 2, 3];

/// Parse a dotted-quad IPv4 address ("10.0.2.15") into its four
/// octets. Strict on purpose: exactly four decimal octets, no leading
/// zeros (the octal reading `inet_aton` allows is an ambiguity no
/// caller needs) and no surrounding whitespace — trim first. Feeds the
/// shell's `ping` builtin; adversarially tested below.
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for slot in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None; // "01" reads as octal elsewhere; refuse it
        }
        let mut value: u16 = 0;
        for byte in part.bytes() {
            let digit = byte.checked_sub(b'0')?;
            if digit > 9 {
                return None;
            }
            value = value * 10 + u16::from(digit);
        }
        *slot = u8::try_from(value).ok()?;
    }
    if parts.next().is_some() {
        return None; // a fifth part — "1.2.3.4." or "1.2.3.4.5"
    }
    Some(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_accepts_dotted_quads() {
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("10.0.2.15"), Some([10, 0, 2, 15]));
        assert_eq!(parse_ipv4("140.82.114.4"), Some([140, 82, 114, 4]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4("1.2.3.4"), Some([1, 2, 3, 4]));
    }

    #[test]
    fn parse_ipv4_rejects_malformed_input() {
        for bad in [
            "",
            ".",
            "....",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            "1.2.3.4.",
            ".1.2.3.4",
            "256.1.1.1",
            "1.2.3.999",
            "1234.1.1.1",
            "-1.2.3.4",
            "1.2.3.+4",
            "01.2.3.4",
            "1.2.3.04",
            "a.b.c.d",
            "1.2.3.x",
            "1.2.3.4 ",
            " 1.2.3.4",
            "1.2.3.4\n",
            "1.2.3.4\t",
            "1.2.3.4\r",
            "１.2.3.4", // full-width digit is not ASCII
            "1.2.3.٤",  // Arabic-Indic digit is not ASCII
        ] {
            assert_eq!(parse_ipv4(bad), None, "accepted {bad:?}");
        }
    }
}
