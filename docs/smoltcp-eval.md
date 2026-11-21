# Adopting **smoltcp** — evaluation and integration design

Status: evaluation complete. Decision: **adopt with conditions** (§5).
All facts below were verified, not remembered. Citations are
`<path>:<line>`; for smoltcp the path is the extracted crates.io tarball
`smoltcp-0.14.0/src/…` (byte-identical to upstream tag `v0.14.0`,
github.com/smoltcp-rs/smoltcp), for our repo it is the workspace-relative
path.

---

## 0. How this was verified

| What | How |
|---|---|
| Version / license / advisories | `crates.io` API, `rustsec/advisory-db` cloned at `--depth 1` (1 536 advisories), `cargo audit` (1 555 advisories, exit 0) |
| Feature set + dependency tree | scratch crate `/tmp/smoltcp-probe` (outside the repo), `cargo tree -e normal --target x86_64-unknown-none` |
| `no_std` / no-allocator build | `cargo build --target x86_64-unknown-none --lib` — **passes** |
| No AVX/SSE4/SSSE3 in the target code | `llvm-objdump -d` over the produced `libsmoltcp-*.rlib`: 147 812 instructions, **0** `%ymm`/`%zmm`, **0** `popcnt`/`lzcnt`/`tzcnt`, **0** SSSE3 (`pshufb`/`palignr`/`pmaddubsw`/…), **0** SSE4 (`pblendvb`/`pcmpeqq`/`pmulld`/`ptest`/…) |
| Static RAM sizes | host build of the same crate printing `size_of::<…>()` |
| API shape (Device, Interface, 4 sockets, static storage, lease/DNS/TCP/ICMP flow) | the whole boot chain type-checks in `/tmp/smoltcp-probe/src/lib.rs::drive` for **both** `x86_64-unknown-none` and host |

The probe's `Cargo.toml` is the feature set quoted in §1.2 and its
`src/lib.rs` is a working template for `kernel/src/netstack.rs`.

---

## 1. Verified facts

### 1.1 Identity, license, advisories, maintenance

| Fact | Value | Source |
|---|---|---|
| Latest version | **0.14.0**, released 2026-08-07 (crates.io 2026-08-17), not yanked | crates.io API; `CHANGELOG.md:11` |
| Previous releases | 0.13.1 (2026-05-01), 0.13.0 (2026-03-20), 0.12.0 (2024-11-28) | `CHANGELOG.md:27,33`; crates.io |
| License | **0BSD** (public domain–style, no attribution obligation) | `Cargo.toml:39` |
| MSRV / edition | Rust **1.91**, edition **2024** — our toolchain is 1.98.1 | `Cargo.toml:13-14`; `rust-toolchain.toml:3` |
| RustSec advisories | **0** — `grep -ri smoltcp` over a fresh `rustsec/advisory-db` clone returns 0 hits (1 536 advisories) | clone in `/tmp/advisory-db` |
| `cargo audit` on the probe lockfile (10 crates) | **exit 0, no vulnerabilities** | `/tmp/smoltcp-probe` |
| Maintenance | Active: last push **2026-11-13** (8 days before this evaluation), 4 684 ★, 134 open issues, not archived | GitHub API `smoltcp-rs/smoltcp` |
| Downloads | 10 801 426 | crates.io API |
| Self-description | "A TCP/IP stack designed for bare-metal, real-time systems **without a heap**" | `Cargo.toml:24` |

### 1.2 Exact minimal feature set

`default-features = false` plus:

```toml
smoltcp = { version = "0.14", default-features = false, features = [
    "medium-ethernet",   # Ethernet frames + ARP  (Cargo.toml:200)
    "proto-ipv4",        # IPv4 wire             (Cargo.toml:224)
    "proto-dhcpv4",      # DHCP wire             (Cargo.toml:216, implies proto-ipv4)
    "proto-dns",         # DNS wire              (Cargo.toml:217)
    "socket-tcp",        # TcpSocket             (Cargo.toml:290)
    "socket-tcp-reno",   # congestion control    (Cargo.toml:293)  ← see §3 R4
    "socket-dhcpv4",     # Dhcpv4Socket          (Cargo.toml:278-282, implies medium-ethernet + proto-dhcpv4)
    "socket-dns",        # DnsSocket             (Cargo.toml:283-286, implies proto-dns)
    "socket-icmp",       # IcmpSocket (echo)     (Cargo.toml:287)
    "log",               # optional: smoltcp's net_debug!/net_trace! → our `log` crate (Cargo.toml:523-527)
] }
```

Deliberately **not** enabled (all verified present in `Cargo.toml` and
harmful or useless to us): `std` (295-298 → pulls `alloc`), `alloc`
(45-48), `phy-raw_socket`/`phy-tuntap_interface` (208-215 → pull `libc`),
`async` (56), `medium-ip`/`medium-ieee802154` (200-205), `proto-ipv6*`
(229-245), `proto-*-fragmentation`, `socket-raw`/`socket-udp`
(289, 294), `socket-mdns` (288), `multicast` (206), `auto-icmp-echo-reply`
(57), `defmt`, `packetmeta-id`, `segmentation-offload`, `socket-tcp-cubic`
(291 — `f64`-based, the `set_congestion_control` doc at `socket/tcp.rs:659-665`
warns about it).

`socket-udp` is **not** needed: the DNS and DHCP sockets emit UDP
themselves (`iface/interface/mod.rs:790-798` dispatches
`Socket::Dhcpv4` to a `(Ipv4Repr, UdpRepr, DhcpRepr)` triple).

### 1.3 Dependency tree (`cargo tree -e normal --target x86_64-unknown-none`)

```
smoltcp-probe v0.0.0
├── log v0.4.35
└── smoltcp v0.14.0
    ├── bitflags v1.3.2      (default-features = false, Cargo.toml:500-502)
    ├── byteorder v1.5.0     (default-features = false, Cargo.toml:504-506)
    ├── cfg-if v1.0.5
    ├── heapless v0.9.4
    │   ├── hash32 v0.3.1 → byteorder
    │   └── stable_deref_trait v1.2.1
    ├── log v0.4.35          (default-features = false, Cargo.toml:523-527)
    └── managed v0.8.0       (features = ["map"], default-features = false, Cargo.toml:528-532)
```

**No `std`, no `alloc`, no `libc`, no `getrandom`, no SIMD crates.**
`extern crate alloc` exists only behind `#[cfg(feature = "alloc")]`
(`src/lib.rs:94-95`) and that feature is off; `managed/std` and
`defmt?/alloc` are likewise off. `libc` is only reachable through the two
host `phy-*` features, which are off.

### 1.4 Target build proof

* `cargo build --target x86_64-unknown-none --lib` — **OK** (no `RUSTFLAGS`,
  no `target-cpu`, no `build-std`).
* `rustc --print cfg --target x86_64-unknown-none` lists
  `target_feature="fxsr"` only — no `sse4.1`, `sse4.2`, `popcnt`, `avx`.
* Disassembly of the produced `libsmoltcp-*.rlib` (release path is the
  same codegen, see `xtask/src/main.rs:94-108`): **0** AVX/SSE4/SSSE3/
  popcnt instructions in 147 812 instructions. smoltcp is scalar on this
  target. **The x86-64-v1 constraint (AGENTS.md) is satisfied.**

### 1.5 `smoltcp::phy::Device` — exact signatures

From `smoltcp-0.14.0/src/phy/mod.rs:396-456` (verbatim):

```rust
pub trait Device {
    type RxToken<'a>: RxToken
    where
        Self: 'a;
    type TxToken<'a>: TxToken
    where
        Self: 'a;

    /// Construct a token pair consisting of one receive token and one transmit token.
    /// … The timestamp must be a number of milliseconds, monotonically increasing
    /// since an arbitrary moment in time, such as system startup.
    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)>;

    /// Construct a transmit token.
    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>>;

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities;
}

pub trait RxToken {
    /// … calls the given closure `f` with the raw packet bytes as argument.
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R;

    fn meta(&self) -> PacketMeta { PacketMeta::default() }
}

pub trait TxToken {
    /// … constructs a transmit buffer of size `len` and calls the passed closure …
    /// When the closure returns, the transmit buffer is sent out.
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R;

    fn set_meta(&mut self, meta: PacketMeta) {}
}
```

Notes:

* The doc comment at `phy/mod.rs:411-412` and `417-418` says "number of
  **milliseconds**" — that text is stale: `Instant` wraps an **`i64` of
  microseconds** (`src/time.rs:17-19`, `25-27`). Build it with
  `Instant::from_millis(ticks * 10)` (`time.rs:44-48`); the extra `×1000`
  is free.
* `DeviceCapabilities` defaults to `medium: Medium::Ethernet` but
  `max_transmission_unit: 0` (`phy/mod.rs:275-298`) — **must** be set to
  1514 (14 B Ethernet + 1500 MTU; `ip_mtu()` then returns 1500,
  `phy/mod.rs:327-338`). Also set `max_burst_size = Some(16)` to match
  the e1000 ring.
* Checksum offload stays at the default `Checksum::Both` for every
  protocol (`phy/mod.rs:189-192` default arm, `223-231`), i.e. smoltcp
  computes **and verifies** every checksum in software. Our e1000 driver
  does no offload today either (`RCTL_SECRC` only strips the FCS,
  `kernel/src/e1000.rs:68-70`).

**Does a synchronous polled driver map cleanly? Yes.**
`E1000::transmit(&[u8])` (`kernel/src/e1000.rs:391-430`) already copies a
frame into a 4 KiB DMA buffer, publishes the descriptor and spins on DD;
`TxToken::consume(len, f)` maps 1:1 — copy `f`'s output into
`tx_buffers[idx]`, publish TDT, wait for DD. `E1000::receive(&mut [u8])`
(`434-472`) copies one descriptor's frame out and reclaims RDT;
`Device::receive` maps to "if `rx_next` descriptor has DD, hand back an
`RxToken` holding a copy of that frame plus a `TxToken`". Frames are
≤ 1514 B (`RCTL.BSIZE` = 2048, `e1000.rs:69-70`), and a 16-descriptor
ring bounds `Interface::poll`'s unbounded-ingress warning (§3 R6).
`entropy::note_rx()` keeps firing because the copy stays inside
`E1000::receive` (`e1000.rs:470`). The probe implements exactly this
(`/tmp/smoltcp-probe/src/lib.rs`, `RingRx`/`RingTx`).

### 1.6 Static RAM budget (measured, host `size_of`, same features)

| Object | Bytes |
|---|---|
| `Interface` | **392** |
| `SocketSet<'_>` (empty; slots live elsewhere) | **16** |
| `tcp::Socket` (state only — rx/tx buffers are separate) | **432** (392 without `socket-tcp-reno`) |
| `dhcpv4::Socket` | **216** |
| `dns::Socket` | **40** |
| `icmp::Socket` | **144** |
| `Storage` = 4 × `SocketStorage` + 4 KiB TCP rx + 4 KiB TCP tx + 2 × 256 B ICMP + 1 DNS query slot | **10 872** |
| **Stack total (`Interface` + `SocketSet` + `Storage`)** | **≈ 11.3 KiB** |

Static defaults that matter (`build.rs:6-26`): neighbor cache **8**
entries, `IFACE_MAX_ADDR_COUNT` **2**, `IFACE_MAX_ROUTE_COUNT` **2**,
`DNS_MAX_SERVER_COUNT` **1**, `DNS_MAX_RESULT_COUNT` **1**,
`DNS_MAX_NAME_SIZE` **255**. slirp hands out exactly one DNS server, so
the defaults fit; `dns-max-result-count-4` (Cargo.toml:92) is the one to
raise if we ever want several A records from `github.com`.

Storage pattern (Q10): **no heap, no `once_cell`**. smoltcp ships
`SocketStorage::EMPTY` as a `const` precisely so a `static` array can be
declared — `iface/socket_set.rs:7-18` ("This is public so you can use it
to allocate space for storing sockets when creating an Interface"),
consumed by `SocketSet::new(&mut slots[..])` (`socket_set.rs:50-56`) and
`sockets.add(socket)` (`socket_set.rs:62-91`; **panics** if the fixed
storage is full, `:83`). embassy does the same: `Stack::new(storage, pool,
random_seed)` where "every packet buffer of the stack and its drivers
comes from `pool`, usually a `StaticPool` in a `static`", and the device
itself is parked in a `StaticCell` (docs.embassy.dev, `embassy_net::Stack`
/ `add_iface_borrowed`). Our repo already uses the `static mut` +
`MaybeUninit` idiom for the TLS record buffers (`kernel/src/tls.rs:69-76`),
so this is consistent house style.

---

## 2. Answers to questions 4–12

### 4. DNS — yes, there is a DNS socket

`smoltcp::socket::dns` ships in `src/socket/dns.rs` (711 lines), gated by
`socket-dns` (Cargo.toml:283-286).

One-shot A-record query:

```rust
let mut sock = sockets.get_mut::<dns::Socket>(handle);
let h = sock.start_query(iface.context(), "github.com", DnsQueryType::A)?; // dns.rs:227-232
// … Interface::poll in a loop …
match sock.get_query_result(h) {                                            // dns.rs:318-338
    Ok(addrs)               => ip = addrs.first().copied(),
    Err(GetQueryResultError::Pending) => { /* keep polling */ }
    Err(GetQueryResultError::Failed)   => sock.cancel_query(h),             // dns.rs:345-351
}
```

`DnsQueryType` is re-exported at `smoltcp::wire` (`wire/mod.rs:291`);
the underlying `wire::dns` module itself is `pub(crate)`
(`wire/mod.rs:85`), so **`smoltcp::wire::dns::Type` is not reachable** —
use `wire::DnsQueryType` (probe compiles against this).

* **Server list**: `Socket::new(&[IpAddress], queries)` (`dns.rs:152-163`)
  or `update_servers(&[…])` (`dns.rs:168-175`) — call the latter with the
  DHCP lease's `dns_servers`.
* **Timeouts**: retransmit after 1 s, doubling to 10 s; overall query
  timeout 10 s (`dns.rs:19-21`, applied at `dns.rs:557`, `565`,
  `643-644`). A failed query flips to `State::Failure` and the next
  `get_query_result` returns `Failed` and frees the slot (`dns.rs:333-337`).
* **Needs a clock: yes** — `cx.now()` drives retransmit/timeout
  (`dns.rs:557`, `565`, `643`), and `start_query_raw` draws `txid` and
  source port from the interface PRNG (`dns.rs:298-299`).
* Query slots are caller-provided (`ManagedSlice<Option<DnsQuery>>`,
  `dns.rs:142`); one slot is enough for our boot chain. The name is
  copied into an internal `Vec<u8, DNS_MAX_NAME_SIZE>` (`dns.rs:296`).

Host-tested equivalence: our `net::dns` hostile-input rules (strict
question echo, txid match, 4-tuple match — `kernel/src/dns.rs:27-33`) are
reimplemented upstream in `socket/dns.rs` + `wire/dns.rs`.

### 5. TCP ISN — the security question

**Answer: smoltcp does *not* use a fixed constant — but it does *not* use
a CSPRNG either.** The ISN comes from an sPCG32 PRNG seeded by
`Config::random_seed`, which defaults to `0` — i.e. **identical ISN
sequence on every boot unless we set the seed.** That would be a real
RFC 6528 regression against our current stack, and it is fixable in one
line.

Exact code:

```rust
// src/socket/tcp.rs:1063-1065  (active open, TcpSocket::connect)
let seq = Self::random_seq_no(cx);
self.local_seq_no = seq;
self.remote_last_seq = seq;

// src/socket/tcp.rs:1074-1077
#[cfg(not(test))]
fn random_seq_no(cx: &mut Context) -> TcpSeqNumber {
    TcpSeqNumber(cx.rand().rand_u32() as i32)
}
// (the #[cfg(test)] variant is the constant 10000, tcp.rs:1069-1072 — tests only)

// src/socket/tcp.rs:1919  (passive open, LISTEN + SYN) — same source
self.local_seq_no = Self::random_seq_no(cx);
```

`cx.rand()` is `InterfaceInner::rand()`, **`pub(crate)`**
(`iface/interface/mod.rs:863-865`) — there is **no public API to seed or
override the ISN per connection**; `local_seq_no` is a private field
(`tcp.rs:491`) with no setter. The `Rand` state is created once, from the
config (`iface/interface/mod.rs:227`):

```rust
let mut rand = Rand::new(config.random_seed);
```

and `Config::random_seed` is `pub u64` with default **0**
(`iface/interface/mod.rs:163-169`, `:191`). The generator is sPCG32
(`src/rand.rs:14-25`), and `Config`'s own doc says:

> It is strongly recommended that the random seed is different on each
> boot, to avoid problems with TCP port/sequence collisions.
> **The seed doesn't have to be cryptographically secure.**
> — `iface/interface/mod.rs:165-168`

**Comparison with our current stack.** `kernel/src/tcp.rs:176-180` and
`:194-198` draw the ISN *and* the ephemeral port from `boot_entropy()`,
i.e. four bytes of ChaCha12 output over the SHA-256-hashed boot jitter
pool (`kernel/src/entropy.rs:44-48`, `73-99`), explicitly documented as
the RFC 6528 §3 off-path-injection defense. `kernel/src/dns.rs:58-62`
does the same for the DNS txid/port. **If we adopt smoltcp without
touching `random_seed`, every boot produces the same ISN stream — a
straight regression.**

**Mitigations (choose A, document B/C as follow-ups):**

* **A — seed from our CSPRNG (recommended, mandatory).**
  ```rust
  let mut cfg = Config::new(HardwareAddress::Ethernet(mac));
  cfg.random_seed = u64::from(entropy::boot_entropy())
      | (u64::from(entropy::boot_entropy()) << 32);
  ```
  This is the *only* hook smoltcp gives us, and it feeds everything that
  needs unpredictability: TCP ISN (`tcp.rs:1076`), TCP/DNS ephemeral ports
  (`rand.rs:32-39`, `socket/dns.rs:299`), DNS txid (`socket/dns.rs:298`),
  DHCP xid (`socket/dhcpv4.rs:554-555`, `:623`), IPv4 identification
  (`iface/interface/mod.rs:254-255`). Parity with today's entropy
  source, at the same "best-effort boot entropy" caveat already
  documented in `kernel/src/entropy.rs:15-21`.
* **Residual risk to document honestly (not a blocker).** smoltcp's
  `Rand` is sPCG32, not a CSPRNG (`src/rand.rs:14-25`: affine step mod
  2⁶⁴, output = truncated/rotated state). An *on-path* observer of two of
  our ISNs can in principle solve for the 64-bit state and predict later
  ISNs; our current stack draws an independent ChaCha12 word per
  connection and is strictly stronger against that specific attack. For
  the off-path attacker RFC 6528 targets, a secret 64-bit per-boot seed
  is sufficient. Record this in `kernel/src/entropy.rs` next to the
  existing caveats.
* **B — upstream hook (follow-up, not a fork).** File an smoltcp issue/PR
  to expose an ISN source (e.g. a `FnMut(&mut Context) -> u32` registered
  on `Config`, or making `Rand` pluggable). A 17k-line vendored fork to
  carry a ~10-line change is not worth it.
* **C — document-and-accept** the default seed: **rejected**, it is a
  per-boot-constant ISN.

### 6. Clock / time

`Instant` is an `i64` of **microseconds**, monotonic from an arbitrary
origin (`src/time.rs:17-27`). What consumes it:

| Consumer | Where | Timer |
|---|---|---|
| `Interface::poll` / `poll_egress` / `poll_ingress_single` / `poll_maintenance` | `iface/interface/mod.rs:486`, `524`, `563`, `575` | sets `inner.now` — every later check reads it |
| `Interface::poll_at` / `poll_delay` | `:594`, `:635` | next soft deadline (`PollAt::Time`) |
| `Interface::new(config, device, now)` | `:207` | initial `now` |
| `Device::receive/transmit(timestamp)` | `phy/mod.rs:413`, `419` | unused by our driver |
| TCP retransmit | `tcp.rs:144` (`RTTE_INITIAL_RTO = 1000 ms`), `:155` (min 1 s), `:159` (max 60 s), `:409` (×2 backoff) | ≥ 1 s |
| TCP delayed ACK | `tcp.rs:300` (`ACK_DELAY_DEFAULT = 10 ms`) | 10 ms |
| TCP TIME-WAIT | `tcp.rs:301` (`CLOSE_DELAY = 10_000 ms`), armed at `:394-397`, `:2012-2013` | 10 s |
| TCP connect/idle timeout | `set_timeout` `tcp.rs:798-800`, doc `:789-792` | caller-set |
| DHCP | `RetryConfig` defaults `dhcpv4.rs:131-140`: discover 10 s, request 5 s, 5 retries, min renew 60 s | seconds |
| DNS | `dns.rs:19-21`: retransmit 1 s → 10 s, timeout 10 s | seconds |
| Neighbor cache | `iface/neighbor.rs:53` `SILENT_TIME = 1 s`, `:56` `ENTRY_LIFETIME = 60 s` | seconds |
| IPv4 fragment reassembly | 60 s — feature off for us | — |

**Is the boot reorder required? Yes.** Today the network chain runs with
`IF=0` and the PIT is armed only afterwards
(`kernel/src/main.rs:75-85` then `:87`), so `pit::ticks()` (`kernel/src/pit.rs:44-46`)
stays at 0 for the whole chain and there is no monotonic source to hand
`Interface::poll`. `kernel/src/entropy.rs:18-21` already anticipates
moving the PIT earlier. Required change:

```
report_rtc → pci::scan/selftest → idt::init + pic::init + pit::init + sti   ← moved up
            → e1000::init (E1000_OK) → NET_OK → PING_OK → DHCP_OK
            → DNS_OK → TCP_OK → TLS_OK → HTTP_OK
            → int3 proof + 3 ticks + INT_OK                                  ← test stays late
            → shell::run (SHELL_OK)
```

i.e. **split `arm_and_test_interrupts()` (`kernel/src/main.rs:291-315`)
into an early `arm_interrupts()` (lines 292-300) and a late
`prove_interrupts()` (lines 303-314)**, so all 14 markers keep their
order and `INT_OK` keeps proving both delivery paths after the network
chain. `clock::now()` = `Instant::from_millis(pit::ticks() * 1000 / pit::HZ)`.

**Does 10 ms granularity suffice? Yes.** Every timer above is ≥ 1 s
except TCP's delayed ACK (10 ms, `tcp.rs:300`) — worst case a delayed ACK
fires one tick late (10 → 20 ms), which is harmless (and smoltcp
retransmits on RTO anyway). DHCP/DNS timeouts are seconds, neighbor
lifetimes are seconds, RTO starts at 1 s. The clock only needs to be
*monotonic and advancing*, which the 100 Hz PIT provides with IF=1.

### 7. DHCP socket

```rust
let handle = sockets.add(dhcpv4::Socket::new());            // dhcpv4.rs:199-217
loop {
    iface.poll(now, phy, &mut sockets);
    if let Some(ev) = sockets.get_mut::<dhcpv4::Socket>(handle).poll() {   // dhcpv4.rs:746-765
        match ev {
            dhcpv4::Event::Configured(c) => { /* c.address: Ipv4Cidr, c.router: Option<Ipv4Address>,
                                                 c.dns_servers: Vec<Ipv4Address, N>, c.server */ }
            dhcpv4::Event::Deconfigured => { /* lease lost */ }
        }
    }
}
```

* **Lease-acquired event**: `Event::Configured(Config)`
  (`dhcpv4.rs:146-151`, `Config` at `:31-47`). The doc on the socket type
  is explicit: *"You must query the configuration with `.poll()` after
  every call to `Interface::poll()`, and apply the configuration to the
  `Interface`"* (`dhcpv4.rs:193-195`).
* **How the interface address is set**: **by us, not by smoltcp** —
  `iface.update_ip_addrs(|a| { a.clear(); a.push(IpCidr::Ipv4(c.address)) })`
  (`iface/interface/mod.rs:398`) plus
  `iface.routes_mut().add_default_ipv4_route(c.router)` (`:422`). The
  reference pattern is `examples/dhcp_client.rs:55-83`.
* **Static IP during the pre-DHCP selftest: yes, it coexists.** Two
  independent proofs from the source: DHCP egress always sources
  `0.0.0.0`/broadcast regardless of what is configured on the interface
  (`dhcpv4.rs:609-615`), and DHCP ingress is intercepted *before* the
  "is this packet addressed to us" check (`iface/interface/ipv4.rs:155-183`
  vs the address check at `:185-209`). So we can keep
  `net::SLIRP_GUEST_IP/24` + the default route on the interface for the
  ARP/ICMP phase, exactly as the smoke test does today.
* **The smoke order should NOT change.** The planned order
  (static IP → ARP → ping → DHCP → DNS → TCP → TLS) is what the markers
  already require (`xtask/src/main.rs:299-302`).
* **Gotcha (must handle):** a freshly created DHCP socket has
  `config_changed: true` (`dhcpv4.rs:204`), so the **first** `poll()` while
  it is still in `Discovering` returns `Event::Deconfigured`
  (`dhcpv4.rs:761-764`). Applied blindly, that clears our pre-DHCP static
  address and default route and breaks the phase we just proved.
  **Fix: add the DHCP socket only after `PING_OK`, and apply
  `Deconfigured` only if a lease had previously been applied.**
* Assertions we make today (lease == 10.0.2.15, router == 10.0.2.2, DNS
  == 10.0.2.3 — `kernel/src/dhcp.rs:106-121`) stay: they are *parser*
  regression tests and just read `Config` fields instead of our own
  decoder.

### 8. ICMP echo socket — enough for `PING_OK`

Yes. From `src/socket/icmp.rs`:

```rust
sock.bind(icmp::Endpoint::Ident(0x5252))?;                       // icmp.rs:262-273 (Endpoint at :83-98)
let repr = Icmpv4Repr::EchoRequest { ident: 0x5252, seq_no: 7, data: &payload };
let buf = sock.send(repr.buffer_len(), IpAddress::Ipv4(GATEWAY))?; // icmp.rs:331
repr.emit(&mut Icmpv4Packet::new_unchecked(buf), &caps.checksum);
// … poll …
let (payload, from) = sock.recv()?;                               // icmp.rs:385 (or recv_slice :403)
let pkt = Icmpv4Packet::new_checked(payload)?;
let repr = Icmpv4Repr::parse(&pkt, &caps.checksum)?;              // verifies the ICMP checksum
```

* Payload, id and seq are ours to choose, so the current
  `PING_OK` proof (echo reply from 10.0.2.2, id `0x5252`, seq 7,
  payload `b"pingtest"`, both addresses checked —
  `kernel/src/e1000.rs:552-600`) reproduces verbatim; the reply's source
  address is `sock.recv()`'s second element.
* **Checksums are validated internally.** Ingress path:
  `Ipv4Repr::parse(…, &self.caps.checksum)` (`iface/interface/ipv4.rs:103`),
  `Icmpv4Repr::parse(&icmp_packet, &self.caps.checksum)` (`ipv4.rs:327`),
  `TcpRepr::parse(…)` with checksum caps (`iface/interface/tcp.rs:24-25`),
  `UdpRepr::parse(…)` (`iface/interface/udp.rs:19-20`). With the default
  `ChecksumCapabilities` (`phy/mod.rs:189-192`, `223-231`) every one of
  them *verifies* on receive and *computes* on send — the
  `internet_checksum`/`parse_udp`/`parse_icmp_echo_reply` machinery in
  `net/src/lib.rs:120-383` becomes redundant.
* Same code serves the shell's `ping` builtin.

### 9. ARP observability and the marker mapping

**smoltcp exposes no way to observe neighbor resolution.** The neighbor
cache is a private field (`iface/interface/mod.rs:134`), its `lookup` is
`pub(crate)` (`iface/neighbor.rs:149`), and `InterfaceInner::has_neighbor`
is a private method (`iface/interface/mod.rs:1047`). There is no
`Interface::neighbor_cache()` in smoltcp 0.14 (embassy-net has one on its
own `Stack`, docs.embassy.dev `embassy_net::Stack::neighbor_cache` — but
that is embassy's wrapper, not smoltcp's API).

**But the driver sees every frame**, so `NET_OK` does not have to be
weakened: implement ARP sniffing in the `phy::Device` adapter. The stack
must resolve the gateway before it can emit the ICMP echo, so the frame
sequence at boot is deterministic:

```
TX  ARP request  (EtherType 0x0806, generated by smoltcp)  → Device::transmit
RX  ARP reply    (from slirp)                              → Device::receive  ⇒ print NET_OK
TX  ICMP echo request                                       → Device::transmit
RX  ICMP echo reply                                         → Device::receive  ⇒ PING_OK
```

so `NET_OK` still means *"ARP resolved the gateway and a reply came back
on the RX ring"* — today's exact semantics (`kernel/src/e1000.rs:543-547`),
different producer. Record `saw_arp_reply: bool` in the adapter (only for
frames whose sender protocol address is the expected gateway and whose
destination MAC is ours — same filter as `e1000.rs:521-533`), and let the
boot chain print the marker.

**Recommended marker mapping — all 14, same order, same meaning:**

| # | Marker | Producer after the swap | Preserved? |
|---|---|---|---|
| 1 | `BOOT_OK` | `report_boot_info` (`kernel/src/main.rs:262`) | unchanged |
| 2 | `MEM_OK` | `memory::selftest` (`main.rs:63`) | unchanged |
| 3 | `RTC_OK` | `report_rtc` (`main.rs:284`) | unchanged |
| 4 | `PCI_OK` | `pci::selftest` (`main.rs:73`) | unchanged |
| 5 | `E1000_OK` | `e1000::init` rings up (`kernel/src/e1000.rs:369`) — unchanged; the `phy::Device` impl wraps this same driver | unchanged |
| 6 | `NET_OK` | phy adapter sees the gateway's **ARP reply** on RX | **semantics kept, producer moved** (stack ARP instead of `E1000::arp_resolve`) |
| 7 | `PING_OK` | `icmp::Socket` echo reply, id/seq/payload/src validated (§8) | unchanged |
| 8 | `DHCP_OK` | `dhcpv4::Event::Configured` + the three field assertions (§7) | unchanged |
| 9 | `DNS_OK` | `dns::Socket::get_query_result` → first A record | unchanged |
| 10 | `TCP_OK` | `tcp::Socket` full GET → server FIN → our `close()` → `state() ∈ {TimeWait, Closed}` (§3 R5) | unchanged (full bidirectional close) |
| 11 | `TLS_OK` | `tls.open(...)` handshake (`kernel/src/tls.rs:122-127`) | unchanged |
| 12 | `HTTP_OK` | existing parser/framer validation (`tls.rs:208-218`) | unchanged |
| 13 | `INT_OK` | `prove_interrupts()` (int3 + 3 ticks) runs **after** HTTP_OK exactly as today; only the *arming* moves earlier (§6) | unchanged, order kept |
| 14 | `SHELL_OK` | `shell::run` (`kernel/src/shell.rs:33`) | unchanged |

Fallback if phy-level sniffing is ever rejected: redefine `NET_OK` as
"first frame transmitted through the smoltcp path" and let `PING_OK` carry
the RX+ARP proof — strictly weaker (a TX-only bug would pass `NET_OK`),
which is why the sniffing option is recommended.

### 10. RAM and static storage

See §1.6 for the measured sizes (≈ 11.3 KiB for the whole stack,
10 872 B of which is `Storage` with 4 KiB + 4 KiB TCP buffers — the same
order as today's `RESP_CAP = 4096` at `kernel/src/tcp.rs:47` plus the
8 KiB TLS stash that disappears). Pattern: `static mut Storage` (or a
`static` array of `SocketStorage::EMPTY`) + `SocketSet::new(&mut slots[..])`,
matching the existing `static mut READ_STORAGE/WRITE_STORAGE` idiom in
`kernel/src/tls.rs:69-76`. The probe's `drive()` is the compiling
template.

### 11. TLS integration — what replaces `kernel/src/tls.rs::Socket`

**Everything in `Socket` dies.** The adapter becomes ~70 lines:

```rust
/// embedded-io transport over one smoltcp TcpSocket.
struct Stream<'a> {
    iface: &'a mut Interface,
    dev:   &'a mut E1000Phy,            // our phy::Device impl
    socks: &'a mut SocketSet<'static>,
    handle: SocketHandle,
    deadline_ms: u64,                   // stall budget, replaces ATTEMPTS/POLLS spin counts
}

impl Stream<'_> {
    fn pump(&mut self) {                       // the only poll site
        self.iface.poll(clock::now(), self.dev, self.socks);
    }
    fn tcp(&mut self) -> &mut tcp::Socket<'static> { self.socks.get_mut(self.handle) }
}

impl embedded_io::Read for Stream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if buf.is_empty() { return Ok(0); }
        loop {
            self.pump();
            if self.tcp().can_recv() { return Ok(self.tcp().recv_slice(buf).map_err(io_err)); }
            if !self.tcp().may_recv() && self.tcp().recv_queue() == 0 { return Ok(0); }   // peer FIN ⇒ EOF
            if clock::now_ms() > self.deadline_ms { return Err(TlsError::Io(ErrorKind::TimedOut)); }
        }
    }
}

impl embedded_io::Write for Stream<'_> {
    fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
        let mut sent = 0;
        while sent < data.len() {
            self.pump();
            sent += self.tcp().send_slice(&data[sent..]).map_err(io_err)?;   // buffer absorbs back-pressure
        }
        Ok(sent)
    }
    fn flush(&mut self) -> Result<(), TlsError> {
        while self.tcp().send_queue() > 0 { self.pump(); /* + deadline */ }
        Ok(())
    }
}
```

`TcpSocket` owns retransmission, RTO backoff, window management,
out-of-order reassembly and congestion control, so the whole
stash/resend apparatus is unnecessary.

**`kernel/src/tcp.rs` (505 lines) — what dies:**

| Lines | Item | Fate |
|---|---|---|
| 1-52, 54-114 | module docs + `http_smoke` | die (marker moves to the new chain) |
| 29-47 | `ATTEMPTS`, `POLLS`, `MAX_SEND`, `MAX_FRAME`, `RESP_CAP` | die (deadlines + smoltcp buffers replace them) |
| 116-139 | `build_get` | **remains** — used by `tls.rs:132`; move to `net/src/http.rs` (or a new `kernel/src/http.rs`) |
| 141-144 | `headers_complete` | dies (only used by `http_smoke`, `tcp.rs:92`) |
| 146-505 | `Conn` (open/send/recv/resend/close/accept/consume/step/send_at/…) | **dies entirely** — smoltcp `tcp::Socket` |

**`kernel/src/tls.rs` — what dies / remains:**

| Lines | Item | Fate |
|---|---|---|
| 30-32, 63, 75-76 | `use crate::tcp::{ATTEMPTS, Conn, MAX_SEND, build_get}`, `STASH_CAP`, `static mut STASH`, `static mut LAST` | die (keep only `build_get`, re-homed) |
| 94-100 | `RtcClock` | remains |
| 42-83 | `ROOT_CA`, `READ_BUF`, `WRITE_BUF`, `CERT_SIZE`, `BODY_HEAD_CAP`, `READ_CAP`, record/parse statics | remain (drop `STASH`/`LAST`) |
| 108-236 | `https_smoke` | **remains, rewritten**: `Conn::open` → `stream.connect(...)`, loop body (parser/framer/status/body validation, `:142-218`) untouched, `conn_ref.close(nic_ref)` → `stream.tcp().close()` + poll until `TimeWait/Closed` |
| 238-398 | `Socket` + `stash_push/stash_take/resend_stalled/wait_ack` + `Read`/`Write` impls | **die**, replaced by `Stream` above |

### 12. What stays ours / what is deleted

**Stays ours**

* `kernel/src/e1000.rs` — register init, MAC, rings, synchronous
  `transmit`/`receive`, `TX_POLLS`; **plus** a new
  `impl smoltcp::phy::Device for E1000Phy` (~90 lines: RX/TX tokens,
  `capabilities()`, ARP-reply sniff for `NET_OK`, `entropy::note_rx()`).
  `arp_resolve`/`try_arp_resolve`/`selftest`/`ping_test`/`ping`
  (`e1000.rs:474-675`, ≈ 200 lines) **die**.
* `kernel/src/shell.rs` — stays; `ping`/`resolve`/`netinfo` are rewired
  onto `icmp::Socket` / `dns::Socket` / `iface.ip_addrs()`.
* `net/src/http.rs` (847 lines) — **independent** (httparse + framer,
  `use super::*` only inside its tests at `:524`), untouched; `build_get`
  moves in here.
* `net/src/lib.rs::parse_ipv4` (`:390-415`) — stays (shell `ping`).
* `net/src/lib.rs::SLIRP_*` (`:43-44`) — stays (smoke assertions).
* `kernel/src/entropy.rs` — stays; now also seeds `Config::random_seed`
  (§5) and still drives the TLS RNG (`:134-144`).

**Deleted**

| File | Lines | Why |
|---|---|---|
| `kernel/src/tcp.rs` | 505 | `Conn` replaced by `tcp::Socket` (keep `build_get`) |
| `kernel/src/dhcp.rs` | 158 | `net::dhcp` + driver replaced by `dhcpv4::Socket` |
| `kernel/src/dns.rs` | 119 | replaced by `dns::Socket` |
| `net/src/tcp.rs` | 380 | smoltcp wire+state |
| `net/src/dhcp.rs` | 341 | smoltcp |
| `net/src/dns.rs` | 437 | smoltcp |
| `net/src/lib.rs` frame layer (`:13-415` minus `parse_ipv4`/`SLIRP_*`) + its tests | ≈ 550 | ARP/IPv4/UDP/ICMP builders+parsers+checksums replaced; `Endpoint`, `on_subnet`, `internet_checksum`, `build_*`, `parse_udp`, `parse_icmp_echo_reply` all lose their last callers |
| `kernel/src/tls.rs::Socket` | ≈ 160 | §11 |
| `e1000.rs` ARP/ping methods | ≈ 200 | §12 |

≈ **2 800 lines deleted**, ≈ **500 added** (`netstack.rs` ~350,
`clock.rs` ~40, `impl Device` folded into `netstack.rs`, TLS `Stream`
~70) — net **≈ −2 300 lines** of hand-rolled protocol code, replaced by
smoltcp's 57 668 lines (`src/`, of which `socket/tcp.rs` alone is 9 875)
of upstream-tested code: congestion control, RTO backoff, out-of-order
reassembly, zero-window persist, TIME-WAIT — all things our module docs
explicitly defer (`kernel/src/tcp.rs:10-20`).

---

## 3. Risk list

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **R1** | **ISN is sPCG32 seeded from `random_seed`, which defaults to 0** → per-boot-constant ISN/ports/xids = RFC 6528 regression (`tcp.rs:1074-1077`, `interface/mod.rs:191`) | **High if ignored** | **Mandatory:** `cfg.random_seed` from `boot_entropy()` (§5-A). Residual sPCG32-vs-CSPRNG caveat documented in `entropy.rs`; upstream ISN-hook issue filed |
| **R2** | **Boot reorder**: `sti`/PIT must move before the network chain; interrupts become live during the deep TLS stack | Medium | Split `arm_and_test_interrupts()` (§6). PIT handler only bumps an `AtomicU64` (`pit.rs:39-41`) — no reentrancy. Side benefit: an exception during TLS now hits a real IDT handler instead of triple-faulting (`kernel/src/main.rs:131-135`) |
| **R3** | **`entropy::note_rx` / POOL reentrancy**: `absorb()` is documented safe *because* interrupts are off (`entropy.rs:53-55`); once the PIT runs early, adding PIT-based reseeding (`entropy.rs:18-21`) would write POOL/LEN from two contexts | Medium | Do **not** add the PIT reseed in the same change. If added later, make `absorb` IRQ-safe (`cli`/`sti` around it or atomic head index) and re-read that doc |
| **R4** | **No congestion control by default**: `CongestionControl::None` (`tcp.rs:453-461`); `AnyController::new()` falls back to `NoControl` unless `socket-tcp-reno`/`-cubic` is on (`socket/tcp/congestion.rs:67-79`) | Medium (politeness/loss, not correctness) | Add **`socket-tcp-reno`** to the feature set (§1.2) — Reno then *is* the default (`socket/tcp/congestion.rs:73-76`); call `set_congestion_control(Reno)` explicitly to document it. Not cubic (f64, `socket/tcp.rs:659-665`) |
| **R5** | **TIME-WAIT is 10 s** (`tcp.rs:301`, armed at `:2012-2013`) — waiting for `state() == Closed` after an *active* close could burn a third of the 30 s smoke budget (`xtask/src/main.rs:25`) | Medium (test-only) | Print `TCP_OK` when `state() ∈ {TimeWait, Closed}`; never wait out `CLOSE_DELAY`. If `Connection: close` makes us the passive closer we reach `Closed` immediately (`CloseWait → LastAck → Closed`) |
| **R6** | **`Interface::poll` drains the whole RX queue** — documented DoS warning (`interface/mod.rs:467-479`) | Low here | The 16-descriptor ring bounds one poll to 16 frames; if the shell ever needs fairness, switch to `poll_ingress_single` + `poll_egress` + `poll_maintenance` (`:518`, `:557`, `:574`) |
| **R7** | **First `dhcpv4::Socket::poll()` returns `Deconfigured`** (`dhcpv4.rs:204`, `:761-764`) and would wipe the pre-DHCP static address | High if missed (breaks NET_OK/PING_OK) | Add the DHCP socket only after `PING_OK`; apply `Deconfigured` only if a lease was previously applied (§7) |
| **R8** | **Marker semantics move** (`NET_OK` producer) and `INT_OK`'s arming moves earlier while its *test* stays late | Low | Documented in §9; `xtask` still asserts the same 14 markers in the same order (`xtask/src/main.rs:299-302`), so the harness itself is untouched |
| **R9** | **`SocketSet::add` panics when storage is full** (`socket_set.rs:83`); `Socket::new` panics on an oversized TCP rx buffer (`tcp.rs:580-582`) | Low | Fixed 4-slot storage, sizes asserted with `const`/`size_of` (§1.6); we add exactly 4 sockets |
| **R10** | **`Instant` doc/impl mismatch** (phy doc says milliseconds, type is microseconds — `phy/mod.rs:411` vs `time.rs:17-19`) | Low | Always build `Instant` via `from_millis(clock::now_ms())`; never hand-roll ticks-as-micros |
| **R11** | **Version churn**: 0.12 → 0.13 bumped MSRV to 1.91 and edition 2024 (`CHANGELOG.md:33`, `:37-38`); 0.14 redesigned congestion control (`CHANGELOG.md:17`) | Low | Pin `0.14` in `Cargo.toml`, `Cargo.lock` records the exact patch; `cargo xtask check` gates every commit |
| **R12** | **Feature/config drift**: `build.rs` sizes are compile-time constants (`build.rs:6-26`); raising e.g. `dns-max-result-count` silently changes RAM | Low | Keep defaults; sizes recorded in §1.6 for regression comparison |

---

## 4. Ordered implementation plan

Every milestone ends with `cargo xtask check` (fmt + clippy `-D warnings`
for host crates **and** for `kernel` on `x86_64-unknown-none`, host tests,
kernel cross-build — `xtask/src/main.rs:69-116`) **and**
`cargo xtask smoke` (14 markers in order within 30 s — `:299-302`,
`:25`). No commit lands with a red gate.

**M0 — clock + interrupt reorder (no smoltcp yet)**
1. New `kernel/src/clock.rs`: `now_ms() -> u64` from `pit::ticks()`.
2. `kernel/src/main.rs`: split `arm_and_test_interrupts()` (`:291-315`)
   into `arm_interrupts()` (idt/pic/pit/sti, `:292-300`) called right
   after `pci::selftest` and **before** `e1000::init`, and
   `prove_interrupts()` (int3 + 3 ticks + `INT_OK`, `:303-314`) called
   exactly where the combined function is today.
3. Update the `guard` module doc (`main.rs:131-135`) — the IDT now *is*
   armed during the network chain.
   *Gate:* check + smoke PASS (proves the reorder alone is safe).

**M1 — smoltcp as a compile-only dependency**
1. Add `smoltcp` with the §1.2 feature set to `kernel/Cargo.toml`.
2. New `kernel/src/netstack.rs`: `E1000Phy` (`impl Device`, ARP sniff,
   `entropy::note_rx()`), `static mut Storage`, `Stack { iface, dev,
   sockets }`, `Stack::poll()`, `clock` wiring — the probe's `drive()`
   is the template. Gate it with `#[allow(dead_code)] mod netstack;` (or a
   single `pub` entry point called from nowhere yet) so `-D warnings`
   stays green.
   *Gate:* check + smoke PASS (old stack still runs; smoltcp linked).

**M2 — swap the whole boot network chain (the one big milestone)**
The RX ring can only be owned by one stack, so ARP/ICMP/DHCP/DNS/TCP/TLS
must move together; the marker order forces exactly this cut anyway.
1. `kernel_main` (`main.rs:75-85`) becomes:
   `Stack::new(seed)` → static IP (10.0.2.15/24 + default route) →
   `prove_arp()` ⇒ **NET_OK** → `prove_ping()` ⇒ **PING_OK** →
   `add_dhcp_socket()` → `wait_lease()` (apply addr/route/
   `dns.update_servers`) ⇒ **DHCP_OK** → `resolve("github.com")` ⇒
   **DNS_OK** → `http_get()` ⇒ **TCP_OK** → `tls::https_smoke()` ⇒
   **TLS_OK**, **HTTP_OK**.
2. `cfg.random_seed` from `boot_entropy()` — **non-negotiable (R1)**.
3. Deadlines (not spin counts) everywhere: DHCP 10 s, DNS 10 s,
   TCP `set_timeout(10 s)` (`tcp.rs:798`), TLS read 10 s.
4. `kernel/src/tls.rs`: add `Stream` (§11), delete `Socket`/`STASH`/`LAST`,
   re-home `build_get` into `net/src/http.rs`.
5. Drop `mod dhcp; mod dns; mod tcp;` from `main.rs` (files deleted in M3).
   *Gate:* check + smoke PASS — **the smoke test is the acceptance test
   for the whole migration**.

**M3 — delete the dead protocol code**
Remove the §12 "Deleted" table (files, methods, frame layer + their
tests), keeping `parse_ipv4`, `SLIRP_*`, `http`, `on_subnet` only if a
caller survives (it won't — smoltcp routes). `cargo test -p net` must
stay green with the remaining tests.
   *Gate:* check + smoke PASS.

**M4 — shell rewire**
`shell::run(&mut Stack, &Lease)`: `ping` → `icmp::Socket` + interface
routing, `resolve` → `dns::Socket`, `netinfo` → `iface.ip_addrs()` +
lease fields, `uptime` unchanged.
   *Gate:* check + smoke PASS, plus manual `cargo xtask run`
   (`stty raw -echo`, then `ping 10.0.2.2`, `resolve github.com`, `netinfo`).

**M5 — entropy/ISN documentation + hardening**
Document the sPCG32 residual risk in `kernel/src/entropy.rs` next to the
existing caveats (`:15-21`); optionally make `absorb()` IRQ-safe and add
the PIT-arrival reseed that doc already promises (R3). Print a
`tcp: ISN seed from CSPRNG (per-boot)` line — never the value.
   *Gate:* check + smoke PASS.

**M6 — optional follow-ups**
Upstream issue for an ISN hook (§5-B); `dns-max-result-count-4` /
`iface-neighbor-cache-count-*` only if a real need appears (R12);
`poll_ingress_single` fairness (R6).

---

## 5. Final recommendation: **ADOPT, with conditions**

**Why adopt.** smoltcp is the only maintained, heap-free, `no_std` TCP/IP
stack in the Rust ecosystem with the exact feature granularity we need;
it is 0BSD, 0 RustSec advisories, actively developed (last push 8 days
ago, three releases in 2026), and it **builds for `x86_64-unknown-none`
with our exact feature set, no allocator, and zero AVX/SSE4/SSSE3
instructions** — the hard constraint in AGENTS.md. It replaces ≈2 300
net lines of deliberately-scoped-out protocol code (no congestion
control, no RTO backoff, no out-of-order reassembly —
`kernel/src/tcp.rs:10-20`) with a stack that has all of those, for ≈11 KiB
of RAM. The `phy::Device` token API maps 1:1 onto our existing
synchronous 16-descriptor e1000 ring (§1.5), and the whole integration
shape already type-checks in the probe.

**Why not unconditional.** One genuine security regression exists —
smoltcp's ISN comes from an sPCG32 seeded by `Config::random_seed`,
**default 0** (`tcp.rs:1074-1077`, `interface/mod.rs:191`), i.e. a
per-boot-constant ISN unless we seed it. That is a one-line fix using the
CSPRNG we already have, and it is a hard condition of adoption; leaving it
unfixed would be a regression against `kernel/src/entropy.rs`'s own stated
purpose.

**Conditions (all folded into M2):**
1. `cfg.random_seed` from `boot_entropy()` — §5-A, **mandatory**; the
   residual sPCG32-vs-CSPRNG caveat gets documented in `entropy.rs`.
2. Arm IDT/PIC/PIT (+`sti`) before the network chain, keep the `INT_OK`
   *test* late — §6, M0.
3. `NET_OK` produced by ARP-reply sniffing in the phy adapter — §9.
4. `socket-tcp-reno` enabled — R4.
5. `TCP_OK` on `state ∈ {TimeWait, Closed}` — R5.
6. DHCP socket added only after `PING_OK`, `Deconfigured` applied only
   after a lease — R7.

**Reject would cost us** a hand-rolled `Conn` with a single outstanding
segment, a fixed receive window, spin-count timeouts, and a TLS adapter
whose only job is to uphold those limits (`kernel/src/tls.rs:238-398`) —
code we would have to grow anyway for git/ssh/browser. Adopting smoltcp
is the shorter path to all of those, and the conditions above are six
lines of code plus one doc paragraph.
