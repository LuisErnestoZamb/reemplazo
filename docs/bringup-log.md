# Persistent bring-up log

The 2007 MacBook has no serial port and its VGA is gone after a reset, so
a failed boot used to leave no evidence. This log records phase codes on
the raw disk and is read back from Debian after the watchdog reboots.

## Shape

- **Ring 0 keeps the driver and the record layout** (`kernel/src/logdisk.rs`):
  the ICH7 has no IOMMU, so a CPL3 process cannot safely own the DMA
  engine. Writes go through the already-probed `ata::Disk` (IDE or AHCI),
  one 512-byte sector per record.
- **The application is userland** (`user/logger`): it writes its own
  record and renders the boot records on the VGA through the hito-3
  console syscalls. It is a normal ELF in `hello.elf`, not kernel code.
- **Syscalls 28/29** (`LogWrite`/`LogRead`) are the only new ABI surface;
  buffers are validated by the same `userptr` gate as the filesystem
  syscalls.

## Disk layout and safety

On the MacBook (`sda`, 234441648 sectors):

| Region | LBA | Use |
|---|---|---|
| sda1 | 2048–4095 | BIOS boot (GRUB) |
| sda2 | 4096–214847487 | Debian ext4 |
| sda3 | 214847488–234440703 | swap |
| **log** | **234440708–234441607** | provisioned header + ≤899 records |
| backup GPT | 234441615–234441647 | untouched |

The region is 5 sectors past the last partition and 8 sectors before the
backup GPT, and is outside GRUB's block list. `LOG_LBA_FROM_END = 940` is
relative to the disk's reported sector count so other machines can use a
different constant when their layout differs.

**Gateway**: the kernel writes *nothing* unless sector `base` carries the
16-byte magic `REEMPLAZO-LOG-v1`. Unprovisioned disks — every QEMU smoke
image and the current install media — are completely inert, which is why
the 30-marker smoke chain is unchanged.

## Record format (512 bytes, little endian)

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 8 | `RLOGv1\0\0` |
| 8 | 2 | sequence number |
| 10 | 2 | reserved |
| 12 | 1 | phase code |
| 16 | 8 | `clock::now_ms()` |
| 24 | 112 | ASCII label (NUL padded) |

Phase codes: `0x11` kernel_main, `0x12` MBI/mem/heap, `0x13` IDT/GDT/PIT,
`0x14` PCI/USB, `0x15` disk probed, `0xA1` demo entered, `0xA4` NIC up,
`0xA5` no NIC, `0xA3` ELF mapped, `0xA6` PCB spawned, `0xA7` user exited,
`0xE0` user record, `0xE1` no user module, `0xE2` ELF load failed.

Codes `0x11`–`0x14` are buffered before the disk probe and replayed in
order by `init`, so even a very early reset is diagnosable.

## Commands

```sh
cargo xtask check          # fmt + clippy + host tests + kernel cross-build
cargo xtask logtest        # QEMU: provisioned disk + user logger, decode records
cargo xtask provisionlog   # SSH: write the magic header into the disk gap
cargo xtask readlog        # SSH: fetch and print the records after reboot
```

Host override variables: `REEMPLAZO_LOG_HOST`, `REEMPLAZO_LOG_KEY`,
`REEMPLAZO_LOG_DEV`, `REEMPLAZO_LOG_LBA`. `logtest` uses
`REEMPLAZO_DEMO_MODULE=logger` to stage the log viewer instead of the
editor in the demo ISO.

For a machine whose last partition ends closer to the backup GPT, choose
a different gap and set `REEMPLAZO_LOG_LBA` **and** the kernel's
`LOG_LBA_FROM_END` together. Never provision over GRUB's block list or a
filesystem area.

## Hardware inventory (hito de bring-up)

`kernel/src/hwdetect.rs` walks the boot's PCI scan right after the log
is bound and records one line per function:

- `0xD0` — driver present; `0xD1` — `NEEDS_DRIVER` (bring-up backlog);
- `0xD2` — non-PCI platform device (SMC/fan, audio, Wi-Fi, SuperDrive,
  Bluetooth); `0xD3` — inventory complete; `0xD4` — `devices=N missing=M`.

This is what answers "what did this machine actually give us?" on a
board with no serial cable: `cargo xtask readlog` shows the inventory
after the watchdog reboots.

### Real-hardware finding (2026-11-22)

The MacBook's disk controller is **not AHCI**. `lspci` reports
`00:1f.2 IDE interface [0101] 8086:27c4` with `ata_piix` and BARs
`0x20c8`/`0x20ec` — ICH7-M SATA in **IDE mode**. The AHCI probe
(class `01/06/01`) and the legacy-ISA probe (`0x1f0`) both miss it,
which is why the first bring-up log had zero records. `kernel/src/
ata_pci.rs` adds a minimal PIO/LBA28 driver for those PCI BARs (the
log LBA 234440708 is below the 2^28 ceiling, so no LBA48 is needed).
The installer's source/target selection is untouched: QEMU smokes
keep their byte-identical IDE path.
