# Userland, syscalls y scheduler

Estado: **hito 1 completado** (`e53295e`).kernel+apps separados por una frontera CPL3 real; el kernel sigue siendo dueño de drivers, red, FS y TLS (no hay IOMMU en el ICH7: VT-x sí, VT-d no).

## Frontera (hito 1)

| Capa | archivo | qué hace |
|---|---|---|
| GDT/TSS | `kernel/src/entry.S` | selectores DPL3 (`CS=0x1b`, `SS=0x23`) + TSS de 64-bit en `0x28`, `ltr` antes de `kernel_main`. El TSS ocupa **16 bytes (2 slots)**: el blueprint original decía 6 entradas, pero SDM Vol.3A §8.2.3 exige la mitad reservada; con 6 el CPU lee basura y `ltr` triple-faulta. |
| IDT | `kernel/src/idt.rs` | gate `0xEE` en vector `0x80` (DPL3), stubs hasta 128, `Frame` con `user_rsp/user_ss`, hooks indirectos, `fxsave/fxrstor`, `clear_fs_gs`. #PF/#GP de CPL3 → hook (no `halt`); en CPL0 sigue `FATAL:`+halt. |
| `iretq` | `kernel/src/interrupts.S` | `isr_common` devuelve en `rax` el frame a restaurar. Con CS.RPL=3 el CPU popea además RSP/SS. El frame sintético del primer proceso debe reservar **192 B** dentro de su kernel stack (15 GPRs + vector/error + RIP/CS/FLAGS/RSP/SS = 176 B) y `iretq` debe hacer `add rsp,136` antes de él. |
| Loader ELF | `kernel/src/userland/elf.rs` | parser `no_std`, sin `unsafe`, sin `unwrap`, `checked_*` en todo: `ET_EXEC`, `EM_X86_64`, `e_phentsize=56`, `e_phnum≤16`, PT_LOAD con `p_filesz≤p_memsz`, `[USER_BASE,USER_END)`, `p_align` potencia de 2 ≥4 KiB, sin `PF_W|PF_X`, sin solapes. 8 tests host adversariales. |
| Page tables | `kernel/src/memory.rs` | `USER_BASE=0x0000_0080_0000_0000` (PML4[1]), `USER_END=+1 GiB`. PML4 nuevo por proceso: entrada 0 copiada del kernel con U/S=0, PML4[1]→PDPT/PD/PT con U/S=1. Páginas de 4 KiB, stacks de usuario 16 KiB y kernel 4 KiB. Sin PCID: flush TLB completo por switch. Sin NXE (Merom no lo necesita para el hito 1). |
| PCB/scheduler | `kernel/src/userland/{process,sched}.rs` | 8 PCBs estáticos, estados `Unused/Ready/Running/Blocked/Exited`, RR cooperativo en el hito 1, `save_idle_frame` para volver a PID0 tras `Exit`. |
| Syscalls | `kernel/src/userland/{syscall,userptr}.rs` | `int 0x80`, args SysV (`rdi,rsi,rdx,r10,r8,r9`), número en `rax`. `Write=0`, `Exit=1`, `Yield=2`, `Time=3`, resto `ENOSYS(-38)`. `copy_from_user` valida rango dentro de un VMA del PCB, `len≤64 KiB`, nunca `&mut` directo. Errnos: `EINVAL(-1)`, `EFAULT(-2)`, `EPERM(-13)`, `ENOSYS(-38)`. |
| ABI de usuario | `userlib/` + `user/hello/` | `no_std`, sin libc/heap. `hello` enlazado en `USER_BASE+0x1000`, PT_LOAD `R|X` (el loader rechaza `W|X`), llama `Write(1,…)` y `Exit(0)`. `code-model=large` **solo** en la invocación cargo de `user-hello` (global rompía el kernel: 2.4→3.6 MiB, boot muerto). |

## Verificación

| Gate | cadena |
|---|---|
| `cargo xtask smoke` | 30 markers originales, byte-idénticos — el ISO no lleva módulo `hello` |
| `cargo xtask smoke-user` | 33 marcadores: `… SHELL_OK, ELF_OK, USER_RUN_OK, SYSCALL_OK, USER_CONSOLE_OK, USER_SHELL_OK, USER_FS_OK, USER_EDITOR_OK, USER_RETURN_OK, SCHED_RR_OK, USER_YIELD_OK, USER_FAULT_OK` |
| `cargo xtask smoke-ssh` | PASS (interop OpenSSH real, intento 1) |
| `cargo xtask smoke-install` | temporalmente limitado por el presupuesto de 60 s con carga de host >7 (documentado; no es regresión) |

## Hoja de ruta

| Hito | estado | qué falta |
|---|---|---|
| 1 · frontera mínima | ✅ `e53295e` | — |
| 2 · RR preventivo por PIT | ✅ (mergeado) | quantum 10 ticks, `Yield` real, #PF→kill con #PF real desde CPL3, `fxsave`/`fxrstor` por PCB; `userptr::set_vm` publicado en cada switch (hito 2b) |
| 3 · consola de usuario | ✅ (mergeado) | syscalls 4–9 (`Read`, `VgaDims/PutCell/Clear/Flush/Peek`), `vgaservice.rs` con diff contra `0xb8000`, proceso `user/shell` con REPL; deuda: publicar `owns_console` desde el PCB |
| 4 · FS | ✅ (mergeado) | syscalls 10–15, fds opacos por PID, volumen RAM acotado, `user/edit` con readback byte-exacto; deuda: volumen FAT-backed real, `Seek`, persistencia |
| 5 · red/TLS | 📋 | handles opacos para `netstack`/`tls`, estados `Blocked`, migrar AI y browser |
| 6 · git/ssh/instalador | 📋 | `Spawn/Waitpid`, IPC acotado, ELFs de usuario en p2 y `GRUB_EARLY_CFG` |
| 7 · corte total | 📋 | borrar `kernel/src/apps/`, `shell::run` solo fallback, `USER_ONLY_OK` |

## Deuda y decisiones

- **netinstall real (I2b)**: `netinstall-real <dev> yes` usa `api.github.com` sobre TLS con la raíz pinnada; el payload aún no está publicado (404), y el fetch desde el kernel en hardware real queda pendiente.
- **Barra superior/launcher** (`kernel/src/apps/launcher.rs`, builtin `apps`): hoy dibuja la fila 0 del VGA en ring 0 con `screen::put` + `flush_diff`; en el hito 3/7 se convierte en el proceso `shell` de usuario, dibujando celdas por `VgaPutCell`/`VgaFlush` sobre el mismo servicio kernel de `flush_diff` (para no romper el readback de `0xb8000`). Su API de navegación (`keyboard::next_event`) ya es la misma que usaría el proceso.

- **Qué se queda en ring 0 al final**: ATA/AHCI/e1000/sky2, PCI/PIC/PIT/IDT, memory/heap, `netstack` (smoltcp), `tls` + raíces, `fs/` + `install.rs`, VGA/serial, y el propio loader/scheduler/dispatch. Razones: sin IOMMU el DMA de usuario es inseguro; el NIC es polled y el stack necesita el PIT en ring 0; FAT16 `write` ya es no-atómico; el installer debe poder formatear antes de que exista un proceso.
- **Latencia**: sky2 y AHCI sin IRQ (INTx/NCQ pendiente) → I/O se sondea en el tick a 100 Hz (≤10 ms añadidos). No bloquea los markers (deadlines ≥1 s).
- **Seguridad**: Merom no tiene SMAP/SMEP/NX; la única barrera al dereferenciar punteros de usuario es `userptr::validated_slice` + los bits U/S. Todo `unsafe` nuevo lleva `// SAFETY:`.

## Superficie de red del kernel (netlog)

`netlog` (:2224 en modo bring-up) transmite el **ring del serial completo** —
incluye líneas del kernel y de los procesos de usuario — a **cualquier
cliente de la LAN**, sin autenticación. Es una decisión deliberada: en la
MacBook no hay puerto serial y este es el único canal de diagnóstico
remoto (junto con sshd en :2222). No debe exponerse a una red no confiable.
El shield de red es la propia red local del banco; si se necesitara
autenticación, el camino es pasar el streaming por una syscall de usuario
con token, no añadir contraseñas al kernel.
