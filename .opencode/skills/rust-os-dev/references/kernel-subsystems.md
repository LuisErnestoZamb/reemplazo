# Subsistemas del kernel: diseño, invariantes y trampas

Contenido: [Convenciones](#convenciones) · [1 Arranque](#1-arranque-y-orden-de-inicialización) · [2 Salida y panic](#2-salida-logging-y-panic) · [3 Memoria](#3-memoria) · [4 Interrupciones](#4-excepciones-interrupciones-y-tiempo) · [5 Sincronización y SMP](#5-sincronización-y-smp) · [6 Tareas](#6-tareas-y-scheduler) · [7 Usuario y syscalls](#7-modo-usuario-y-syscalls) · [8 IPC](#8-ipc) · [9 Drivers](#9-drivers-y-modelo-de-dispositivos) · [10 Filesystems](#10-filesystems) · [11 Red](#11-red) · [12 Hardening](#12-hardening)

## Convenciones

- Los datos de hardware de esta página son un **mapa para orientarte, no la fuente de verdad**. Antes de escribir código que dependa de un registro, un bit o un layout, confírmalo en el manual o la especificación correspondiente y cita la sección en un comentario.
- Para cada subsistema: implementación mínima correcta → tests → medición → optimización.
- Separa **política** (qué hacer: algoritmo de planificación, estrategia de asignación) de **mecanismo** (cómo: cambio de contexto, tablas de páginas). La política va en crates puros testeables en host.

## 1. Arranque y orden de inicialización

- Un bootloader moderno (Limine, UEFI directo, `bootloader`) entrega al kernel: CPU en modo de 64 bits, paginación activa, un mapeo directo de la RAM (HHDM en Limine), mapa de memoria, framebuffer, RSDP/DTB, módulos (initrd) y, opcionalmente, información de CPUs. En Limine se piden mediante *requests* estáticas; consulta su `PROTOCOL.md` y la revisión base soportada.
- **Orden recomendado:** serial/log → panic handler → mapa de memoria → PMM → paginación propia (el kernel deja de depender de las tablas del bootloader) → heap → tablas de excepciones/IRQ → timers → scheduler → ACPI/FDT y PCI → drivers → montaje de FS → `init`. Documenta este orden; las dependencias entre inicializaciones son la fuente de la mayoría de bugs de arranque.
- Mientras no hay heap, usa estructuras estáticas o un *bump allocator* de arranque con tope conocido.
- El kernel enlazado en la mitad alta del espacio de direcciones (en x86_64 típicamente `0xFFFFFFFF80000000` con *code model* `kernel`); la mitad baja es para usuario.

**Datos orientativos por arquitectura**

| | x86_64 (QEMU q35 + UEFI) | riscv64 (QEMU virt) | aarch64 (QEMU virt) |
|---|---|---|---|
| Entrada | Bootloader UEFI/Limine | OpenSBI en M-mode → kernel en S-mode (carga típica en `0x80200000`; `a0` = hartid, `a1` = puntero al DTB) | Firmware (UEFI/edk2) o carga directa en EL1; DTB provisto |
| Consola temprana | UART 16550 en puerto `0x3F8` | NS16550 MMIO (típ. `0x10000000`) | PL011 MMIO (típ. `0x09000000`) |
| Descubrimiento | ACPI (RSDP → XSDT → MADT, MCFG, HPET) | Device Tree | Device Tree o ACPI |
| Salida de test | `isa-debug-exit` (puerto `0xf4`) | dispositivo `sifive_test` (típ. `0x100000`) | semihosting |

Las direcciones de `virt` provienen del DTB: **léelas del DTB** en lugar de codificarlas.

## 2. Salida, logging y panic

- **Primer driver:** UART por polling (`uart_16550` en x86_64). No dependas de interrupciones ni de heap.
- `log` como fachada; sumideros: serial (siempre), framebuffer (después). Protege el sumidero con un lock IRQ-safe; en el panic handler, "fuerza" el lock (o usa un camino sin lock) para no hacer deadlock.
- **`panic_handler`:** imprime mensaje + ubicación + CPU + registros relevantes + backtrace (con `-C force-frame-pointers=yes` recorres la cadena `rbp`/`fp`), después detiene todas las CPUs (en SMP, IPI de parada) y, en tests, sale con código de error por el dispositivo de salida.
- Protege contra *panic en panic* (bandera atómica) para evitar bucles.
- Aserciones del kernel (`kassert!`) activas en desarrollo; `debug_assert!` para comprobaciones caras.

## 3. Memoria

### 3.1 Memoria física (PMM)
- Parte del mapa de memoria; **solo** las regiones marcadas como utilizables. No marques como libres: el propio kernel y módulos, tablas del bootloader mientras las uses, framebuffer, ACPI reclaimable hasta haberlo leído, ni la memoria baja (<1 MiB) si la necesitas para el trampolín de APs.
- Empieza con un **bitmap** (simple, fácil de verificar); evoluciona a **buddy allocator** (asignaciones contiguas de orden 2ⁿ, fusión de compañeros) y *caches* por CPU para reducir contención.
- Metadatos por frame (contador de referencias para *copy-on-write* y mapeos compartidos) en una tabla indexada por número de frame.
- API tipada: `alloc_frame() -> Option<Frame>`, `alloc_contiguous(order)`, `free(frame)`. Los `Frame` no son `Copy` para evitar doble liberación (o usa un guard con `Drop`).
- Pruebas en host con `proptest`: tras secuencias aleatorias de alloc/free, no hay solapes, el total se conserva y la fusión funciona.

### 3.2 Paginación (VMM)
- x86_64: 4 niveles (PML4→PDPT→PD→PT), páginas de 4 KiB/2 MiB/1 GiB; bits P, R/W, U/S, PWT/PCD, A, D, PS, G, NX (requiere `EFER.NXE`). RISC-V: Sv39/Sv48 (`satp`). ARM64: `TTBR0_EL1` (usuario) y `TTBR1_EL1` (kernel) con `MAIR_EL1`/`TCR_EL1`.
- **Mapeo directo (HHDM)** de toda la RAM física en el kernel para traducir físico→virtual sin trucos recursivos.
- **W^X:** ninguna página escribible y ejecutable; secciones del kernel con permisos exactos (`.text` RX, `.rodata` R, `.data/.bss` RW+NX). Páginas guard sin mapear bajo cada pila del kernel.
- API: `map(virt, frame, flags)`, `unmap`, `translate`, `protect`; `unmap` y cambios de permisos **invalidan el TLB** (`invlpg`/`sfence.vma`/`tlbi`) y, en SMP, en las demás CPUs que puedan tener la entrada (shootdown por IPI).
- Tablas de páginas del kernel **compartidas** entre procesos (la mitad alta apunta a las mismas tablas de nivel superior); la mitad baja es por proceso.
- Fallos de página (`#PF`): distingue por causa (código de error + `CR2`): acceso a VMA válida sin página (demand paging), escritura a página COW, crecimiento de pila, o violación → señal/terminación del proceso. Un `#PF` en el kernel fuera de las rutas `copy_*_user` es un bug: panic con contexto.

### 3.3 Heap del kernel
- `#[global_allocator]` sobre el PMM/VMM. Primera versión: `linked_list_allocator` o `talc`; después, **slab** para objetos de tamaño fijo y `GlobalAlloc` por tamaños.
- El asignador debe ser seguro frente a IRQs (lock IRQ-safe) y **no se invoca desde handlers de IRQ** salvo que esté diseñado para ello; en la práctica, pre-reserva buffers.
- Rutas que pueden fallar por memoria usan `try_reserve` y devuelven `ENOMEM`. Define una política ante OOM (devolver error, matar el proceso con más memoria...).

### 3.4 Espacios de direcciones de usuario
- `AddressSpace` = tablas de páginas + conjunto de VMAs (`BTreeMap` por dirección inicial) con permisos y respaldo (anónima, archivo, compartida).
- `mmap`/`munmap`/`mprotect`/`brk`, *demand paging* (mapea al primer acceso), *copy-on-write* para `fork`, ASLR para pila/heap/mmap.
- `Drop` de `AddressSpace` libera frames y tablas, comprobando contadores de referencia.

## 4. Excepciones, interrupciones y tiempo

**x86_64**
- GDT con segmentos de kernel y usuario y un **TSS** (RSP0 para cambio de pila al entrar desde ring 3; entradas **IST** para pilas dedicadas a double fault, NMI y machine check, evitando el triple fault por desbordamiento de pila).
- Si usas `syscall/sysret`, el orden de la GDT importa: `syscall` carga CS de `STAR[47:32]` y SS = esa +8; `sysret` (64 bits) carga CS = `STAR[63:48]`+16 y SS = `STAR[63:48]`+8, por lo que el orden debe ser: kernel code, kernel data, user data, user code.
- IDT de 256 entradas; excepciones 0–31 (`#DF` = 8, `#GP` = 13, `#PF` = 14 con `CR2`); algunas empujan código de error (8, 10–14, 17, 21, 29, 30). Entradas de interrupción en `naked`/asm que guardan el estado completo en un `TrapFrame` bien definido.
- **Controlador:** desactiva el 8259 PIC heredado (remapéalo y enmascara todo) y usa **Local APIC + I/O APIC** (x2APIC si está disponible). **EOI** al terminar cada IRQ (olvidarlo "congela" esa fuente).
- **Tiempo:** APIC timer (calibrado con HPET/PIT/TSC/CPUID 0x15), modo TSC-deadline si hay soporte, TSC invariante para reloj monotónico, HPET como respaldo, RTC para hora de pared.
- Vectores espurios: ignóralos sin EOI cuando corresponda según el tipo.

**RISC-V:** `stvec` (vector de traps), `sscratch` para cambiar de pila, `scause` decide excepción/IRQ, PLIC para IRQ externas, timer por SBI (`sbi_set_timer`) o extensión Sstc, `ecall` para syscalls.
**ARM64:** `VBAR_EL1` (tabla de 16 vectores de 0x80 bytes alineada a 2 KiB), GICv2/GICv3 (distribuidor, redistribuidor/CPU interface), *generic timer*, `svc` para syscalls, barreras `dsb`/`isb`.

**Reglas de handlers:** cortos; sin asignación de memoria ni locks que duerman; el trabajo pesado se difiere a una cola/tarea (*top half/bottom half*); guardan y restauran todo el estado; respetan el estado de IRQ al volver.

## 5. Sincronización y SMP

- Primitivas: `SpinLock` IRQ-safe (guarda/restaura el estado de interrupciones en el guard), `Mutex` que bloquea la tarea (wait queue), `RwLock`, semáforo, `Once`, contadores atómicos, `CondVar`/wait queues.
- **Per-CPU data:** x86_64 con `GS` base (`swapgs` al entrar/salir de ring 3 mediante `KernelGSBase`), RISC-V con `tp`, ARM64 con `TPIDR_EL1`. Evita locks para estado local de CPU (runqueue, caches).
- **Arranque de APs:** pide la lista de CPUs al bootloader (Limine MP) o usa ACPI MADT + secuencia INIT-SIPI-SIPI con un trampolín en memoria baja; en ARM, PSCI `CPU_ON`; en RISC-V, SBI HSM. Cada AP necesita su pila, GDT/TSS (x86), IDT y per-CPU propios.
- **TLB shootdown:** IPI a las CPUs que ejecutan ese espacio de direcciones y espera confirmación.
- **Depuración de concurrencia:** *lockdep ligero* (registra el orden de locks y avisa de inversiones), temporizador *watchdog*, `-smp N` con `-icount` para repetir carreras.

## 6. Tareas y scheduler

- Modelo: `Process` (espacio de direcciones, tabla de descriptores, credenciales) y `Thread/Task` (pila de kernel, contexto, estado, prioridad). Estados: `Ready`, `Running`, `Blocked(motivo)`, `Zombie(código)`.
- **Cambio de contexto:** guarda solo los registros *callee-saved*, el puntero de pila y, si cambia el proceso, la base de tablas de páginas; el resto lo guarda la entrada de trap. Escríbelo como una función `naked`/`global_asm!` mínima y revisada.
- **Política (separada del mecanismo):** round-robin con *time slice* → prioridades/MLFQ → fair scheduling por tiempo virtual. Colas de ejecución por CPU con balanceo/robo de trabajo.
- **Preempción:** el timer fuerza `need_resched`; el cambio ocurre en un punto seguro (retorno de interrupción, sin spinlocks tomados).
- **Bloqueo y despertar:** *wait queues*. Evita el *lost wakeup*: marca la tarea como bloqueada **antes** de comprobar la condición y vuelve a comprobarla tras encolarse, todo con el lock de la cola.
- **Ciclo de vida:** una tarea no libera su propia pila mientras la usa (la libera otra, p. ej. el *reaper*); los procesos `Zombie` se recolectan con `wait`; `Arc<Task>` con `Weak` para evitar ciclos.
- **Tarea inactiva (idle)** por CPU con `hlt`/`wfi`; timers (rueda de timers o *min-heap*) para `sleep` y timeouts.
- Pilas de kernel de 16–32 KiB con guard page.

## 7. Modo usuario y syscalls

- **Entrada:** x86_64 `syscall` (configura `EFER.SCE`, `LSTAR`, `STAR`, `SFMASK`; la instrucción **no cambia la pila**: tu entrada debe hacerlo y usar `swapgs`); RISC-V `ecall`; ARM64 `svc`. Número de syscall y argumentos en registros según un ABI documentado.
- **Retorno seguro:** en x86_64, antes de `sysretq` comprueba que la dirección de retorno es canónica (si no, usa `iretq`) para evitar la clase de fallos de privilegio por RIP no canónico; limpia registros que puedan filtrar datos del kernel.
- **Validación de punteros:** `copy_from_user`/`copy_to_user` comprueban que el rango está en espacio de usuario (sin desbordar: `checked_add`), que los permisos son los adecuados y manejan fallos de página sin panic (tabla de excepciones con *fixup* o prefault). Habilita SMEP/SMAP (o PAN/SUM) y abre ventanas de acceso solo en esas funciones.
- **Una sola copia de los argumentos** (copia al kernel antes de validar) para evitar TOCTOU.
- **Diseño del ABI:** pequeño y estable; resultados con convención de error uniforme; versión del ABI; operaciones sobre *handles/descriptores*, no sobre punteros del kernel. Cada syscall nueva: contrato, límites de recursos, comportamiento ante señales/cancelación y tests hostiles (ver `checklists.md`).
- **ELF loader:** parsea con un crate/parser robusto y validando todos los offsets/tamaños (entrada hostil); mapea `PT_LOAD` con permisos exactos, construye la pila inicial (argv/envp/auxv) y salta a ring 3.
- Primera syscall mínima: `write` (a la consola) y `exit`; luego `spawn/exec`, `mmap`, `read/open/close`, `wait`, `sleep`, `yield`.

## 8. IPC

- **Monolítico:** pipes, sockets locales, memoria compartida, señales/eventos, futex.
- **Microkernel:** paso de mensajes síncrono (estilo L4) con *endpoints* y **capabilities** (referencias infalsificables a objetos con derechos), más memoria compartida para datos grandes. Mensajes pequeños en registros; los grandes por páginas compartidas (*zero-copy*).
- Define desde el principio: límites de tamaño, qué ocurre si el receptor muere, cancelación/timeouts y cómo evitar inversión de prioridad.

## 9. Drivers y modelo de dispositivos

- **Modelo:** bus → dispositivo → driver, con `probe`/`remove`, propiedad exclusiva de recursos (BARs, IRQs, DMA) y *drop* que libera.
- **Orden de drivers:** UART → framebuffer/consola → teclado (PS/2 o virtio-input) → **PCI/PCIe** (enumeración por ECAM de MCFG; legado por puertos `0xCF8/0xCFC`; dimensionado de BARs; capabilities; MSI/MSI-X; activar *bus mastering*) → **virtio** (blk, net, gpu, input) → AHCI/NVMe → USB (xHCI) → NICs reales.
- **virtio:** empieza por aquí porque QEMU lo emula bien y la spec es clara; usa el crate `virtio-drivers` como referencia o impleméntalo desde la spec (transporte PCI moderno, *virtqueues*, negociación de features).
- **DMA:** buffers contiguos y alineados, direcciones físicas (o de IOMMU), barreras antes de notificar al dispositivo, no reutilizar un buffer hasta su finalización; considera *bounce buffers*.
- **MMIO tipado:** un wrapper por bloque de registros con acceso volátil; los bits con `bitflags`/`tock-registers`. Todo el `unsafe` en esa capa.
- Descubrimiento: ACPI (`acpi` crate; el intérprete AML es complejo: considera `uacpi`/ACPICA o evita AML al principio) o Device Tree (`fdt`).
- Los IRQ de drivers: *top half* mínimo (reconoce, copia/anota, encola) y *bottom half* en tarea.

## 10. Filesystems

- **Capa VFS** con traits (`Filesystem`, `Inode`, `File`) o estructuras equivalentes: resolución de rutas, tabla de montajes, tabla de descriptores por proceso, permisos.
- **Orden:** `tmpfs`/ramfs → **initramfs** (tar USTAR o cpio) → FAT32 (crate `fatfs` para empezar) → ext2/ext4 solo lectura → sistema propio (log-structured/CoW) si hace falta.
- **Caché de páginas/bloques** con política de reemplazo y escritura diferida (*write-back*) con `sync`/`fsync` definidos.
- **Consistencia ante fallos:** *journaling* o CoW; orden de escrituras documentado; `fsck`.
- **Rutas:** normalización, `..`, enlaces simbólicos (límite de profundidad), componentes demasiado largos.
- Las imágenes de FS son **entrada hostil**: fuzzing y validación estricta de metadatos.

## 11. Red

- Pila TCP/IP en `no_std`: **`smoltcp`** sobre un driver (virtio-net primero). API de sockets propia o estilo BSD; DHCP y DNS cuando haya TCP/UDP estable.
- Buffers de red con propiedad clara (anillos de DMA, `Arc`/pools), *zero-copy* hacia el usuario cuando sea posible, límites de colas para contrapresión.
- Los paquetes son entrada hostil: valida longitudes y campos en cada capa; fuzzing del parser.

## 12. Hardening

- **Aislamiento:** espacios de direcciones separados; kernel no mapeado en usuario salvo lo imprescindible (considera KPTI en CPUs afectadas por Meltdown).
- **Protecciones de CPU:** NX, W^X, SMEP/SMAP (x86), PAN/PXN (ARM), SUM (RISC-V), UMIP, guard pages, KASLR.
- **Datos:** pon a cero la memoria al liberar/asignar páginas de usuario para no filtrar información; evita filtrar punteros del kernel a usuarios sin privilegios (logs, `/proc`-like).
- **Comparaciones sensibles** en tiempo constante; `zeroize` de claves.
- **Límites de recursos** por proceso (memoria, descriptores, hilos, tamaño de mensajes) para que no puedan agotar el sistema.
- **Fuzzing continuo** de syscalls, parsers (ELF, FAT/ext, ACPI/FDT, red) y del cargador.
- Modelo de privilegios: usuarios/*capabilities*; el principio de mínimo privilegio aplica también a los drivers (en microkernel, procesos sin acceso a más MMIO/IRQ que los suyos).
