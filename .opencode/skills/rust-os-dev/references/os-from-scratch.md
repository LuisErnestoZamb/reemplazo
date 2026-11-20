# Estrategia para crear un sistema operativo desde cero

Contenido: [Antes de escribir código](#antes-de-escribir-código) · [Modelos de kernel](#modelos-de-kernel) · [Estrategia general](#estrategia-general) · [Estructura del repo](#estructura-del-repositorio) · [Roadmap por hitos](#roadmap-por-hitos) · [Hardware real](#de-qemu-a-hardware-real) · [Trampas clásicas](#trampas-clásicas) · [Recursos](#recursos-de-referencia)

## Antes de escribir código

Responde (con el usuario) y registra las respuestas en `docs/adr/` o `docs/vision.md`. Cambiar estas decisiones después es lo más caro del proyecto.

1. **Objetivo:** ¿aprender, investigar una idea, o construir algo usable? Define el criterio de éxito de la versión 0.1 (p. ej. "arranca en QEMU, ejecuta una shell desde un initrd y lee un FS").
2. **No-objetivos:** qué queda fuera explícitamente (GUI, compatibilidad Linux, red, multiusuario...). Protege el alcance.
3. **Arquitectura(s) objetivo** y plataforma (QEMU `q35`/`virt` primero). Diseña desde el principio con `arch/` separado, aunque empieces con una sola.
4. **Modelo de kernel** (siguiente sección) y **ABI de usuario** (POSIX parcial, API propia basada en *capabilities*, compatibilidad con el ABI de Linux).
5. **Modelo de seguridad:** ¿usuarios y permisos?, ¿*capabilities*?, ¿aislamiento entre procesos y con drivers?
6. **Lenguajes:** Rust para casi todo; ensamblador mínimo (`global_asm!`/`naked_asm!`) para entradas de excepción, cambio de contexto y arranque. C solo si portas una libc.
7. **Licencia** del proyecto y compatibilidad con las dependencias.

## Modelos de kernel

| Modelo | Ventajas | Inconvenientes | Para quién |
|---|---|---|---|
| **Monolítico** (drivers y FS en el kernel) | Más simple y rápido (llamadas directas), menos IPC | Un fallo de driver tumba el sistema; superficie de ataque grande | Aprendizaje y primeros hitos; la mayoría de proyectos |
| **Microkernel** (drivers/FS en espacio de usuario) | Aislamiento, kernel pequeño y verificable, reinicio de servicios | IPC en el camino crítico (diseño y rendimiento exigentes) | Seguridad/robustez como prioridad (ejemplos: seL4, Redox, Hubris) |
| **Híbrido/modular** | Equilibrio, carga de módulos | Complejidad de ABI interna | Sistemas que evolucionan |
| **Unikernel / *library OS*** | Mínimo, una sola aplicación, muy rápido | Sin multiusuario ni aislamiento interno | Nubes, aplicaciones dedicadas (ejemplo: Hermit) |
| **Single address space intralingüístico** | Aislamiento por el sistema de tipos, cambios de contexto baratos | Investigación, depende de la corrección del compilador | Investigación (ejemplo: Theseus) |
| **Framekernel** | Pequeño núcleo `unsafe` de confianza + servicios en Rust seguro | Diseño específico | Kernels compatibles con Linux en Rust (ejemplo: Asterinas) |

**Recomendación por defecto:** empieza monolítico pero con **fronteras de módulo limpias** (traits para FS, dispositivos de bloque, red) y una capa de syscalls estable. Así puedes mover un servicio a espacio de usuario más adelante sin reescribirlo. Si eliges microkernel, diseña el IPC (mensajes, *capabilities*, memoria compartida) en el primer hito de procesos, no al final.

## Estrategia general

- **Siempre arrancable.** Tras cada commit, `cargo xtask run` debe arrancar y llegar al punto del hito. Un kernel que no arranca no se puede depurar por bisección.
- **Rebanadas verticales.** Cada hito entrega algo observable (salida por serial, test en QEMU) y un test automático, no solo código.
- **Primero el diagnóstico.** Serial + logger + panic con contexto antes que memoria, antes que interrupciones. Sin visibilidad, cada bug es una caja negra.
- **Lo simple primero, lo rápido después de medir.** Bitmap antes que buddy, round-robin antes que prioridades, un lock grande antes que muchos, siempre documentando que es temporal.
- **Lógica pura en crates testeables en host.** Allocators, parsers (ELF, FAT, tar), VFS, planificador (política) y estructuras de datos se desarrollan con `cargo test` + `proptest` + `miri`; el kernel solo los integra.
- **Aísla la arquitectura.** Todo lo específico (registros, tablas de páginas, IRQ, cambio de contexto) vive en `arch/<nombre>/` tras traits/funciones con interfaz común.
- **Una cosa por hito, no avances sin cumplir la "definición de hecho"**: la deuda en un kernel se compone con interés (un bug de paginación aparece tres hitos después como corrupción aleatoria).
- **Lee la especificación antes de implementar** cada mecanismo de hardware; anota la sección en el código.
- **Decisiones grandes → ADR**; **riesgos grandes → spike** antes de comprometer diseño.
- **Mantén un `docs/roadmap.md` vivo:** estado de cada hito, deuda conocida y próximos pasos.

## Estructura del repositorio

```
myos/
├── Cargo.toml                 # workspace (resolver = "3")
├── rust-toolchain.toml
├── xtask/                     # build, image, run, test, debug, fmt/lint
├── kernel/
│   ├── .cargo/config.toml     # target + flags del kernel
│   ├── linker.ld
│   └── src/
│       ├── main.rs            # entrada y orden de inicialización
│       ├── arch/{x86_64,riscv64,aarch64}/   # boot, cpu, mmu, irq, context, syscall
│       ├── mm/                # pmm, vmm, heap, address_space
│       ├── sched/             # tareas, runqueues, wait queues, timers
│       ├── sync/              # spinlock IRQ-safe, mutex, per-cpu
│       ├── syscall/
│       ├── ipc/
│       ├── fs/                # vfs, tmpfs, initramfs, fat/ext2
│       ├── drivers/           # serial, pci, virtio, framebuffer, ...
│       └── net/
├── crates/                    # lógica pura (no_std, testeable en host)
│   ├── frame-alloc/  elf-loader/  vfs-core/  sched-policy/  ...
├── userland/                  # init, shell, utilidades, libc/runtime propio
├── docs/                      # architecture.md, roadmap.md, adr/, hardware.md
└── tests/                     # integración QEMU, imágenes de prueba, fuzz/
```

## Roadmap por hitos

Cada hito tiene un criterio de "hecho" **verificable por un comando**. Detalle técnico de cada subsistema en `kernel-subsystems.md`.

| Hito | Entregable | Hecho cuando... | Trampas habituales |
|---|---|---|---|
| **M0 · Hola, mundo** | Workspace, target, linker script, punto de entrada, serial, `xtask run` | Imprime un banner por serial y sale con código 0 (debug-exit); el CI lo ejecuta | Linker script/dirección de carga equivocada; sin flush de la UART |
| **M1 · Diagnóstico** | `log`, `panic_handler` con ubicación y backtrace, aserciones | Un `panic!` intencional imprime contexto y detiene la CPU; un test lo comprueba | Panic dentro del panic handler; logs que usan heap antes de tenerlo |
| **M2 · Memoria física** | Mapa de memoria del bootloader, allocator de frames (bitmap → buddy) | Alloc/free de N frames sin fugas ni solapes; proptest en host + test en QEMU | Contar memoria reservada/ACPI como libre; frames del propio kernel/bootloader |
| **M3 · Paginación y heap** | Tablas propias, W^X, `map/unmap/translate`, `#[global_allocator]` | `Box` y `Vec` funcionan; page fault capturado en una guard page; kernel mapeado con permisos mínimos | Flags NX/USER; olvidar `invlpg`/`sfence.vma`; heap que depende de sí mismo |
| **M4 · Excepciones e IRQ** | IDT/vectores, double fault con pila propia, controlador de interrupciones, timer | Tick periódico; división por cero y page fault imprimen diagnóstico sin triple fault | EOI olvidado; PIC sin deshabilitar; pila insuficiente en handlers |
| **M5 · Tareas y scheduler** | Hilos del kernel, cambio de contexto, round-robin preemptivo, sleep/wake, mutex/semáforo/wait queue | 3 hilos alternan con la salida esperada; stress sin deadlock (1 CPU) | *Lost wakeup*; cambio de contexto con IRQs mal habilitadas; liberar la pila en uso |
| **M6 · Usuario y syscalls** | Espacios de direcciones por proceso, cargador ELF, `write/exit/mmap/spawn`, validación de punteros | `init` en userland imprime y termina; un programa hostil (punteros al kernel, tamaños enormes) no tumba el kernel | Entrada de syscall sin cambiar pila; no limpiar registros al volver; páginas del kernel visibles al usuario |
| **M7 · VFS, initramfs, TTY, shell** | Capa VFS, tmpfs, initramfs (tar/cpio), consola/TTY, shell mínima | La shell lista y ejecuta programas del initrd | Rutas con `..`/enlaces; contadores de referencia de inodos |
| **M8 · Bus y almacenamiento** | ACPI/FDT, PCI(e), virtio-blk, FS real (FAT/ext2) | Escribir un archivo, reiniciar la VM y leerlo | DMA con dirección virtual; BAR sin dimensionar; imágenes de FS hostiles (fuzz) |
| **M9 · SMP** | Arranque de CPUs secundarias, per-CPU, locks SMP, TLB shootdown, balanceo | `-smp 4` estable en un stress de varios minutos | Orden de inicialización; carreras en el arranque de APs; shootdown incompleto |
| **M10 · Red, gráficos, entrada** | virtio-net + `smoltcp`, framebuffer/virtio-gpu, teclado/ratón | `ping` y una conexión TCP de prueba; consola gráfica | Buffers DMA reutilizados antes de tiempo; ajuste de ventanas/colas |
| **M11 · Compatibilidad y userland** | libc (relibc/mlibc o propia), runtime Rust (`std` para tu target) y port de software | Se compila y ejecuta un programa C y uno Rust con `std` | ABI inestable; semántica POSIX sutil (señales, `fork`, `mmap`) |
| **M12 · Endurecimiento y hardware real** | Hardening, fuzzing de syscalls y parsers, gestión de energía, arranque en hardware | Pasa fuzz/stress de larga duración; arranca en máquina real | Quirks de firmware ACPI/UEFI; timing; cachés y atributos de memoria |

Para cada hito: crea una rama o serie de commits pequeños, escribe primero el test o el escenario de aceptación, implementa, verifica con `xtask test`, actualiza `docs/roadmap.md` y registra la deuda.

## De QEMU a hardware real

1. Mantén QEMU como entorno principal hasta M9–M10. Usa KVM para tiempos; consulta `performance.md`.
2. Antes de hardware: serial en un adaptador USB-UART o consola de depuración; sin serial, un fallo temprano es invisible.
3. Prueba primero en máquinas virtuales de otros hipervisores (VirtualBox/Hyper-V/VMware) y con distintas configuraciones de QEMU (`-cpu`, `-smp`, `-m`) para destapar suposiciones.
4. Escribe la imagen en una **memoria USB concreta y confirmada por el usuario**; el agente nunca elige un dispositivo de bloque por su cuenta.
5. Espera diferencias: tablas ACPI con peculiaridades, mapa de memoria con huecos, caché y orden de memoria reales, relojes imprecisos, dispositivos que exigen secuencias exactas.

## Trampas clásicas

- **Triple fault / reinicio en bucle:** mira la última excepción (`-d int -no-reboot`); causas típicas: pila inválida, IDT/GDT mal cargados, falta de pila IST para double fault, `#PF` dentro del handler.
- **Alineación de pila ABI** (16 bytes en x86_64 antes de un `call`) y *red zone*: el kernel debe compilarse sin red zone (los targets `*-unknown-none` x86_64 ya lo hacen).
- **SSE/FPU en el kernel** sin guardar su estado, o sin habilitarlo para usuario.
- **Direcciones canónicas** (x86_64) y mezcla de direcciones físicas/virtuales (usa newtypes).
- **Caché de TLB obsoleta** tras cambiar mapeos; en SMP requiere *shootdown*.
- **Carreras entre IRQ y código normal** por locks sin deshabilitar interrupciones.
- **Memoria no inicializada y `static` con dependencias de orden** (inicialización global).
- **Orden de memoria en MMIO** y *write combining*/atributos de caché incorrectos para dispositivos.
- **Confiar en el mapa de memoria del firmware** sin excluir lo que el bootloader aún usa (tablas de página, módulos, framebuffer).
- **Overflow de pila del kernel** por arrays grandes o recursión; usa pilas con *guard page*.

## Recursos de referencia

Úsalos para confirmar detalles en lugar de recordarlos:

- **Manuales de arquitectura:** Intel SDM, AMD APM, Arm Architecture Reference Manual, RISC-V Unprivileged/Privileged ISA, SBI spec.
- **Firmware y buses:** UEFI y ACPI specs, PCI/PCIe, virtio spec (OASIS), documentación de Limine (`PROTOCOL.md`).
- **Comunidad:** OSDev Wiki (wiki.osdev.org), *Writing an OS in Rust* (os.phil-opp.com), rCore tutorial (RISC-V), xv6, *Operating Systems: Three Easy Pieces* (OSTEP), *The Rustonomicon*.
- **Proyectos de referencia en Rust:** Redox OS, Theseus, Tock (embebido), Hubris (Oxide), Asterinas, Hermit, y los crates de `rust-osdev` (`x86_64`, `bootloader`, `uart_16550`, `acpi`, `uefi`), `virtio-drivers`, `smoltcp`, `fatfs`, `linked_list_allocator`/`talc`.
- **Consejo de uso:** lee código ajeno para aprender el diseño, pero reescribe y entiende cada línea `unsafe`; respeta las licencias al copiar.
