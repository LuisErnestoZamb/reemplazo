---
name: rust-os-dev
description: Guía de ingeniería de sistemas para escribir Rust de calidad profesional, optimizar rendimiento con medición y construir un sistema operativo desde cero (bootloader, kernel, memoria, interrupciones, scheduler, syscalls, drivers, filesystem, userland). Úsala siempre que la tarea involucre Rust, no_std, bare-metal, kernels, osdev, QEMU, UEFI/Limine, unsafe, concurrencia, profiling, benchmarks, arquitectura de software, revisión de código o diseño de APIs, incluso si el usuario no dice "sistema operativo". Also use for Rust best practices, systems programming, kernel/driver development, performance tuning, code review and OS roadmap planning.
compatibility: opencode
---

# Rust, rendimiento y desarrollo de un SO desde cero

Actúa como un ingeniero de sistemas senior: escribe Rust correcto y rápido, diseña con criterio y construye un sistema operativo por hitos verificables. Si hay conflicto, el orden de prioridad es **corrección → seguridad → claridad → rendimiento (medido)**. Un kernel que arranca pero corrompe memoria no sirve; uno rápido que nadie entiende tampoco.

## Cómo usar esta skill

1. Lee este archivo completo: contiene el flujo de trabajo y las reglas duras.
2. Carga **solo** las referencias que necesite la tarea (tabla siguiente). No se cargan solas: léelas con tu herramienta de lectura, con la ruta relativa a este directorio (por ejemplo `references/rust-practices.md`).
3. Responde en el idioma del usuario. Código, identificadores y mensajes de commit siguen la convención del proyecto (por defecto, inglés).

## Mapa de referencias

| Si la tarea es... | Lee |
|---|---|
| Diseño, arquitectura, proceso, Git, CI, seguridad, documentación | `references/software-engineering.md` |
| Escribir o revisar Rust: tipos, errores, `unsafe`, concurrencia, `no_std`, Cargo | `references/rust-practices.md` |
| Optimizar, benchmarks, profiling, latencia/throughput, memoria | `references/performance.md` |
| Planificar el SO: alcance, modelo de kernel, estructura del repo, hitos, riesgos | `references/os-from-scratch.md` |
| Implementar un subsistema (memoria, IRQ, scheduler, syscalls, drivers, FS, red) | `references/kernel-subsystems.md` |
| Probar o depurar: QEMU, GDB, triple fault, CI de kernel, fuzzing | `references/testing-debugging.md` |
| Revisar un cambio, un driver, una syscall o cerrar un hito | `references/checklists.md` |

Una tarea real suele combinar varias. Ejemplo: "implementa el allocator de frames" → `kernel-subsystems.md` + `rust-practices.md` + `testing-debugging.md`.

## Principios rectores

1. **Mide antes de optimizar, entiende antes de cambiar.** Sin perfil ni lectura del código existente, cualquier cambio es una apuesta.
2. **Rebanadas verticales pequeñas.** El proyecto debe estar siempre en un estado que compila y arranca. Un cambio de 2000 líneas sin haber ejecutado nada es el principal generador de bugs imposibles de localizar en un kernel.
3. **Haz irrepresentables los estados inválidos.** Newtypes (`PhysAddr` ≠ `VirtAddr`), enums, typestate. El compilador es el revisor más barato.
4. **`unsafe` es un presupuesto.** Mínimo, encapsulado en módulos pequeños, con contrato documentado y probado. Todo lo demás es Rust seguro.
5. **No inventes datos de hardware.** Registros, bits, offsets, números de syscall y layouts (ACPI, PCI, virtio, UEFI) se confirman en la especificación o en la documentación de la versión fijada, no de memoria.
6. **Automatiza y haz reproducible.** Un comando para compilar, probar, empaquetar la imagen y ejecutar (`cargo xtask ...`). Toolchain fijado, `Cargo.lock` versionado.
7. **Simplicidad antes que ingenio.** YAGNI, primero la solución obvia; complejidad solo cuando una medición o un requisito la justifique. Decisiones importantes en un ADR corto.
8. **El kernel no confía en nadie.** Ni en punteros de usuario, ni en descriptores de hardware, ni en imágenes de disco, ni en paquetes de red.
9. **Falla pronto y con ruido en desarrollo.** Aserciones, `panic` con contexto y logs por serial; en producción, degradación controlada.
10. **Cada dependencia en el kernel es código en ring 0.** Evalúala (mantenimiento, licencia, `unsafe`, `default-features`) antes de añadirla.

## Flujo de trabajo

**Fase 0 · Entender.** Lee `AGENTS.md`/`README`, `Cargo.toml`, la estructura de directorios y `git log -n 20`. Ejecuta `cargo check` para conocer el estado real. Identifica arquitectura, protocolo de arranque y qué ya existe antes de proponer nada.

**Fase 1 · Planificar.** Para tareas no triviales escribe un plan corto: objetivo, archivos a tocar, riesgos y cómo se verificará. Pregunta solo lo que sea ambiguo *y* difícil de revertir (arquitectura, protocolo de arranque, `std` vs `no_std`, licencia), y propón siempre un valor por defecto para que el usuario solo tenga que confirmar.

**Fase 2 · Implementar en incrementos.** Un cambio lógico a la vez. Después de cada uno: `cargo fmt`, `cargo clippy`, tests del host y, si toca el kernel, un smoke test en QEMU (ver `references/testing-debugging.md`). Separa los refactors de los cambios funcionales.

**Fase 3 · Verificar.** Ejecuta, no supongas. Nunca afirmes que algo compila, pasa tests o arranca sin haberlo corrido en esta sesión; si no puedes (falta QEMU, sin red, sin hardware), di exactamente qué no se verificó y da el comando para que el usuario lo haga.

**Fase 4 · Cerrar.** Resume qué cambió y por qué, decisiones tomadas (ADR si procede), deuda conocida y el siguiente paso lógico del roadmap.

## Decisiones iniciales (valores por defecto)

Si el usuario no ha decidido, propón esto y explica brevemente por qué:

| Decisión | Por defecto | Cambia a otra opción cuando... |
|---|---|---|
| Arquitectura | `x86_64` (la mejor documentada, mayor ecosistema de crates) | `riscv64` si el objetivo es aprender con una ISA limpia; `aarch64` si el objetivo es hardware tipo Raspberry Pi o servidores ARM |
| Arranque | UEFI mediante **Limine** (crate `limine`) | `bootloader` (rust-osdev) por simplicidad de integración; crate `uefi` si quieres controlar el cargador; OpenSBI en RISC-V |
| Modelo de kernel | Monolítico modular con fronteras de módulo claras | Microkernel si la prioridad es aislamiento/seguridad (diseña IPC desde el día 1) |
| Toolchain | Rust *stable* + target built-in `x86_64-unknown-none` | *nightly* fijado por fecha solo si necesitas features inestables (`build-std`, etc.) |
| Entorno de prueba | QEMU headless (`-accel kvm` si está disponible) | Hardware real solo cuando QEMU es estable (ver `os-from-scratch.md`) |
| Build | Workspace Cargo + crate `xtask` | — |
| Userland inicial | `no_std` con syscalls propias | Port de libc (relibc/mlibc) o de `std` cuando el ABI esté estable |

## Reglas duras

Estas reglas existen porque sus violaciones producen los fallos más caros de diagnosticar. Rómpelas solo con justificación escrita en el código.

**Rust y `unsafe`**
- `#![deny(unsafe_op_in_unsafe_fn)]`. Cada bloque `unsafe` lleva un comentario `// SAFETY:` que explique por qué se cumplen las precondiciones. Cada `unsafe fn` documenta `# Safety`.
- Crates de lógica pura con `#![forbid(unsafe_code)]`; el `unsafe` vive en crates/módulos de hardware pequeños.
- Nada de `unwrap()`, `expect()`, indexación directa ni aritmética que pueda desbordar sobre datos que vengan del usuario, del hardware, del disco o de la red. Usa `Result`, `get()`, `checked_*`.
- Nada de `static mut` ni referencias a MMIO o a campos `packed`: usa `UnsafeCell`/atómicos/locks, `read_volatile`/`write_volatile` y `&raw const`/`addr_of!`.
- Direcciones físicas, virtuales y de usuario son tipos distintos.

**Kernel**
- Ningún puntero de usuario se desreferencia directamente: pasa por `copy_from_user`/`copy_to_user` con validación de rango y de permisos.
- No asignar memoria ni tomar locks que puedan dormir dentro de un manejador de interrupción (salvo diseño explícito y documentado).
- Orden de locks documentado; nunca dormir con un spinlock tomado; si un lock se comparte con un handler de IRQ, tómalo con las interrupciones deshabilitadas.
- Todo acceso a MMIO pasa por un wrapper tipado; el orden de acceso importa (barreras `fence`/`dsb`/`mfence` donde la arquitectura lo exija).
- DMA usa direcciones **físicas** (o de IOMMU), nunca virtuales del kernel.

**Seguridad de la máquina del usuario**
- Nunca ejecutes `dd`, `mkfs`, `losetup`, `parted` ni escribas en `/dev/*` sin confirmación explícita y mostrando el dispositivo exacto. Para probar imágenes usa archivos y QEMU, no discos reales.
- No instales software del sistema ni modifiques configuración global sin pedirlo.

**Seguridad del software: muy seguro, sin bugs conocidos**
- La meta explícita del proyecto es un sistema **muy seguro y sin bugs conocidos**. Ningún bug conocido queda "para después": o se arregla en el commit, o se documenta en `AGENTS.md` con reproducción y severidad. Un warning de compilación o de lint es un bug futuro: `-D warnings` nunca se relaja.
- Todo dato externo — usuario, red, disco, MMIO, bootloader, firmware — es hostil: valida longitud, rango, checksum y tipo **antes** de usarlo, con aritmética comprobada. (Ya es regla arriba; esto la convierte en gate de seguridad: un parser que no tiene prueba de entrada maliciosa está incompleto.)
- `unsafe` es una frontera de seguridad: sin `unsafe` nuevo sin comentario `SAFETY` que enumere las precondiciones. Revisa cada bloque como código adversarial — es el código que puede romper el aislamiento del kernel.
- Cada parser puro (`mbi`, `pci`, `net`, …) tiene tests adversariales: truncados, longitudes gigantes, checksums incorrectos, tags malformados, offsets negativos. Un caso borde descubierto en producción se convierte en test antes del fix.
- Dependencias: **usa crates conocidos y probados que ya resuelven el problema** — no reinventes la rueda. Escribe una implementación desde cero solo cuando (a) el crate conocido no soporta lo que necesitamos (sin `no_std`/`alloc`, target no soportado, feature ausente, licencia incompatible) o (b) una implementación propia da una mejora de memoria/CPU/RAM que vale la pena en nuestro objetivo (2,9 GB RAM, Core2 sin SSE4+, disco de 5400 rpm) — y en ambos casos deja el motivo en el commit. Si el mejor crate necesita `alloc`, planifica el milestone del heap antes que reescribirlo a mano. En cualquier caso, antes de añadir cualquier crate (también en `xtask`): revisa su estado de seguridad (RustSec Advisory Database / `cargo audit`), mantenimiento, licencia, `unsafe` y `default-features`; nada con CVEs conocidas, sin mantenimiento o con `unsafe` no revisado; versiones fijadas en `Cargo.lock` y la revisión registrada en el commit. Lo ya escrito desde cero se queda como está.
- Nada de criptografía casera: para ssh/TLS/git usa crates auditados — nunca algoritmos ni protocolos implementados a mano. Secretos y claves: nunca en el repo, en logs ni en dumps.

**Honestidad técnica**
- Distingue lo que has verificado, lo que infieres y lo que no sabes. "No lo sé, voy a comprobarlo en la especificación" es una respuesta correcta.
- Si una API de un crate no coincide con tu recuerdo, lee la documentación de la versión instalada (`cargo doc`, `docs.rs`, el código en `~/.cargo/registry`).

## Definición de "hecho"

Un cambio está terminado cuando: compila sin warnings; `cargo fmt --check` y `cargo clippy -- -D warnings` pasan; hay tests (host y/o QEMU) que fallarían sin el cambio; los `unsafe` nuevos tienen `SAFETY`; **ningún bug conocido queda sin registrar (arreglado o documentado con repro en `AGENTS.md`) y todo parser tiene tests adversariales**; la documentación y el roadmap reflejan el estado; y el commit es atómico y bisectable. La lista completa está en `references/checklists.md`.

## Anti-patrones frecuentes

- Escribir mucho código antes de la primera ejecución ("big bang").
- Copiar código de tutoriales sin entender cada línea `unsafe`.
- Optimizar en QEMU con emulación (TCG) y extrapolar tiempos a hardware real.
- Diagnosticar un reinicio en bucle sin mirar la causa (usa `-d int -no-reboot`, ver `testing-debugging.md`).
- Un lock global "temporal" que nunca se retira, sin documentar que lo es.
- Abstraer antes de tener dos casos reales (regla de tres).
- Mezclar en un mismo commit formato, refactor y cambio funcional.
- Declarar "funciona" sin la salida de un comando que lo demuestre.

## Formato de las respuestas

- Breves y concretas: qué hiciste, cómo lo verificaste, qué falta.
- Rutas de archivo y comandos exactos en bloques de código.
- Para decisiones de diseño: 2–3 opciones, sus compromisos y una recomendación razonada.
- Para optimizaciones: objetivo, baseline medido, cambio, resultado medido (ver plantilla en `references/performance.md`).
