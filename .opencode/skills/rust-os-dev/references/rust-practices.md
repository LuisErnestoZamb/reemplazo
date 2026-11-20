# Buenas prácticas de Rust (aplicadas a sistemas)

Contenido: [Proyecto y toolchain](#proyecto-y-toolchain) · [Tipos](#diseño-con-tipos) · [Ownership](#ownership-y-préstamos) · [Errores](#manejo-de-errores) · [Traits](#traits-y-genéricos) · [unsafe](#unsafe) · [Concurrencia](#concurrencia) · [no_std](#no_std-y-bare-metal) · [Cargo](#cargo-y-perfiles) · [Compilación](#tiempos-de-compilación) · [Checklist](#checklist-rápido)

## Proyecto y toolchain

`rust-toolchain.toml` en la raíz, para que todos (y el CI) usen lo mismo:

```toml
[toolchain]
channel = "stable"   # o "nightly-AAAA-MM-DD" fijado si necesitas features inestables
components = ["rustfmt", "clippy", "rust-src", "llvm-tools"]
targets = ["x86_64-unknown-none"]
```

- Usa la edición vigente (2024 o posterior). Sus defaults endurecen cosas útiles: `unsafe_op_in_unsafe_fn` avisa, las referencias a `static mut` se deniegan y `extern`/`no_mangle` requieren `unsafe(...)`.
- Prefiere los targets *built-in* `x86_64-unknown-none`, `aarch64-unknown-none` y `riscv64gc-unknown-none-elf` (ya vienen con `core` precompilado y con la configuración adecuada para kernel). Un target JSON propio + `-Zbuild-std` solo si necesitas flags que los built-in no ofrecen; eso te ata a *nightly*.
- Estructura de workspace recomendada: crates de **lógica pura** (`no_std`, sin `unsafe`, testeables en host) separados del crate del **kernel** (hardware, `unsafe`) y de `xtask`.

Lints compartidos en el `Cargo.toml` raíz (cada crate hereda con `[lints] workspace = true`):

```toml
[workspace]
resolver = "3"
members = ["kernel", "crates/*", "xtask"]

[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"

[workspace.lints.clippy]
undocumented_unsafe_blocks = "deny"
missing_safety_doc = "deny"
pedantic = { level = "warn", priority = -1 }
unwrap_used = "warn"
indexing_slicing = "warn"
cast_possible_truncation = "warn"
```

En los crates de lógica pura añade `#![forbid(unsafe_code)]`. Ajusta los lints `pedantic` que molesten, pero con un `allow` justificado, no a ciegas.

Cuidado con `build.target` en un `.cargo/config.toml` global: fuerza el target bare-metal también a los tests del host. Pon la configuración de target en `kernel/.cargo/config.toml` o pásalo explícitamente desde `xtask` con `--target`.

## Diseño con tipos

- **Newtypes** para todo lo que se pueda confundir: `PhysAddr(u64)`, `VirtAddr(u64)`, `Pid(u32)`, `Irq(u8)`. Con `#[repr(transparent)]` si cruzan una frontera ABI.
- **Enums en lugar de banderas booleanas** y de "estados + campos opcionales": `enum TaskState { Ready, Running { cpu: CpuId }, Blocked(WaitReason), Zombie(ExitCode) }`.
- **Typestate** cuando el orden de operaciones importa y su violación es un bug grave (`Device<Uninit>` → `Device<Ready>`).
- **`match` exhaustivo sin `_`** para enums internos: añadir una variante provoca error de compilación en cada punto que debe decidir.
- **Constructores que validan** (`TryFrom`, `new() -> Result`); los campos privados mantienen el invariante.
- **`bitflags`** para registros y permisos; `NonZeroU32`/`NonNull<T>` para aprovechar *niche optimization* y expresar "nunca cero/nulo".
- `#[must_use]` en tipos y funciones cuyo resultado no debe ignorarse (`Result` ya lo lleva). `#[non_exhaustive]` en enums/structs públicos que evolucionarán.
- `#[repr(C)]` para cualquier struct cuyo layout importe (hardware, ABI, formato en disco); nunca confíes en el layout por defecto de Rust.

## Ownership y préstamos

- Pasa referencias (`&T`, `&mut T`, `&[T]`, `&str`) en lugar de propiedad cuando no necesitas poseer; acepta `impl AsRef<[T]>`/`impl Into<X>` solo cuando mejore de verdad el sitio de llamada.
- No uses `.clone()` para silenciar al *borrow checker*: suele indicar un problema de diseño (estructura de datos, alcance del préstamo). Reestructura primero: divide el struct en campos prestables por separado, usa índices/*handles* en lugar de referencias entrelazadas, reduce el alcance del préstamo.
- Mutabilidad interior (`Cell`, `RefCell`, `Mutex`) solo donde el modelo lo exige y documentando el invariante.
- `Arc`/`Rc` para propiedad compartida real; en grafos (tareas, VMAs, inodos) piensa en quién es el dueño y usa `Weak` para romper ciclos.
- `Cow` y `Box<[T]>`/`Box<str>` cuando evitan copias o capacidad sobrante.

## Manejo de errores

- Funciones fallibles devuelven `Result<T, E>`; `Option` solo para ausencia legítima.
- Librerías: tipos de error propios (`enum KernelError`) con `thiserror` (`default-features = false` para `no_std` en la versión actual) o implementación manual de `Display`/`Error`. Aplicaciones/`xtask`: `anyhow` con contexto.
- Los `panic!`/`unwrap`/`expect` son para **bugs** (invariantes rotos), nunca para entrada externa. `expect("invariante: <por qué no puede fallar>")` si de verdad es imposible.
- En el kernel, define un conjunto cerrado de códigos de error que se mapea de forma estable al ABI de syscalls (estilo errno).
- Asignaciones que pueden fallar en rutas críticas: `Vec::try_reserve`, `try_*` y devolver `ENOMEM`, en vez de abortar.
- Mantén contexto al propagar (qué operación, qué recurso) para que un log sea suficiente para diagnosticar.

## Traits y genéricos

- **Despacho estático por defecto** (`impl Trait`, genéricos). `dyn Trait` cuando necesitas heterogeneidad, reducir tamaño de código o romper dependencias en tiempo de ejecución (drivers, filesystems).
- Un **HAL por trait** (`trait Console`, `trait BlockDevice`, `trait FrameSource`) permite sustituir el hardware por dobles en tests del host.
- *Sealed traits* para impedir implementaciones externas cuando el trait es parte de un contrato interno.
- Evita APIs sobre-genéricas: cada parámetro genérico es monomorfización (tiempo de compilación y tamaño de binario) y complejidad en mensajes de error.
- `Send`/`Sync` son contratos, no etiquetas: nunca los implementes con `unsafe impl` sin una justificación escrita del invariante (por ejemplo, "protegido por el lock X").
- `async` en el kernel solo si el diseño lo justifica (drivers con muchos estados de espera); exige un ejecutor propio y cuidado con `Waker` e interrupciones.
- Macros: declarativas primero y con moderación; las procedurales encarecen la compilación y esconden el control de flujo.

## `unsafe`

**Modelo mental.** `unsafe` no desactiva el compilador: promete que tú has comprobado lo que él no puede. Un bloque `unsafe` correcto puede envolverse en una API segura *sin condiciones*; si no puede, la función debe ser `unsafe fn` y documentar su contrato.

**Patrón canónico:**

```rust
/// Lee el registro de estado del dispositivo.
///
/// # Safety
/// `base` debe ser la dirección virtual de la región MMIO del dispositivo,
/// mapeada como no cacheable y vigente durante toda la llamada.
unsafe fn read_status(base: *const u32) -> u32 {
    // SAFETY: por el contrato de la función, `base` apunta a MMIO válido y alineado.
    unsafe { core::ptr::read_volatile(base.add(STATUS_OFFSET / 4)) }
}

pub struct Uart { base: NonNull<u32> }

impl Uart {
    /// # Safety
    /// `base` debe apuntar a la región MMIO de una UART y ser de uso exclusivo de este `Uart`.
    pub unsafe fn new(base: NonNull<u32>) -> Self { Self { base } }

    pub fn status(&self) -> u32 {
        // SAFETY: `new` exige que `base` sea válido y exclusivo; `&self` impide accesos concurrentes mutables.
        unsafe { read_status(self.base.as_ptr()) }
    }
}
```

**Reglas:**
- Reduce la superficie: bloques `unsafe` mínimos, módulo propio con la API segura alrededor. Lo ideal es que la revisión de seguridad de memoria se limite a unos pocos archivos.
- Una `unsafe` = un invariante explicado. Si no sabes escribir el `SAFETY`, no sabes que es correcto.
- Prefiere crates auditados a `transmute` casero: `zerocopy`/`bytemuck` para reinterpretar bytes, `volatile`/`tock-registers` para registros, `bitflags`, `x86_64`, `uart_16550`, `spin`/`lock_api`.
- `MaybeUninit<T>` para memoria sin inicializar; nunca `mem::uninitialized`/`zeroed` para tipos que no admiten el patrón de ceros.

**Fuentes clásicas de comportamiento indefinido (UB)** — revísalas en cada `unsafe`:
- Dos `&mut` (o `&mut` y `&`) al mismo dato vivos a la vez (violación de aliasing), incluso "solo por un instante".
- Referencias desalineadas, nulas, colgantes o a campos de `repr(packed)` (usa `&raw const`/`addr_of!` y `read_unaligned`).
- Valores inválidos: un `bool` ≠ 0/1, un `enum` con discriminante inexistente, referencias nulas, `char` fuera de rango.
- Datos sin sincronizar entre hilos/CPUs/handlers (carrera de datos).
- Lectura de memoria sin inicializar; lectura/escritura fuera de límites; uso tras liberar.
- Referencias a MMIO: genera lecturas "espurias" y reordenaciones; usa punteros con `read_volatile`/`write_volatile`.
- Extender lifetimes con `transmute` o punteros crudos más allá de lo que garantiza el dueño.
- Código de ensamblador (`asm!`) que rompe lo que declara (clobbers, `nomem`, `preserves_flags`, `nostack`): declara con exactitud.

**Herramientas:** `cargo miri test` (detecta muchos UB en la lógica pura), `loom` (explora interleavings), `cargo careful`, `cargo-fuzz`, y revisión humana específica de cada `unsafe`.

**Estado global:** nada de `static mut`. Alternativas: `static FOO: Mutex<T>`, `spin::Once`/`spin::Lazy` para inicialización única compartida (`core::cell::OnceCell` no es `Sync`), atómicos para contadores/flags, o estructuras per-CPU. Si necesitas inicialización diferida, documenta el orden de boot que la garantiza.

## Concurrencia

- Comprende los ámbitos de concurrencia del kernel: **otra CPU**, **un handler de IRQ en la misma CPU**, **preempción por el scheduler**. Cada dato compartido debe estar protegido contra los que le apliquen.
- **Spinlock con IRQs:** si un lock puede tomarse desde un handler, el código normal debe deshabilitar interrupciones mientras lo tiene (si no, deadlock en la misma CPU). Implementa un `SpinLock` IRQ-safe sobre `lock_api` y guarda/restaura el estado de IRQ en el *guard*.
- **Orden de locks** documentado (p. ej. `scheduler → task → mm`). Nunca tomes dos locks del mismo nivel sin un criterio de orden (p. ej. por dirección).
- **No dormir con spinlock**, no llamar a código que pueda dormir o reasignar con locks de IRQ tomados.
- **Atómicos:** `Relaxed` para contadores estadísticos independientes; `Acquire`/`Release` para publicar/consumir datos a través de una bandera o un lock; `SeqCst` por defecto si dudas, y solo se relaja con una razón escrita. Prueba lo no trivial con `loom`.
- **Estructuras sin lock** (colas SPSC/MPSC, contadores per-CPU, RCU) solo cuando la medición muestre contención; cuidado con ABA y con la reclamación de memoria.
- Mantén secciones críticas **cortas**; mueve el trabajo pesado fuera (copiar datos, asignar, loguear).

## `no_std` y bare-metal

- Capas: `core` (siempre) → `alloc` (cuando existe heap) → `std` (nunca en kernel). Los crates reutilizables declaran `#![no_std]` y activan `std`/`alloc` por *features* aditivas.
- `#[panic_handler]` propio que escriba al puerto serie con ubicación y detenga la CPU (`hlt`/`wfi` en bucle). Usa `panic = "abort"`; con eso `eh_personality` no es necesario.
- `#[global_allocator]` solo después de tener PMM + paginación; antes de eso, usa estructuras estáticas o un *bump allocator* de arranque.
- Si el enlazador pide `memcpy`/`memset`/`memcmp`: habilita `compiler-builtins-mem` en `build-std-features` o provee implementaciones propias (cuidado: el optimizador puede convertir tu bucle de copia en una llamada recursiva a `memcpy`; márcalo con la técnica adecuada o impleméntalo con `asm!`/`rep movsb`).
- Evita punto flotante y SIMD en el kernel salvo que guardes/restaures su estado; los targets `*-unknown-none` de x86_64 ya compilan sin SSE (soft-float) por eso.
- `static` con tamaño fijo para estructuras de arranque; `heapless`/`arrayvec` para colecciones sin heap.
- Funciones desnudas (`#[unsafe(naked)]` + `naked_asm!`, estables en versiones recientes) o `global_asm!` para entradas de interrupción/syscall y cambio de contexto: son pequeñas y están bajo revisión estricta.
- El stack del kernel es pequeño y fijo: nada de arrays grandes en pila, recursión no acotada ni `Box::new([0; N])` que construya primero en pila.

## Cargo y perfiles

```toml
[profile.dev]
panic = "abort"
opt-level = 1          # opt-level 0 suele ser demasiado lento/voluminoso para un kernel

[profile.release]
opt-level = 3          # "s"/"z" si el tamaño manda
lto = "fat"
codegen-units = 1
panic = "abort"
debug = "line-tables-only"   # símbolos útiles sin coste en runtime
```

- `Cargo.lock` versionado en binarios y en el workspace del SO.
- Features **aditivas** (activar una nunca debe romper); `default-features = false` en dependencias del kernel.
- `cargo tree -d` para detectar duplicados; `cargo udeps`/`cargo machete` para dependencias sin uso; `cargo deny` para política.
- Para análisis de rendimiento y backtraces: `-C force-frame-pointers=yes`.

## Tiempos de compilación

- Divide en crates pequeños (la compilación incremental y el paralelismo funcionan por crate).
- `cargo check` en el bucle interno; `cargo build --timings` para encontrar cuellos de botella; `cargo llvm-lines` para ver monomorfización excesiva.
- Enlazador rápido (`lld`/`mold`) y `sccache` en CI.

## Checklist rápido

- [ ] ¿Algún `unwrap`/índice/aritmética sin comprobar sobre datos no confiables?
- [ ] ¿Cada `unsafe` tiene `SAFETY` y la superficie es mínima?
- [ ] ¿Tipos distintos para direcciones físicas/virtuales/usuario?
- [ ] ¿Errores con contexto y mapeados al ABI?
- [ ] ¿Orden de locks respetado y sin dormir con spinlocks?
- [ ] ¿Sin `static mut`, sin referencias a MMIO ni a campos `packed`?
- [ ] ¿`clippy -D warnings`, `fmt`, tests y `miri` en verde?
