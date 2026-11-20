# Testing y depuración de un kernel

Contenido: [Estrategia por capas](#estrategia-por-capas) · [Tests en host](#1-tests-de-lógica-pura-en-host) · [Tests en QEMU](#2-tests-de-integración-en-qemu) · [Comandos QEMU](#comandos-qemu) · [Depuración](#depuración) · [Síntoma → causa](#síntoma--causa-probable) · [Fuzzing y stress](#fuzzing-y-stress) · [CI](#ci)

## Estrategia por capas

| Capa | Qué prueba | Dónde corre | Velocidad |
|---|---|---|---|
| 1. Unitarios / propiedades | Algoritmos y estructuras (allocators, parsers, VFS, política del scheduler) | `cargo test` en el host, `proptest`, `miri`, `loom` | Segundos |
| 2. Integración de kernel | Subsistemas sobre hardware emulado (paginación, IRQ, syscalls) | QEMU headless, un binario de test por escenario | Segundos–minutos |
| 3. Extremo a extremo | Arranque completo, userland, FS, red | QEMU con imagen completa y aserciones sobre la salida serial | Minutos |
| 4. Fuzzing y estrés | Entrada hostil, carreras, larga duración | `cargo-fuzz`, QEMU `-smp N`, bucles de larga duración | Horas |
| 5. Hardware real | Quirks de firmware y timing | Máquina con consola serial | Manual |

Regla práctica: si algo puede probarse en la capa 1, **no** lo pruebes solo en QEMU. Para ello la lógica vive en crates `no_std` sin dependencias de hardware.

## 1. Tests de lógica pura en host

- `cargo test -p <crate>` sobre los crates `crates/*`. Estructura del crate: `#![cfg_attr(not(test), no_std)]` para poder usar `std` en los tests.
- **Dobles de prueba por trait:** un `FakeMemory`/`MockDisk` implementa el mismo trait que el hardware.
- **Propiedades con `proptest`:** secuencias aleatorias de operaciones contra un modelo simple (p. ej. el allocator frente a un `BTreeSet`). Guarda las semillas de regresión.
- **`cargo miri test`** detecta UB en la lógica con `unsafe` (aliasing, accesos fuera de límites, no inicializados). Miri no ejecuta hardware ni ensamblador: pruébalo en los crates puros.
- **`loom`** para explorar entrelazados en estructuras concurrentes pequeñas.
- **Benchmarks** de estos crates con `criterion`/`divan` (ver `performance.md`).

## 2. Tests de integración en QEMU

**Mecanismo de resultado:** el test debe terminar solo y comunicar éxito/fracaso por el código de salida de QEMU.

- **x86_64:** dispositivo `isa-debug-exit`: `-device isa-debug-exit,iobase=0xf4,iosize=0x04`. Escribir el valor `v` en el puerto `0xf4` hace que QEMU salga con código `(v << 1) | 1`; define `0x10` (→ 33) como éxito y `0x11` (→ 35) como fallo, y haz que `xtask` traduzca esos códigos.
- **RISC-V `virt`:** dispositivo de test `sifive_test` (MMIO, típ. `0x100000`): escribir `0x5555` = éxito; `0x3333 | (código << 16)` = fallo con código.
- **ARM64 / RISC-V:** alternativa con **semihosting** (`-semihosting`) y la llamada `SYS_EXIT`.
- Siempre: `-display none -serial stdio -no-reboot` y un *timeout* en `xtask` (un test colgado no debe bloquear el CI).

**Harness de tests del kernel:** `custom_test_frameworks` es inestable. Alternativas estables: un binario por escenario con `harness = false` y un runner propio, o una macro que registre funciones de test en una sección del enlazador y un `run_tests()` que las recorra, imprimiendo `test nombre ... ok` por serial. Cada test indica su nombre antes de ejecutarse (así un cuelgue se atribuye).

**Tests de extremo a extremo:** `xtask test` arranca la imagen, captura el serial en un archivo y busca cadenas esperadas (con *timeout*): `"[init] listo"`, `"test result: ok"`. Para pánicos esperados, verifica el mensaje y el código de salida.

**Qué escenarios cubrir en el kernel:**
- Excepciones controladas (división por cero, `#PF` en guard page, `ud2`) → el handler imprime y el sistema no se reinicia.
- PMM/VMM: alloc/map/unmap/translate; permisos W^X; liberación sin fugas (cuenta de frames libres antes/después).
- Heap: `Box`/`Vec` crecen y se liberan; estrés de asignaciones de tamaños mixtos.
- Scheduler: N hilos con contadores atómicos; sleep/wake; sin pérdida de despertares.
- Syscalls: argumentos válidos y **hostiles** (punteros nulos, al kernel, no alineados, tamaños `usize::MAX`, desbordes).
- Drivers: contra dispositivos emulados (virtio-blk con imagen conocida → leer/escribir/verificar).

## Comandos QEMU

x86_64 con UEFI (la ruta de OVMF depende de la distro; verifica dónde está instalado):

```bash
qemu-system-x86_64 \
  -machine q35 -m 512M -smp 2 \
  -cpu qemu64                       `# con KVM: -accel kvm -cpu host` \
  -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive format=raw,file=target/disk.img \
  -serial stdio -display none \
  -no-reboot -no-shutdown \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -d int,cpu_reset,guest_errors -D target/qemu.log
```

Depuración con GDB: añade `-s -S` (stub GDB en `localhost:1234` y CPU detenida al inicio).

RISC-V:

```bash
qemu-system-riscv64 -machine virt -cpu rv64 -smp 2 -m 256M -nographic \
  -bios default -kernel target/riscv64gc-unknown-none-elf/debug/kernel
```

ARM64:

```bash
qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 512M -nographic \
  -kernel target/aarch64-unknown-none/debug/kernel
```

Banderas útiles: `-d int` (registra cada excepción/interrupción), `-d cpu_reset` (causa del reinicio), `-d guest_errors`, `-d mmu` (en algunas arquitecturas), `-icount shift=auto` (ejecución más determinista), `-trace`.

## Depuración

**GDB**
```bash
rust-gdb target/x86_64-unknown-none/debug/kernel \
  -ex "target remote :1234" -ex "hbreak kernel_main" -ex "continue"
```
- Usa `hbreak` (breakpoints hardware) en arranque temprano; los de software no funcionan antes de tener la memoria mapeada.
- `info registers`, `x/16gx $rsp`, `bt` (si hay frame pointers), `layout split`. Con `add-symbol-file` si cargas módulos/userland.
- Mantén símbolos en la build de depuración (`debug = true`) y desactiva ASLR/KASLR mientras depuras.

**Monitor de QEMU** (`Ctrl-A C` con `-serial mon:stdio`, o `-monitor`): `info registers`, `info mem`/`info tlb`, `info mtree` (mapa de memoria de la máquina), `xp /8x 0xDIRECCION` (leer memoria física), `info pic`/`info lapic`.

**Técnicas**
- **Serial primero:** un `println!` temprano vale más que diez teorías. Añade trazas con marcas de tiempo y CPU.
- **Reducir hasta reproducir:** bisecta con Git (cada commit arranca) y reduce el escenario (un hilo, `-smp 1`, sin drivers).
- **Pintar la memoria:** rellena memoria liberada con un patrón (`0xDEADBEEF…`) en modo depuración para detectar usos tras liberar; *redzones* en el asignador; contador de fugas.
- **Guard pages** bajo cada pila y entre regiones; así los desbordes fallan de forma limpia.
- **Aserciones de invariantes** en los puntos de entrada de cada subsistema (lock tomado, IRQs deshabilitadas, CPU correcta).
- **Lockdep ligero** y *watchdog* para localizar deadlocks.
- **Backtraces:** con frame pointers, convierte direcciones con `addr2line -e kernel -f -C 0x...`.
- **`-no-reboot`** para congelar la VM en el fallo y poder inspeccionarla en lugar de ver un bucle de reinicios.

## Síntoma → causa probable

| Síntoma | Causas probables | Primer paso |
|---|---|---|
| Reinicio en bucle / triple fault | Pila inválida, IDT/GDT/TSS mal cargados, `#DF` sin IST, `#PF` dentro del handler | `-d int,cpu_reset -no-reboot`; mira la última excepción y su `RIP`/`CR2` |
| Se cuelga tras habilitar interrupciones | EOI olvidado, IRQ no esperada sin handler, tormenta de interrupciones, timer mal configurado | Contadores por vector; enmascara fuentes una a una |
| `#PF` en dirección rara | Mapeo ausente o con flags equivocados (NX/USER/RW), TLB obsoleto, puntero físico usado como virtual | `translate()` de esa dirección; `info mem`/`info tlb` |
| Corrupción aleatoria | Desbordamiento de pila, aliasing/UB, DMA a dirección equivocada, carrera, uso tras liberar | Guard pages, patrón en memoria liberada, `miri` sobre la lógica pura |
| Funciona en debug, falla en release | UB, falta de `volatile`/barreras, `static` con orden de inicialización, pila más justa | Compilar release con `debug = true` y comparar; revisar `unsafe` |
| Funciona en QEMU, falla en hardware | Timing, quirks ACPI/UEFI, atributos de caché, accesos desalineados, mapa de memoria con huecos | Consola serial, logs de tablas del firmware, reducir suposiciones |
| Deadlock ocasional | Orden de locks, spinlock con IRQ habilitadas, dormir con lock | Lockdep ligero, backtrace de todas las CPUs en el watchdog |
| Salida serial entrecortada o duplicada | Lock del logger, buffer de la UART sin esperar, handler que imprime | Poner el logger tras un lock IRQ-safe y esperar el THR vacío |

## Fuzzing y estrés

- **`cargo-fuzz`** (libFuzzer) para parsers en host: ELF, FAT/ext, tar/cpio, ACPI/FDT, paquetes de red. Guarda el corpus y los hallazgos como tests de regresión.
- **Fuzzing de syscalls:** generador de secuencias aleatorias (válidas y hostiles) ejecutado dentro de QEMU con un proceso de usuario; el kernel no debe hacer panic ni filtrar punteros.
- **Estrés:** muchos hilos que asignan/liberan/mapean con `-smp 4`, minutos u horas; vigila contadores de recursos (frames libres, descriptores abiertos) para detectar fugas.
- **Determinismo:** semilla fija y registrada; `-icount` para reproducir carreras.

## CI

Esqueleto en GitHub Actions (adapta nombres y versiones de las acciones a las vigentes):

```yaml
name: ci
on: [push, pull_request]
jobs:
  build-test:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4          # usa la versión vigente
      - name: Toolchain (lee rust-toolchain.toml)
        run: rustup show
      - uses: Swatinem/rust-cache@v2
      - name: Dependencias del sistema
        run: sudo apt-get update && sudo apt-get install -y qemu-system-x86 ovmf xorriso
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test -p frame-alloc -p vfs-core    # crates puros del host
      - run: cargo +nightly miri test -p frame-alloc  # requiere nightly + miri
      - run: cargo xtask test                         # QEMU headless con timeout
      - run: cargo deny check
```

- Imágenes y firmware (Limine, OVMF) con versión fijada y descargados por `xtask` con *checksum*.
- Sube `qemu.log` y la salida serial como artefactos cuando falle un test.
- Mantén el pipeline rápido (< 10 min) y separa los jobs largos (fuzz, estrés) en ejecución nocturna.
