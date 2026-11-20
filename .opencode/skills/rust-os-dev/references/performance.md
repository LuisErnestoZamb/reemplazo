# Rendimiento: método, palancas y herramientas

Contenido: [Método](#método) · [Orden de las palancas](#orden-de-las-palancas) · [Memoria y caché](#memoria-y-caché) · [CPU](#cpu-y-compilador) · [Concurrencia](#concurrencia-y-contención) · [I/O y kernel](#io-y-kernel) · [Compilación](#flags-de-compilación) · [Herramientas](#herramientas) · [Errores de medición](#errores-de-medición-frecuentes) · [Informe](#plantilla-de-informe)

## Método

Optimizar es un experimento, no una intuición:

1. **Define el objetivo** con una métrica y un umbral: latencia p99 < X µs, throughput > Y MB/s, arranque < Z ms, memoria < W MiB. Sin objetivo no sabes cuándo parar.
2. **Establece una línea base reproducible** (mismo hardware, mismos datos, mismo build `release`). Guárdala.
3. **Perfila** para encontrar dónde se va el tiempo realmente. El 90 % del coste suele estar en un 5 % del código, casi nunca donde se supone.
4. **Formula una hipótesis**, cambia **una sola cosa**, vuelve a medir.
5. **Conserva o descarta** según los números, no según la elegancia. Documenta el resultado.
6. **Evita la regresión:** convierte el benchmark en una prueba de CI con umbral o seguimiento de tendencia.

Conceptos que evitan errores de razonamiento:
- **Ley de Amdahl:** acelerar el 10 % del tiempo total como máximo da un 10 % de mejora. Ataca lo grande.
- **Ley de Little:** concurrencia media = throughput × latencia media. Úsala para dimensionar colas, pools y profundidad de colas de dispositivos.
- **Latencia ≠ throughput:** a menudo se compran con el uno el otro (batching sube throughput y latencia). Decide cuál manda.
- **Percentiles, no medias:** reporta p50/p95/p99/máx y la dispersión. Una media esconde la cola.

## Orden de las palancas

De mayor a menor retorno; no pases a la siguiente sin agotar la anterior:

1. **Algoritmo y estructura de datos** (O(n²) → O(n log n), `BTreeMap` vs `HashMap` vs `Vec` ordenado, índices en lugar de búsquedas).
2. **Evitar trabajo:** cachear, diferir (lazy), agrupar (batch), sacar invariantes de bucles, no copiar.
3. **Memoria:** localidad, menos asignaciones, estructuras compactas.
4. **Concurrencia y paralelismo:** menos contención antes que más hilos.
5. **Compilador y flags:** LTO, PGO, `target-cpu`.
6. **Micro-optimización:** SIMD, ensamblador, `unsafe` sin comprobación de límites — solo con perfil que lo justifique y tests que lo protejan.

## Memoria y caché

La memoria, no la CPU, suele ser el cuello de botella: un fallo de caché a DRAM cuesta cientos de ciclos.

- **Localidad:** recorre datos contiguos y en orden. `Vec<T>`/slices ganan casi siempre a listas enlazadas y a árboles de `Box`.
- **SoA frente a AoS:** si un bucle solo toca un campo de muchos elementos, *Structure of Arrays* aprovecha mejor la caché y facilita la autovectorización.
- **Tamaño de los tipos:** revisa `size_of`/`align_of`, el relleno (*padding*) y los `enum` grandes (`-Zprint-type-sizes` en nightly). Ordena campos de mayor a menor alineación o deja que Rust los reordene (`repr(Rust)`); usa `repr(C)` solo cuando el layout debe ser fijo.
- **False sharing:** datos escritos por CPUs distintas no deben compartir línea de caché (64 B en x86_64 y la mayoría de ARM; algunas son 128 B): `#[repr(align(64))]` o `crossbeam_utils::CachePadded`.
- **Menos asignaciones:** `Vec::with_capacity`, reutilizar buffers (`clear()` en lugar de crear), `SmallVec`/`ArrayVec`/`heapless` para colecciones pequeñas, `Box<[T]>` en lugar de `Vec<T>` si no crece.
- **Arenas y *handles*:** guarda los objetos en un `Vec` y refiérelos con índices `u32`: mejor localidad, mitad de tamaño que un puntero de 64 bits, y esquiva los conflictos con el *borrow checker* en grafos.
- **Asignadores especializados:** *bump/arena* para ciclos de vida cortos y uniformes, *slab/pool* para objetos de tamaño fijo (tareas, inodos, buffers de red). En kernel evitan la fragmentación y el coste del asignador general.
- **Páginas grandes** (2 MiB/1 GiB) para mapeos directos del kernel y heaps grandes: menos entradas de TLB y menos *page walks*.
- **Alineación para DMA y MMIO** donde el dispositivo lo exige; para rutas calientes, alinea a la línea de caché.

## CPU y compilador

- **Predicción de saltos:** mantén ramas predecibles; separa el camino frecuente del raro (`#[cold]` en rutas de error, `core::hint::cold_path()` donde esté disponible), evita ramas dentro de bucles internos si pueden elevarse.
- **Inlining:** `#[inline]` en funciones pequeñas que cruzan crates (sin LTO no se inlinean si no llevan el atributo). `#[inline(always)]` solo con evidencia; infla código y puede perjudicar la caché de instrucciones.
- **Monomorfización:** demasiados genéricos inflan el binario; mueve el cuerpo no genérico a una función interna.
- **Comprobación de límites:** usa iteradores (`iter()`, `zip`, `chunks_exact`) en lugar de índices; una aserción previa (`assert!(buf.len() >= 16)`) ayuda a eliminar comprobaciones posteriores. Verifica con `cargo asm` antes de recurrir a `get_unchecked`, que exige prueba escrita de que el índice es válido.
- **Aritmética:** en *release* el desbordamiento envuelve silenciosamente; sé explícito (`wrapping_*`, `checked_*`, `saturating_*`). División y módulo son caros; con potencias de dos usa desplazamientos/máscaras.
- **Autovectorización:** bucles simples sobre slices sin dependencias entre iteraciones. Comprueba el ensamblador resultante; `core::arch` (intrínsecos) o `std::simd` (inestable) solo si el compilador no lo consigue. En kernel el uso de SIMD implica guardar estado (`xsave`).
- **Aprovecha el hardware:** instrucciones como `popcnt`, `bmi2`, AES/SHA con detección en tiempo de ejecución cuando el binario es genérico.
- **Estructuras de datos de la std** con parámetros adecuados: `HashMap` con *hasher* rápido (`ahash`/`rustc-hash`) si no hay riesgo de DoS por colisiones; en entradas no confiables, mantén el hasher resistente.

## Concurrencia y contención

- **Reduce la contención antes de añadir paralelismo:** más hilos sobre un lock caliente empeoran. Técnicas: datos por CPU (*per-CPU*), *sharding* de locks, *batching* de actualizaciones, estructuras de solo lectura casi siempre (RCU/epoch).
- **Mide la contención:** tiempo esperando locks, tasa de fallos de CAS, rebotes de línea de caché (`perf c2c`).
- **Spin vs. dormir:** spin para secciones muy cortas; si la espera puede ser larga, bloquea en una *wait queue*. Usa `core::hint::spin_loop()` (`pause`) en los bucles de espera activa con *backoff* exponencial.
- **Colas sin lock** (SPSC/MPSC de anillo) entre productor y consumidor conocidos suelen ser el mejor punto de partida; evita el *lock-free* general salvo necesidad (ABA, reclamación de memoria, orden de memoria).
- **Afinidad y NUMA:** mantén los datos cerca de la CPU que los usa; evita migraciones innecesarias de tareas calientes.

## I/O y kernel

- **Menos transiciones:** agrupa syscalls (lectura/escritura vectorizada, interfaces de anillos de envío/finalización tipo `io_uring`), evita copias (memoria compartida, *zero-copy*, `mmap`).
- **Interrupciones:** moderación/coalescencia, o sondeo (*polling*) bajo alta carga (como NAPI); *top half* mínimo y trabajo diferido a una cola/tarea.
- **DMA y *scatter-gather*** en lugar de copiar; colas de dispositivo (virtio, NVMe) con profundidad suficiente (ley de Little) y notificaciones agrupadas.
- **TLB:** *shootdowns* son caros (IPIs): agrupa invalidaciones, usa PCID/ASID, páginas grandes, y evita remapear en caliente.
- **Cambio de contexto:** guarda solo el estado necesario (registros callee-saved + pila + CR3/TTBR si cambia el espacio de direcciones); estado FPU/SIMD sólo cuando la tarea lo usa; colas de ejecución por CPU.
- **Planificador:** latencia de despertar y justicia son compromisos; mide *wakeup latency* y tiempo en cola con carga realista antes de cambiar políticas.
- **Page cache y *readahead*** si hay FS; escritura diferida con *flush* acotado; mide tasa de aciertos.
- **Tickless e inactividad:** `hlt`/`wfi`/`mwait` en la tarea inactiva; temporizadores bajo demanda en vez de tick fijo cuando madure el diseño.
- **Arranque:** el tiempo de boot se perfila igual: marca hitos con TSC y optimiza lo secuencial (inicialización de drivers en paralelo, diferir lo que no es necesario para la primera tarea).

## Flags de compilación

- *Release* con `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` (ver `rust-practices.md`). Compara `opt-level = 3` con `"s"`: a veces el código más pequeño es más rápido por caché de instrucciones.
- **PGO** (`cargo-pgo`) y **BOLT** para aplicaciones y rutas calientes estables; requieren perfiles representativos.
- `-C target-cpu=native` solo en binarios que se ejecutan en la misma máquina donde se compilan; para distribuir, fija un nivel (`x86-64-v2/v3`) o usa detección en tiempo de ejecución.
- `debug = "line-tables-only"` y `-C force-frame-pointers=yes` para perfiles útiles sin coste apreciable.

## Herramientas

| Objetivo | Herramienta |
|---|---|
| Microbenchmarks estadísticos | `criterion`, `divan` |
| Benchmarks deterministas para CI (instrucciones/caché) | `iai-callgrind` (requiere Valgrind) |
| Comparar comandos/binarios | `hyperfine` |
| Dónde se va el tiempo (CPU) | `perf`, `cargo flamegraph`, `samply` |
| Fallos de caché, ramas | `perf stat`, `valgrind --tool=cachegrind`/`callgrind` |
| Contención y *false sharing* | `perf c2c`, `perf lock` |
| Asignaciones de memoria | `dhat`, `heaptrack`, contadores en tu allocator |
| Tamaño de binario / genéricos | `cargo bloat`, `cargo llvm-lines` |
| Ensamblador resultante | `cargo asm` / `cargo show-asm`, Compiler Explorer |
| Tiempo en el kernel | contador de ciclos (`rdtsc`/`rdtscp` con `lfence`, `CNTVCT_EL0`, `rdcycle`), PMU, puntos de traza a un buffer circular |

En un kernel propio: calibra el TSC (invariante) contra un reloj conocido, serializa las lecturas, repite cientos de veces y reporta distribución. Emula en QEMU con **KVM** (`-accel kvm -cpu host`) o hardware real para tiempos; con **TCG** (emulación pura) los tiempos no representan una CPU real (solo sirven para contar instrucciones con `-icount`, de forma aproximada).

## Errores de medición frecuentes

- Medir un build `debug`.
- El optimizador elimina el código medido (usa `std::hint::black_box`/`criterion::black_box`).
- Una sola ejecución; sin calentamiento (cachés, TLB, predicción); sin repeticiones ni dispersión.
- Datos de prueba de tamaño o distribución irreal (caben en L1 y en producción no).
- Cambiar varias cosas a la vez; no guardar la línea base.
- Ruido del sistema: gobernador de frecuencia, turbo, otras cargas, migración de hilos. Fija CPU, `performance` governor, aísla núcleos cuando importa.
- Microbenchmark que no representa la carga real; valida con un benchmark de sistema.
- Optimizar sin perfilar y "por si acaso".

## Plantilla de informe

```markdown
### Objetivo
Métrica y umbral (p. ej. p99 de `read()` < 20 µs con 4 hilos).
### Línea base
Entorno (CPU, KVM/hardware, build), comando, resultado con dispersión.
### Hallazgo
Perfil / evidencia de dónde está el coste.
### Cambio
Qué se modifica y por qué debería ayudar.
### Resultado
Antes → después (media, p99, dispersión), mismo entorno y comando.
### Riesgos y compromisos
Complejidad añadida, memoria, latencia vs throughput, `unsafe` nuevo, tests que lo protegen.
```
