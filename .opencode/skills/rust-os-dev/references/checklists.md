# Checklists

Úsalas como lista de verificación al revisar o cerrar trabajo. Marca solo lo que hayas comprobado de verdad; lo que no aplique, descártalo explícitamente.

## Cambio general (antes de proponer o fusionar)

- [ ] Resuelve el problema pedido y nada más (sin cambios ajenos mezclados).
- [ ] Compila sin warnings para todos los targets relevantes.
- [ ] `cargo fmt --check` y `cargo clippy --workspace --all-targets -- -D warnings` pasan.
- [ ] Hay tests nuevos o actualizados que fallarían sin el cambio; los tests existentes pasan.
- [ ] Si toca el kernel: smoke test en QEMU ejecutado (salida adjunta o descrita).
- [ ] Errores manejados; sin `unwrap`/`expect`/índices sobre datos externos.
- [ ] Documentación y `docs/roadmap.md` actualizados; ADR si hay decisión importante.
- [ ] Mensaje de commit con Conventional Commits y explicación del porqué; commit atómico.
- [ ] Sin secretos, artefactos de build ni imágenes en el diff.

## Revisión de `unsafe`

- [ ] ¿Es imprescindible? ¿Existe una alternativa segura o un crate auditado?
- [ ] El bloque es lo más pequeño posible y está en un módulo/crate acotado.
- [ ] Cada bloque tiene `// SAFETY:` con las precondiciones **concretas** y por qué se cumplen aquí.
- [ ] Cada `unsafe fn`/`unsafe trait` documenta `# Safety` (qué debe garantizar quien llama o implementa).
- [ ] Sin riesgo de aliasing (`&mut` duplicados), referencias desalineadas, nulas o colgantes.
- [ ] Sin lectura de memoria sin inicializar; valores válidos para su tipo (bool, enum, referencias).
- [ ] Accesos a MMIO mediante `read_volatile`/`write_volatile` y punteros, no referencias.
- [ ] `repr(C)`/`repr(transparent)` donde el layout importa; campos `packed` tratados con `&raw`/`read_unaligned`.
- [ ] `Send`/`Sync` implementados a mano solo con justificación escrita del invariante.
- [ ] `asm!` declara bien operandos, *clobbers* y opciones (`nomem`, `nostack`, `preserves_flags`).
- [ ] Probado con `miri` (si es lógica pura) y con un test que ejercita los límites.

## Concurrencia y kernel

- [ ] Para cada dato compartido: ¿quién lo protege frente a otras CPUs, a handlers de IRQ y a la preempción?
- [ ] Locks con IRQ deshabilitadas si se comparten con un handler; orden de locks respetado y documentado.
- [ ] Sin dormir, asignar ni loguear en exceso dentro de un handler de IRQ.
- [ ] Sin spinlocks tomados al llamar a código que puede dormir o replanificar.
- [ ] Orden de memoria de los atómicos justificado; estructuras sin lock probadas con `loom`.
- [ ] Recursos liberados en todas las rutas de error (`Drop`/guards) y en la terminación del proceso.
- [ ] El cambio de pila/contexto conserva el estado completo; guard pages intactas.

## Nueva syscall

- [ ] Contrato documentado: argumentos, retorno, errores, efectos, límites de recursos.
- [ ] Todos los punteros de usuario pasan por `copy_*_user`; rangos con `checked_add`; una sola copia de los argumentos.
- [ ] Longitudes y contadores acotados (sin asignaciones controladas sin límite por el usuario).
- [ ] Comprobación de permisos/capabilities antes de actuar.
- [ ] Comportamiento definido ante señales, cancelación, proceso muriendo y recursos agotados.
- [ ] No filtra memoria ni punteros del kernel (inicializa buffers de salida; limpia registros).
- [ ] Tests con entradas válidas **y hostiles**; incluida en el fuzzer de syscalls.
- [ ] ABI versionado: número de syscall asignado y registrado.

## Nuevo driver

- [ ] Especificación del dispositivo leída; secciones citadas en comentarios.
- [ ] MMIO/puertos encapsulados con wrappers tipados; todo el `unsafe` en una capa fina.
- [ ] Propiedad exclusiva de BARs/IRQs/DMA; `Drop` libera y deshabilita el dispositivo.
- [ ] DMA con direcciones físicas, alineación y barreras correctas; buffers no reutilizados antes de finalizar.
- [ ] Handler de IRQ mínimo; EOI/ack correcto; trabajo pesado diferido.
- [ ] Manejo de errores, timeouts y reinicio del dispositivo; sin esperas activas infinitas.
- [ ] Probado en QEMU con el dispositivo emulado y, si es posible, en otro entorno.
- [ ] Entrada del dispositivo (descriptores, longitudes) tratada como no confiable.

## Cambio de rendimiento

- [ ] Objetivo y métrica definidos; línea base guardada (entorno, comando, resultados con dispersión).
- [ ] Perfil que identifica el cuello de botella real.
- [ ] Un solo cambio medido; resultado antes/después en el mismo entorno (no solo QEMU TCG).
- [ ] Tests de corrección siguen verdes; sin `unsafe` nuevo sin justificación escrita.
- [ ] Benchmark añadido al repositorio/CI para evitar regresiones.
- [ ] Compromisos (memoria, latencia, complejidad) anotados en el commit o ADR.

## Cierre de hito del SO

- [ ] La "definición de hecho" del hito se cumple y se demuestra con un comando (`cargo xtask test`/`run`).
- [ ] El kernel arranca limpio desde cero con la imagen generada por `xtask`.
- [ ] CI en verde, incluido el smoke test de QEMU.
- [ ] Sin `TODO` sin issue; deuda conocida anotada en `docs/roadmap.md`.
- [ ] `docs/architecture.md` y ADRs al día; *tag* del hito creado.
- [ ] Siguiente hito planificado con su definición de hecho.

## Antes de publicar una versión

- [ ] `cargo deny check` y `cargo audit` limpios (o excepciones documentadas).
- [ ] Fuzzers y estrés ejecutados durante un tiempo razonable sin hallazgos abiertos.
- [ ] `CHANGELOG.md` y versión actualizados; licencias de dependencias revisadas.
- [ ] Instrucciones de compilación y ejecución verificadas en una máquina limpia.
- [ ] `SECURITY.md` con el canal de contacto para vulnerabilidades.
