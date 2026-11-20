# Mejores prácticas de ingeniería de software

Contenido: [Proceso](#proceso) · [Arquitectura](#arquitectura-y-diseño) · [Código limpio](#código-limpio) · [Git](#control-de-versiones) · [Revisión](#revisión-de-código) · [Testing](#testing) · [CI/CD](#cicd-y-reproducibilidad) · [Seguridad](#seguridad) · [Documentación](#documentación) · [Observabilidad](#observabilidad) · [Deuda técnica](#deuda-técnica) · [Dependencias](#dependencias-y-licencias)

## Proceso

- **Define "hecho" antes de empezar.** Cada tarea tiene un criterio de aceptación observable ("el kernel imprime X por serial y sale con código 0"), no una descripción de actividad.
- **Riesgos primero.** Si hay una incógnita grande (¿funciona el boot en UEFI?, ¿cuánto cuesta este lock?), haz un *spike* de tiempo acotado y descártalo o intégralo. No construyas encima de una suposición sin probar.
- **Incrementos verticales.** Entrega una rebanada delgada que atraviese todas las capas y funcione, y engrósala después. Es preferible un allocator ingenuo integrado y probado que uno brillante aislado.
- **Time-boxing.** Si una tarea supera con holgura su estimación, para y replantea (¿descomponer?, ¿falta información?).
- **Decisiones registradas.** Todo lo difícil de revertir (arquitectura, ABI, formato de disco, modelo de concurrencia) va a un ADR (plantilla abajo).

```markdown
# ADR-NNNN: <título corto>
- Estado: propuesta | aceptada | reemplazada por ADR-XXXX
- Fecha: AAAA-MM-DD

## Contexto
Qué problema hay y qué fuerzas actúan (requisitos, restricciones).

## Decisión
Qué se decide, en una o dos frases claras.

## Alternativas consideradas
Cada una con su pro y su contra.

## Consecuencias
Positivas, negativas y deuda que se asume.
```

## Arquitectura y diseño

- **Separación de responsabilidades.** Cada módulo tiene una razón para cambiar. Interfaces estrechas, detalles ocultos; las dependencias apuntan hacia el núcleo estable (dominio), nunca desde él hacia los detalles (hardware, formato, red).
- **Núcleo funcional, frontera imperativa.** La lógica (algoritmos de asignación, planificación, parsing, VFS) se escribe como código puro y determinista, testeable en el host. El efecto (registros, MMIO, I/O) se queda en una capa fina detrás de un `trait`. Esto es lo que hace posible probar un kernel con `cargo test`.
- **Composición sobre herencia.** En Rust: structs + traits pequeños. Un trait por capacidad, no un trait "dios".
- **SOLID, aplicado con criterio.** SRP y DIP (depender de traits) rinden mucho; no crees un trait por cada struct "por si acaso".
- **KISS, YAGNI.** No construyas extensibilidad que nadie ha pedido. La regla de tres: abstrae al ver el tercer caso, no el primero.
- **DRY con cuidado.** Duplicar dos veces es más barato que una abstracción equivocada. Sí unifica *conocimiento* (constantes, formatos, reglas de negocio) duplicado.
- **Invariantes en la construcción.** Un valor construido debe ser válido (`new()` que devuelve `Result`, tipos con rango). Así el resto del código no revalida.
- **Diseño de APIs.** Pequeñas, difíciles de usar mal, con nombres que dicen la intención. Sigue las *Rust API Guidelines* (nombres, conversiones `From/Into/AsRef`, `#[must_use]`, `Debug` en todo, errores con tipo propio).
- **Fronteras explícitas.** Dibuja las fronteras de confianza (usuario ↔ kernel, kernel ↔ dispositivo, red ↔ host) y valida en cada una.
- **Evolución.** Las interfaces públicas (ABI de syscalls, formatos en disco, protocolos) se versionan desde el principio; cambiar su semántica después es carísimo.

## Código limpio

- **Nombres** que revelan intención y respetan el dominio (`frame_allocator`, no `mgr2`). Una función que necesita "y" en su nombre hace dos cosas.
- **Funciones pequeñas** y de un solo nivel de abstracción; pocos parámetros (si pasan de cuatro, agrúpalos en un tipo con nombre).
- **Sin números mágicos.** Constantes con nombre, y para registros/bits, el nombre de la especificación más la referencia a la sección.
- **Comentarios que explican el porqué**, no el qué: restricciones, invariantes, referencias a specs, trampas. Código muerto o comentado se borra (Git lo guarda).
- **Errores explícitos.** Nada de fallos silenciosos; propaga con contexto.
- **Estado global mínimo.** Si es inevitable (tabla de IRQ, per-CPU), encapsúlalo detrás de una API con lock y documenta su inicialización.
- **Regla del boy scout y "tidy first".** Deja el código algo mejor de lo que lo encontraste, pero en commits separados del cambio funcional.

## Control de versiones

- **Commits atómicos y bisectables:** cada commit compila y pasa tests. Un cambio lógico por commit.
- **Mensajes con [Conventional Commits](https://www.conventionalcommits.org):** `feat(mm): add buddy frame allocator`, `fix(irq): send EOI after spurious vector`, `perf(sched): per-cpu runqueue`, `refactor`, `test`, `docs`, `build`, `ci`. El cuerpo explica el *porqué*.
- **Ramas cortas** (trunk-based): integra a menudo; usa *feature flags* o cfg para trabajo incompleto en lugar de ramas largas.
- **PRs pequeños** (idealmente < 400 líneas de diff real). Descripción: contexto, qué cambia, cómo se probó, riesgos.
- **Versionado semántico** para crates publicados, *tags* en hitos del SO y `CHANGELOG.md` mantenido (Keep a Changelog).
- No se commitean artefactos de build, imágenes de disco ni secretos; `.gitignore` desde el primer día.

## Revisión de código

Revisa en este orden: (1) ¿resuelve el problema correcto?, (2) ¿es correcto (invariantes, concurrencia, errores, `unsafe`)?, (3) ¿está probado?, (4) ¿es legible y mantenible?, (5) ¿rendimiento y seguridad dentro del presupuesto?, (6) estilo (lo hacen las herramientas, no las personas). Los comentarios distinguen *bloqueante* de *sugerencia*. Lista concreta en `checklists.md`.

## Testing

- **Pirámide:** muchos tests unitarios rápidos y deterministas en el host; menos de integración (QEMU); pocos de extremo a extremo.
- **Un bug = un test de regresión** que falle antes de la corrección.
- **Property-based testing** (`proptest`) para algoritmos con invariantes (allocators, parsers, estructuras de datos). **Fuzzing** (`cargo-fuzz`) para todo lo que parsea entrada no confiable.
- **Tests deterministas:** sin dependencia de tiempo real ni de orden de ejecución; semillas fijas y registradas.
- **Dobles de prueba vía traits** para hardware (un `FakeFrameSource`, un `MockDisk`).
- **Cobertura como señal, no como objetivo.** Un 100 % sin aserciones no vale nada; prioriza ramas de error y límites.
- Detalles de kernel en `testing-debugging.md`.

## CI/CD y reproducibilidad

Pipeline mínimo en cada push/PR, en este orden (falla rápido):
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. Compilación de todos los targets (host y bare-metal)
4. Tests del host (`cargo test` o `cargo nextest`) y `cargo miri test` sobre los crates con `unsafe` en lógica pura
5. Smoke/integración en QEMU headless con *timeout*
6. `cargo deny check` y `cargo audit`
7. `cargo doc --no-deps` con `RUSTDOCFLAGS="-D warnings"`

Reproducibilidad: `rust-toolchain.toml` fijo, `Cargo.lock` versionado, versiones de QEMU/OVMF/Limine documentadas, imágenes generadas por `xtask` y no a mano. Cachea `target/` y el registro de Cargo en CI.

## Seguridad

- **Modelado de amenazas ligero** al diseñar cada frontera: ¿quién controla esta entrada?, ¿qué pasa si es hostil?, ¿qué activo se pierde? (STRIDE como guía).
- **Mínimo privilegio y defensa en profundidad:** aislamiento de espacios de direcciones, W^X/NX, SMEP/SMAP (o PAN/PXN en ARM, SUM en RISC-V), guard pages, KASLR, validación en todas las fronteras.
- **Memoria segura por construcción:** Rust elimina clases enteras de bugs, pero no el `unsafe`, la lógica ni la concurrencia; esos siguen siendo tu responsabilidad.
- **Entrada hostil:** longitudes con `checked_add/mul`, copia única de argumentos (evita TOCTOU), límites de recursos (memoria, descriptores, tamaño de mensaje).
- **Cadena de suministro:** `cargo deny` (licencias, fuentes, duplicados), `cargo audit` (RustSec), `cargo vet` en proyectos serios; fija versiones y revisa los cambios al actualizar.
- **Secretos:** nunca en el repo ni en logs; comparaciones de secretos en tiempo constante; borra claves de memoria (`zeroize`).
- **Divulgación responsable:** `SECURITY.md` con canal de contacto.

## Documentación

- `README`: qué es, por qué existe, cómo compilar y ejecutar en tres comandos.
- `docs/architecture.md`: mapa de subsistemas y dependencias; `docs/adr/`: decisiones; `docs/roadmap.md`: hitos y estado.
- **rustdoc** en toda API pública, con ejemplos que son *doctests*; secciones `# Safety`, `# Panics`, `# Errors` donde aplique.
- Documenta invariantes y contratos junto al código; los diagramas viven en texto (Mermaid/ASCII) para versionarse.
- La documentación se actualiza en el mismo PR que el cambio.

## Observabilidad

- Logging con niveles (`error/warn/info/debug/trace`) mediante el crate `log` (compatible con `no_std`); cada subsistema con su *target*. En kernel, el sumidero por defecto es el puerto serie.
- Contadores y estadísticas expuestos (fallos de página, cambios de contexto, IRQs por vector) para detectar anomalías y medir.
- Los `panic` incluyen ubicación, registros relevantes y, si es posible, *backtrace* por frame pointers.
- Evita logs en rutas calientes y dentro de handlers de IRQ (o usa un buffer circular sin bloqueo).

## Deuda técnica

- Marca la deuda: `// TODO(#123): ...` con *issue* asociado; sin issue no hay TODO.
- Reserva tiempo regular para pagarla; refactoriza con tests en verde antes y después.
- Anota en el ADR la deuda que se acepta conscientemente ("lock global hasta M9").

## Dependencias y licencias

- Antes de añadir un crate: ¿está mantenido?, ¿tiene `unsafe` sensible?, ¿soporta `no_std` y `default-features = false`?, ¿su licencia es compatible?, ¿cuánto añade al árbol (`cargo tree`)?
- Prefiere crates pequeños y centrados; evita dependencias pesadas para resolver 20 líneas.
- Features de Cargo siempre aditivas; fija MSRV si publicas crates.
