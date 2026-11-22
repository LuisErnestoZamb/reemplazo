# `user-edit` — hito 4

Primer editor como **proceso de usuario** (`no_std`, sin heap, sin libc).
`xtask smoke-user` compila este crate con `code-model=large` acotado a esa
invocación y lo graba en el ISO dedicado bajo el nombre de módulo `hello`
(el loader U1 tiene una sola ranura de captura).

## Qué demuestra

1. `USER_CONSOLE_OK` / `USER_SHELL_OK` — el mismo preámbulo VGA y el REPL
   de una línea del hito 3, para que la cadena de marcadores y la fase de
   teclado de `smoke-user` sigan iguales.
2. `USER_FS_OK` — syscalls 10..=15 contra el volumen en memoria del kernel:
   `Open` → `Read` → `Stat` → `Readdir(Close)` → `Close`, más violaciones
   deliberadas (`..`, fichero inexistente, fd 0) que deben devolver
   `EPERM` / `EINVAL`.
3. `USER_EDITOR_OK` — el documento se edita en un gap buffer de capacidad
   fija (`mod gapbuf`, `forbid(unsafe_code)`), se guarda con
   `Open(O_WRONLY|O_TRUNC)` + `Write`, se cierra, se vuelve a abrir y se
   compara **byte a byte** con el resultado esperado, con `Stat` de tamaño.

## ABI usada

`userlib::fs_open/fs_close/fs_read/fs_write/fs_stat/fs_readdir`, con
constantes `NR_OPEN..NR_READDIR`, `O_*`, `STAT_LEN` y `DIRENT_LEN` añadidas
sin tocar las funciones del hito 1/3. Todos los buffers pasan por
`userptr` en el kernel; los fd son opacos y se indexan por PID.

## Deuda conocida

`sched::install_context` publica `brk_end = PCB.brk_end`, que el spawn
actual deja a 0; tras un cambio de contexto el VMA de `.data` del proceso
se pierde y los `Write` de usuario devuelven `EFAULT`. Afecta también al
shell del hito 3 y es competencia del integrador de `sched.rs`.
