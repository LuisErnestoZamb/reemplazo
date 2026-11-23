# `user-net` — hito 5 (red/TLS desde CPL3)

`no_std`, sin heap. Ejercita las syscalls 16..=21 del kernel:

| # | syscall | qué prueba el proceso |
|---|---|---|
| 16 | `DnsResolve` | resuelve `10.0.2.3` (literal, sin red) y rechaza `evil.example` con `EPERM` |
| 17 | `SockConnect` | conecta a `10.0.2.2:8099` (mock de chat) con IP de 4 octetos |
| 18 | `SockSend` | envía un `GET /` mínimo |
| 19 | `SockRecv` | recibe con `EAGAIN` → `yield_now()` acotado; compara `HTTP/1.1 200` y `reemplazo: mock reply ok` |
| 20 | `SockClose` | cierra el handle opaco |
| 21 | `TlsUpgrade` | envuelto por `userlib`, con whitelist de hosts en el kernel (no lo usa el smoke) |

Imprime `USER_NET_OK` y termina con `exit(0)`; el handler de los hitos 3/4
(`src/legacy.rs`) corre antes para conservar la cadena de markers de
`smoke-user`.

## Deuda / integración

El loader U1 tiene **un solo slot** de módulo (`hello`), así que este ELF
sustituye a `user/edit` en el ISO de `smoke-user` y vuelve a probar U3/U4.
Cuando el loader capture un segundo módulo, `legacy.rs` vuelve a `user/edit`
y este proceso queda dedicado a red. El despacho de syscalls requiere tres
líneas del integrador en `kernel/src/{main.rs,userland/mod.rs,userland/syscall.rs}`;
están documentadas en el reporte del hito y en los comentarios de
`kernel/src/userland/net.rs`.
