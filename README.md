# cortex9-toolprof

[![CI](https://github.com/federiconbaez/cortex9-toolprof/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/cortex9-toolprof/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Perfiles de sandbox **por herramienta** sintetizados a partir de trazas eBPF: allow-list seccomp **con condiciones sobre argumentos** (flags de `mmap`/`openat`/`socket`, fds, comandos) donde los valores observados son estables, más reglas **Landlock** de filesystem a partir de los paths observados. Se aplican sin privilegios y se vuelve a correr la suite de la herramienta.

Per-**tool** sandbox profiles synthesized from eBPF traces: a seccomp allow-list **with argument conditions** where the observed values are stable, plus **Landlock** filesystem rules from the observed paths. Enforced unprivileged, then the tool's test suite is rerun.

> **ES** primero · **EN** below

---

## Español

### Pipeline

```text
 suite de la tool ──▶ toolprof trace (sudo, eBPF) ──▶ trace.jsonl
                                                         │
                     toolprof synth ◀────────────────────┘
                         │  seccomp: syscall + (arg == valor) si es estable
                         │  Landlock: derechos por path (open flags, execve, PT_INTERP)
                         ▼
                    profile.json ──▶ toolprof run (sin privilegios):
                                     Landlock → filtro seccomp → execve(tool)
                                          │
                     suite otra vez ◀─────┘   0 bloqueos = criterio
```

| Crate | Qué tiene |
|---|---|
| `toolprof-common` | `no_std`: el registro del tracer publicado (`SyscallEvent`, 112 bytes, reusado de `cortex9-tracer-common`) seguido de 256 bytes de path. |
| `toolprof-ebpf` | Programa eBPF derivado de [cortex9-ebpf-tracer](https://github.com/federiconbaez/cortex9-ebpf-tracer) (nightly + `bpf-linker`). Workspace propio. |
| `toolprof` | Biblioteca (síntesis, evaluación, métrica, import del perfil de Docker) + CLI `trace`, `synth`, `run`, `diff`, `surface`. |
| `calc-tool` | Demo: el evaluador `calc` de [mcp-server-rs](https://github.com/federiconbaez/mcp-server-rs) como proceso stdin/stdout, y `calc-suite`, su suite end-to-end (55 casos + fuzzing). |

Del tracer publicado se reusan, fijados por commit (`c6732e6`), el layout del evento, el decodificador, el formato JSON lines y las tablas de syscalls; el repo del tracer no se modificó. El programa eBPF de toolprof agrega tres cosas que la síntesis necesita:

- **Filtro por `comm` en el kernel**, con `execve`/`execveat` siempre registrados en la entrada (el `comm` cambia recién cuando el exec tiene éxito; la salida vuelve a filtrar).
- **Captura del path** (`bpf_probe_read_user_str`) en la entrada de las syscalls con path (tabla `PATH_ARGS`), antes de que `execve` reemplace esa memoria.
- **Syscalls que no vuelven**: `exit` y `exit_group` se emiten en la entrada. El tracer original no las ve (no llegan a `sys_exit`) y un perfil hecho con esa traza mataría a todo proceso al terminar.

### Síntesis

**seccomp.** Por cada syscall observada se mira la tabla `argspec` (sólo argumentos por valor: seccomp-BPF ve registros, no memoria):

- `Flags` (prot/flags de `mmap`, flags de `openat`, `cmd` de `fcntl`, `op` de `futex`, señal de `rt_sigaction`...): se condiciona si tomó ≤ `--max-variants` (16) valores distintos.
- `Fd`: sólo si todos los valores son 0, 1 o 2 (los demás dependen del orden de apertura).
- `DirFd`: sólo si siempre fue `AT_FDCWD`.

Cada tupla distinta de valores conservados es una regla `arg == valor` (comparación de 32 bits para `int`); si hay más de `--max-rules` (32) tuplas se descarta el argumento con más valores. El reporte (`--report`) dice qué argumento se descartó y por qué.

**Landlock** (ABI 6: filesystem + TCP + scoping). Sólo llamadas exitosas: `open*` según `O_ACCMODE`, `O_TRUNC`, `O_CREAT` (→ `make_reg` en el directorio), `O_DIRECTORY`; `O_PATH` no necesita derecho. `execve` → `execute` + `read_file` sobre el binario **y su intérprete `PT_INTERP`**, que el kernel abre sin syscall visible. Las reglas son sobre archivos exactos. Si no se observa actividad TCP/UDP se maneja TCP sin puertos permitidos; si no hay señales a otros procesos se activa el scoping.

### Métrica de superficie (definición)

Sobre x86_64:

1. **syscalls**: cantidad de números de syscall invocables con al menos una combinación de argumentos.
2. **ponderada**: suma, sobre las syscalls permitidas, de la fracción de su *dominio de referencia de argumentos* que las reglas aceptan. El dominio es el producto cartesiano de los dominios de `argspec` (p. ej. `mmap`: 8 valores de `prot` × 256 combinaciones de 8 bits de `flags` = 2048 puntos; `openat`: 3 modos × 2⁹ flags = 1536). Una syscall sin dominio, o sin condiciones, pesa 1. Las condiciones sobre argumentos sin dominio (fds, `ioctl`, `clone`) se toman como satisfacibles: la métrica sólo acredita filtrado que puede contar.

Reducción = `1 − perfil / base`. La base es el perfil por defecto de Docker (`data/docker-default.json`, moby/profiles `6fe7deb`) evaluado para amd64, con las capabilities por defecto de Docker y kernel 6.12, con la misma evaluación (`toolprof::docker`). La variante "conservadora" le da peso 0 a las syscalls de Docker condicionadas que la métrica no puede acreditar.

### Resultados medidos

VM Linux 6.12 x86_64 (`sudo` sólo para trazar). Comando: `scripts/measure.sh`.

| Medición | Resultado |
|---|---|
| Traza de la suite (55 casos) | 4068 eventos de 55 procesos, 0 perdidos |
| Perfil sintetizado | 24 syscalls (10 con condiciones de argumentos), 7 reglas Landlock |
| Docker default (amd64, caps por defecto) | 305 syscalls, ponderada 304.696 |
| **Reducción vs Docker** | **92.13 %** (syscalls), **94.53 %** (ponderada), 94.50 % (conservadora) — criterio ≥ 80 %: cumplido |
| **Suite bajo el perfil** | **55/55, 0 bloqueos** — criterio: cumplido |
| `toolprof diff` traza vs perfil | 0 de 4068 eventos bloqueados |
| 6 probes fuera del perfil | 6/6 frenados: `open-file` → `EACCES` (Landlock; seccomp lo deja pasar porque los flags son los del loader), `create-file`, `mmap-exec` (`mmap` está permitido, `PROT_EXEC` anónimo no), `write-stderr` (`write` sólo en fd 1), `socket`, `spawn` → SIGSYS |
| Hold-out: perfil de los casos pares, suite de los impares | 27/27 |
| Fuzzing bajo el perfil (1000 entradas, seed 1) | 1000/1000, 0 bloqueos |
| vs filtro a mano de mcp-server-rs (13 syscalls) | el perfil de toolprof es **más grande**: 24 vs 13 (−84.6 %; −28.1 % ponderada). Ese filtro se instala después del arranque del worker y deja el arranque (exec, loader, runtime) sin filtrar, no condiciona argumentos (permite `mmap` con `PROT_EXEC`) y no tiene Landlock; el de toolprof cubre desde el `execve`. |

### Uso

```sh
(cd toolprof-ebpf && cargo build --release)      # nightly + bpf-linker
cargo build --release --workspace
B=target/release
sudo -E $B/toolprof trace -c calc-tool -o trace.jsonl -- \
    $B/calc-suite --cases calc-tool/cases.tsv -- $PWD/$B/calc-tool
$B/toolprof synth -i trace.jsonl -c calc-tool -o profile.json --report report.json
$B/calc-suite --cases calc-tool/cases.tsv -- $B/toolprof run -p profile.json -- $PWD/$B/calc-tool
$B/toolprof surface -p profile.json --docker data/docker-default.json
$B/toolprof diff -c calc-tool -p profile.json -i trace.jsonl   # compuerta offline
```

`toolprof trace` corre el comando con `SUDO_UID`/`SUDO_GID` y falla si el ring buffer perdió eventos. `toolprof run --errno` devuelve `EPERM` en vez de matar. `toolprof synth` acepta también la salida `-f json` del `cortex9-tracer` original (sin paths: sin reglas Landlock).

### Tests y verificación

- 44 tests: 31 unitarios en `toolprof` (argspec, eventos, evaluación, síntesis seccomp y Landlock, ELF, import de Docker, métrica, decodificación), 2 de layout en `toolprof-common`, 3 de la suite, 7 de integración sin privilegios (`calc-tool/tests/enforce.rs`: perfiles armados a mano prueban SIGSYS, `EACCES` de Landlock, condición sobre `mmap`, condición de fd, modo `--errno` y que los probes sí escapan sin perfil) y 1 de pipeline completo con root (`calc-tool/tests/pipeline.rs`, `#[ignore]`, falla si no es root o si el kernel rechaza el programa).
- En la VM: los 44 pasan (el de pipeline con `sudo` como runner de cargo); el verificador aceptó el programa eBPF (nightly 1.101, bpf-linker 0.12.0).
- CI (GitHub Actions): `check` (fmt, clippy `-D warnings`, tests sin privilegios, que incluyen enforcement real de seccomp y Landlock), `ebpf` (compila y sube el objeto) y `pipeline` (con `sudo`: test de pipeline y `scripts/measure.sh`, que sale con error si no se cumple el criterio).

### Qué no está probado / limitaciones

- **Una sola herramienta, chica y pura.** `calc` no abre archivos, no usa red ni hilos. Que la suite alcance para herramientas con I/O real (paths dinámicos, errores raros, hilos) no está medido: el perfil es tan bueno como la cobertura de la suite. El hold-out y el fuzzing de arriba son sobre `calc`.
- **Argumentos puntero no se filtran**: seccomp-BPF sólo ve registros. Los flags de `openat2` y `clone3` viven en structs; los paths los cubre Landlock.
- Landlock **no** puede restringir `stat`, `access`, `chdir`, `chmod`, `chown`, `fcntl` ni similares (lo dice la documentación del kernel); el reporte los cuenta en `unrestrictable_path_ops`.
- Reglas sobre archivos exactos del host: el perfil no es portable, se sintetiza en la máquina donde se aplica. Los symlinks se resuelven al aplicar. Paths de más de 255 bytes o relativos a un `dirfd` quedan sin resolver (se reportan). `rename`/`link` no se sintetizan.
- `comm` exacto (15 bytes): procesos ajenos con el mismo `comm` durante la traza se mezclarían.
- Tablas de argumentos con valores x86_64; aarch64 no se probó.
- La red sólo se cierra por TCP (Landlock ABI 4); UDP (ABI 10) no se maneja.
- La métrica depende de dominios elegidos a priori (`argspec.rs`) y no acredita condiciones sin dominio; la semántica AND de los `args` de Docker sigue moby y no se contrastó con libseccomp.

### Arte previo (leído)

- [oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook): hook OCI que traza `raw_syscalls:sys_enter` por namespace de PID y genera un perfil que "permite todas las syscalls hechas" — por nombre, por contenedor.
- [Inspektor Gadget `advise_seccomp`](https://inspektor-gadget.io/docs/latest/gadgets/advise_seccomp): perfil por contenedor, lista de nombres con `SCMP_ACT_ALLOW`; advierte que la carga tiene que ejecutar todos los caminos.
- [Docker: seccomp security profiles](https://docs.docker.com/engine/security/seccomp/): el perfil por defecto es una allow-list que bloquea ~44 syscalls de 300+ y sólo usa argumentos en casos puntuales (`personality`, `socket`, `clone`).
- [Kernel: Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html): los filtros no pueden desreferenciar punteros; `SECCOMP_RET_KILL_PROCESS` termina con SIGSYS.
- [Kernel: Landlock](https://docs.kernel.org/userspace-api/landlock.html): derechos por jerarquía de archivos, ABIs, y la lista de operaciones que todavía no puede restringir.

No encontré una herramienta que sintetice a la vez filtros seccomp con condiciones de argumentos y reglas Landlock, por herramienta (proceso) y no por contenedor, y que mida el resultado contra un perfil de referencia; eso no prueba que no exista.

### Licencia

Apache-2.0. Ver [LICENSE](LICENSE). El programa eBPF declara `GPL` en su sección `license`, como exige el kernel para los helpers que usa. `data/docker-default.json` es de moby/profiles (Apache-2.0), ver [data/SOURCES.md](data/SOURCES.md).

---

## English

### Pipeline

Trace the tool's test suite (`toolprof trace`, root, eBPF) → synthesize (`toolprof synth`) → enforce unprivileged (`toolprof run`: Landlock, then the seccomp filter, then `execve` of the tool) → rerun the suite; 0 blocks is the criterion.

| Crate | Contents |
|---|---|
| `toolprof-common` | `no_std`: the published tracer record (`SyscallEvent`, 112 bytes, reused from `cortex9-tracer-common`) followed by 256 path bytes. |
| `toolprof-ebpf` | eBPF program derived from [cortex9-ebpf-tracer](https://github.com/federiconbaez/cortex9-ebpf-tracer) (nightly + `bpf-linker`). Own workspace. |
| `toolprof` | Library (synthesis, evaluation, metric, Docker profile import) + CLI `trace`, `synth`, `run`, `diff`, `surface`. |
| `calc-tool` | Demo: the `calc` evaluator of [mcp-server-rs](https://github.com/federiconbaez/mcp-server-rs) as a stdin/stdout process, and `calc-suite`, its end-to-end suite (55 cases + fuzzing). |

The event layout, decoder, JSON-lines format and syscall tables are reused from the published tracer, pinned to commit `c6732e6`; the tracer repo was not modified. toolprof's eBPF program adds what synthesis needs: an in-kernel `comm` filter (with `execve`/`execveat` always recorded at entry, since `comm` only changes on success), path capture at entry with `bpf_probe_read_user_str`, and emission of `exit`/`exit_group` at entry (they never reach `sys_exit`; a profile built without them would kill every process on exit).

### Synthesis

**seccomp**: per observed syscall, only by-value arguments from `argspec` (seccomp-BPF sees registers, not memory). `Flags` arguments are conditioned when they took ≤ `--max-variants` (16) distinct values; `Fd` only when every value is 0, 1 or 2; `DirFd` only when always `AT_FDCWD`. Each distinct tuple of kept values becomes an `arg == value` rule (32-bit compare for `int`); above `--max-rules` (32) tuples the widest argument is dropped. The report says what was dropped and why.

**Landlock** (ABI 6): successful calls only. `open*` by `O_ACCMODE`, `O_TRUNC`, `O_CREAT` (→ `make_reg` on the directory), `O_DIRECTORY`; `O_PATH` needs nothing. `execve` → `execute` + `read_file` on the binary **and its `PT_INTERP` interpreter**, which the kernel opens without a visible syscall. Rules are on exact files. TCP is handled with no allowed port when no TCP/UDP activity was seen; scoping is on unless signals to other processes were seen.

### Surface metric (definition)

On x86_64: (1) **syscalls**: number of syscall numbers callable with at least one argument combination; (2) **weighted**: sum over allowed syscalls of the fraction of their *reference argument domain* accepted by the rules (cartesian product of the `argspec` domains, e.g. `mmap` 8 `prot` × 256 `flags` = 2048 points, `openat` 3 modes × 2⁹ flags = 1536). A syscall without a domain, or without conditions, weighs 1; conditions on arguments without a domain are assumed satisfiable, so only countable filtering is credited. Reduction = `1 − profile/baseline`. The baseline is Docker's default profile (moby/profiles `6fe7deb`) evaluated for amd64 with Docker's default capabilities and kernel 6.12, with the same evaluator. The "conservative" variant gives weight 0 to Docker's conditioned syscalls the metric cannot credit.

### Measured results

Linux 6.12 x86_64 VM (`sudo` only for tracing). Command: `scripts/measure.sh`.

| Measurement | Result |
|---|---|
| Suite trace (55 cases) | 4068 events from 55 processes, 0 dropped |
| Synthesized profile | 24 syscalls (10 with argument conditions), 7 Landlock rules |
| Docker default (amd64, default caps) | 305 syscalls, weighted 304.696 |
| **Reduction vs Docker** | **92.13 %** (syscalls), **94.53 %** (weighted), 94.50 % (conservative) — ≥ 80 % criterion: met |
| **Suite under the profile** | **55/55, 0 blocks** — criterion: met |
| `toolprof diff` trace vs profile | 0 of 4068 events blocked |
| 6 out-of-profile probes | 6/6 stopped: `open-file` → `EACCES` (Landlock; seccomp lets it through because the flags match the loader's), `create-file`, `mmap-exec` (`mmap` is allowed, anonymous `PROT_EXEC` is not), `write-stderr` (`write` on fd 1 only), `socket`, `spawn` → SIGSYS |
| Held out: profile from even cases, suite of odd cases | 27/27 |
| Fuzzing under the profile (1000 inputs, seed 1) | 1000/1000, 0 blocks |
| vs mcp-server-rs hand-written filter (13 syscalls) | toolprof's profile is **larger**: 24 vs 13 (−84.6 %; −28.1 % weighted). That filter is installed after the worker starts and leaves startup (exec, loader, runtime) unfiltered, has no argument conditions (allows `mmap` with `PROT_EXEC`) and no Landlock; toolprof's covers everything from `execve`. |

### Usage

See the Spanish section for the exact commands (`trace`, `synth`, `run`, `surface`, `diff`). `toolprof trace` runs the command as `SUDO_UID`/`SUDO_GID` and fails if the ring buffer dropped events. `toolprof run --errno` returns `EPERM` instead of killing. `toolprof synth` also accepts plain `cortex9-tracer -f json` output (no paths, hence no Landlock rules).

### Tests and verification

- 44 tests: 31 unit tests in `toolprof`, 2 layout tests in `toolprof-common`, 3 suite tests, 7 unprivileged integration tests (`calc-tool/tests/enforce.rs`: hand-built profiles prove SIGSYS, Landlock `EACCES`, an `mmap` argument condition, an fd condition, `--errno` mode, and that the probes do escape without a profile) and 1 full root pipeline test (`calc-tool/tests/pipeline.rs`, `#[ignore]`, fails when not root or when the kernel rejects the program).
- On the VM all 44 pass (the pipeline one with `sudo` as cargo runner); the verifier accepted the eBPF program (nightly 1.101, bpf-linker 0.12.0).
- CI (GitHub Actions): `check` (fmt, clippy `-D warnings`, unprivileged tests including real seccomp and Landlock enforcement), `ebpf` (builds and uploads the object) and `pipeline` (with `sudo`: pipeline test and `scripts/measure.sh`, which exits with an error if the criterion is not met).

### Not tested / limitations

- **One small, pure tool.** `calc` opens no files, uses no network and no threads. Whether a suite is enough for tools with real I/O (dynamic paths, rare errors, threads) is not measured: the profile is only as good as the suite's coverage. The held-out and fuzzing numbers are for `calc`.
- **Pointer arguments are not filtered**: seccomp-BPF only sees registers. `openat2` and `clone3` flags live in structs; paths are covered by Landlock.
- Landlock **cannot** restrict `stat`, `access`, `chdir`, `chmod`, `chown`, `fcntl` and similar (per the kernel documentation); the report counts them in `unrestrictable_path_ops`.
- Rules are on exact host files: profiles are not portable and must be synthesized where they are applied. Symlinks are resolved at enforcement time. Paths over 255 bytes or relative to a `dirfd` stay unresolved (reported). `rename`/`link` are not synthesized.
- Exact `comm` (15 bytes): unrelated processes with the same `comm` during the trace would be merged.
- Argument tables use x86_64 values; aarch64 was not tried.
- The network is closed for TCP only (Landlock ABI 4); UDP (ABI 10) is not handled.
- The metric depends on domains chosen up front (`argspec.rs`) and does not credit conditions without a domain; the AND semantics for Docker `args` follows moby and was not cross-checked against libseccomp.

### Prior art (read)

- [oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook): OCI hook tracing `raw_syscalls:sys_enter` per PID namespace; the profile "allows all the syscalls made" — by name, per container.
- [Inspektor Gadget `advise_seccomp`](https://inspektor-gadget.io/docs/latest/gadgets/advise_seccomp): per-container profile, a list of names with `SCMP_ACT_ALLOW`; warns the workload must exercise every path.
- [Docker: seccomp security profiles](https://docs.docker.com/engine/security/seccomp/): the default profile is an allow-list blocking ~44 of 300+ syscalls, using arguments only for a few (`personality`, `socket`, `clone`).
- [Kernel: Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html): filters cannot dereference pointers; `SECCOMP_RET_KILL_PROCESS` exits with SIGSYS.
- [Kernel: Landlock](https://docs.kernel.org/userspace-api/landlock.html): file-hierarchy rights, ABIs, and the operations it cannot restrict yet.

I did not find a tool that synthesizes both seccomp filters with argument conditions and Landlock rules, per tool (process) rather than per container, and measures the result against a reference profile; that does not prove none exists.

### License

Apache-2.0. See [LICENSE](LICENSE). The eBPF program declares `GPL` in its `license` section, as the kernel requires for the helpers it uses. `data/docker-default.json` comes from moby/profiles (Apache-2.0), see [data/SOURCES.md](data/SOURCES.md).
