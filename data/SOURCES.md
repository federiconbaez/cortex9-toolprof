# Data sources

| File | Source | License |
|---|---|---|
| `docker-default.json` | `seccomp/default.json` of [moby/profiles](https://github.com/moby/profiles) at commit `6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef` (2026-09-17), unmodified | Apache-2.0 |
| `baseline-mcp-server-rs.json` | `allowed_syscalls()` in `src/sandbox.rs` of [mcp-server-rs](https://github.com/federiconbaez/mcp-server-rs) at `9da13ddb13a4f33870873ce1fe8d995a3819f1a8` | Apache-2.0 |

The default capability set used to evaluate `docker-default.json`
(`toolprof::docker::DEFAULT_CAPS`) is `DefaultCapabilities()` from moby
`daemon/pkg/oci/caps/defaults.go`.
