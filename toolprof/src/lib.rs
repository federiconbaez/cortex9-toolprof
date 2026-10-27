//! toolprof: per-tool sandbox profiles synthesized from syscall traces.
//!
//! Pipeline: trace the tool's test suite with the eBPF loader
//! ([`trace`], root only) -> read the JSON-lines trace ([`event`]) ->
//! synthesize a [`profile::Profile`] ([`synth`]): a seccomp allow-list with
//! argument conditions where the observed values are stable plus Landlock
//! filesystem rules from the observed paths -> enforce it unprivileged
//! ([`enforce`]) and rerun the suite.
//!
//! Everything except [`trace`] is plain Rust testable without privileges.

pub mod argspec;
pub mod docker;
pub mod elf;
pub mod eval;
pub mod event;
pub mod profile;
pub mod surface;
pub mod synth;

#[cfg(target_os = "linux")]
pub mod enforce;
#[cfg(target_os = "linux")]
pub mod trace;
