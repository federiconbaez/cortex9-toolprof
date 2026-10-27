//! `toolprof` command line.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use cortex9_tracer::syscalls::Arch;
use std::ffi::OsString;
use std::io::BufReader;
use std::path::PathBuf;
use toolprof::{docker, eval, event, profile::Profile, surface, synth};

/// Per-tool seccomp + Landlock profiles synthesized from syscall traces.
#[derive(Debug, Parser)]
#[command(name = "toolprof", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Trace a command (root): JSON lines of the syscalls of tasks whose
    /// comm matches, with path arguments.
    Trace {
        /// Keep tasks with this comm (repeatable; default: all tasks).
        #[arg(short, long = "comm")]
        comms: Vec<String>,
        /// Output file (default stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// eBPF object to load instead of the embedded/default one.
        #[arg(long)]
        object: Option<PathBuf>,
        /// Keep root for the traced command instead of dropping to
        /// SUDO_UID/SUDO_GID.
        #[arg(long)]
        keep_root: bool,
        #[arg(required = true, last = true)]
        command: Vec<OsString>,
    },
    /// Synthesize a profile from a trace.
    Synth {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long = "comm")]
        comms: Vec<String>,
        /// Directory relative AT_FDCWD paths are resolved against.
        #[arg(long, default_value = "/")]
        cwd: PathBuf,
        #[arg(long, default_value_t = 16)]
        max_variants: usize,
        #[arg(long, default_value_t = 32)]
        max_rules: usize,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Write the synthesis report (JSON) here.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Run a command under a profile (unprivileged): Landlock, then the
    /// seccomp filter, then execve.
    Run {
        #[arg(short, long)]
        profile: PathBuf,
        /// Return EPERM instead of killing the process on a violation.
        #[arg(long)]
        errno: bool,
        /// Accept a partially enforced Landlock ruleset (older kernels).
        #[arg(long)]
        allow_partial_landlock: bool,
        #[arg(long)]
        no_seccomp: bool,
        #[arg(long)]
        no_landlock: bool,
        #[arg(required = true, last = true)]
        command: Vec<OsString>,
    },
    /// Offline gate: list trace events the profile's seccomp part would
    /// block. Exit status 1 if there is any.
    Diff {
        #[arg(short, long)]
        profile: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long = "comm")]
        comms: Vec<String>,
    },
    /// Attack-surface metric of a profile against Docker's default
    /// seccomp profile and optional baselines.
    Surface {
        #[arg(short, long)]
        profile: PathBuf,
        /// Docker/moby seccomp profile (default.json format).
        #[arg(long)]
        docker: PathBuf,
        /// Kernel version used for `minKernel` entries.
        #[arg(long, default_value = "6.12")]
        kernel: String,
        /// Extra baseline: NAME=FILE with a JSON list of syscall names
        /// allowed without conditions.
        #[arg(long = "baseline")]
        baselines: Vec<String>,
        #[arg(long)]
        json: bool,
    },
}

fn read_profile(p: &PathBuf) -> Result<Profile> {
    let s = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    Profile::from_json(&s).with_context(|| format!("parsing {}", p.display()))
}

fn read_trace(p: &PathBuf) -> Result<Vec<event::TraceEvent>> {
    let f = std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?;
    event::parse(BufReader::new(f)).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}

fn arch() -> Result<Arch> {
    Arch::host().context("no syscall table for this architecture")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Trace {
            comms,
            output,
            object,
            keep_root,
            command,
        } => cmd_trace(comms, output, object, keep_root, command),
        Cmd::Synth {
            input,
            comms,
            cwd,
            max_variants,
            max_rules,
            output,
            report,
        } => {
            let events = read_trace(&input)?;
            let opt = synth::Options {
                comms,
                cwd,
                max_variants,
                max_rules,
                arch: arch()?,
            };
            let (p, r) = synth::synthesize(&events, &opt);
            if r.events_used == 0 {
                bail!("no events matched; check --comm");
            }
            match output {
                Some(o) => std::fs::write(&o, p.to_json() + "\n")?,
                None => println!("{}", p.to_json()),
            }
            if let Some(rp) = report {
                std::fs::write(&rp, serde_json::to_string_pretty(&r)? + "\n")?;
            }
            let conditioned = p
                .seccomp
                .syscalls
                .iter()
                .filter(|s| !s.rules.is_empty())
                .count();
            eprintln!(
                "toolprof: {} events from {} processes -> {} syscalls ({} with argument conditions), {} landlock rules, {} unresolved paths",
                r.events_used,
                r.processes,
                p.seccomp.syscalls.len(),
                conditioned,
                p.landlock.fs.len(),
                r.unresolved_paths.len()
            );
            Ok(())
        }
        Cmd::Run {
            profile,
            errno,
            allow_partial_landlock,
            no_seccomp,
            no_landlock,
            command,
        } => cmd_run(
            profile,
            errno,
            allow_partial_landlock,
            no_seccomp,
            no_landlock,
            command,
        ),
        Cmd::Diff {
            profile,
            input,
            comms,
        } => {
            let p = read_profile(&profile)?;
            let events = read_trace(&input)?;
            let a = arch()?;
            let mut blocked = 0usize;
            let mut total = 0usize;
            for e in &events {
                if !comms.is_empty() && !comms.contains(&e.comm) {
                    continue;
                }
                total += 1;
                if !eval::allows(&p, e.nr, &e.args) {
                    blocked += 1;
                    let name = a.name(e.nr).unwrap_or("?");
                    println!(
                        "blocked: pid {} {} ({}) args {:#x?}",
                        e.pid, name, e.nr, e.args
                    );
                }
            }
            println!("{blocked} of {total} events would be blocked");
            if blocked > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        Cmd::Surface {
            profile,
            docker: docker_path,
            kernel,
            baselines,
            json,
        } => {
            let p = read_profile(&profile)?;
            let a = arch()?;
            let dj = std::fs::read_to_string(&docker_path)?;
            let d = docker::import(&dj, a, docker::DEFAULT_CAPS, &kernel)
                .map_err(|e| anyhow::anyhow!("{}: {e}", docker_path.display()))?;
            let ps = surface::measure(&p.seccomp);
            let ds = surface::measure(&d.seccomp);
            let mut reds = vec![surface::reduction("docker-default", &ps, &ds)];
            for b in &baselines {
                let (name, file) = b.split_once('=').context("--baseline expects NAME=FILE")?;
                let names: Vec<String> = serde_json::from_str(&std::fs::read_to_string(file)?)?;
                let sc = toolprof::profile::Seccomp {
                    arch: a.to_string(),
                    syscalls: names
                        .iter()
                        .map(|n| {
                            Ok(toolprof::profile::SyscallRule {
                                name: n.clone(),
                                nr: a
                                    .number(n)
                                    .with_context(|| format!("unknown syscall {n}"))?,
                                rules: Vec::new(),
                            })
                        })
                        .collect::<Result<_>>()?,
                };
                reds.push(surface::reduction(name, &ps, &surface::measure(&sc)));
            }
            if json {
                let v = serde_json::json!({
                    "profile": ps,
                    "docker_unknown_names": d.unknown_names.len(),
                    "reductions": reds,
                });
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!(
                    "profile: {} syscalls, weighted {:.3}, {} with conditions",
                    ps.syscalls, ps.weighted, ps.conditioned
                );
                for r in &reds {
                    println!(
                        "vs {}: {} syscalls / weighted {:.3} -> reduction {:.2}% (syscalls), {:.2}% (weighted), {:.2}% (weighted, conservative)",
                        r.baseline,
                        r.baseline_syscalls,
                        r.baseline_weighted,
                        100.0 * r.syscalls,
                        100.0 * r.weighted,
                        100.0 * r.weighted_conservative
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn cmd_trace(
    comms: Vec<String>,
    output: Option<PathBuf>,
    object: Option<PathBuf>,
    keep_root: bool,
    command: Vec<OsString>,
) -> Result<()> {
    let run_as = if keep_root {
        None
    } else {
        match (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
            (Ok(u), Ok(g)) => Some((u.parse()?, g.parse()?)),
            _ => None,
        }
    };
    let opt = toolprof::trace::TraceOptions {
        comms,
        object,
        command,
        run_as,
    };
    let summary = match output {
        Some(o) => {
            let f = std::fs::File::create(&o)?;
            let mut w = std::io::BufWriter::new(f);
            toolprof::trace::run(&opt, &mut w)?
        }
        None => {
            let mut w = std::io::BufWriter::new(std::io::stdout().lock());
            toolprof::trace::run(&opt, &mut w)?
        }
    };
    eprintln!(
        "toolprof: {} events, {} dropped in kernel, {} undecodable; command {}",
        summary.events, summary.dropped, summary.undecodable, summary.status
    );
    if summary.dropped > 0 || summary.undecodable > 0 {
        bail!("trace is incomplete: a profile from it could block real calls");
    }
    if !summary.status.success() {
        bail!("traced command failed: {}", summary.status);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cmd_trace(
    _: Vec<String>,
    _: Option<PathBuf>,
    _: Option<PathBuf>,
    _: bool,
    _: Vec<OsString>,
) -> Result<()> {
    bail!("tracing requires Linux")
}

#[cfg(target_os = "linux")]
fn cmd_run(
    profile: PathBuf,
    errno: bool,
    allow_partial_landlock: bool,
    no_seccomp: bool,
    no_landlock: bool,
    command: Vec<OsString>,
) -> Result<()> {
    use toolprof::enforce::{exec_confined, ExecOptions, Violation};
    let p = read_profile(&profile)?;
    exec_confined(
        &p,
        &command,
        ExecOptions {
            on_violation: if errno {
                Violation::Errno
            } else {
                Violation::Kill
            },
            strict_landlock: !allow_partial_landlock,
            seccomp: !no_seccomp,
            landlock: !no_landlock,
        },
    )
}

#[cfg(not(target_os = "linux"))]
fn cmd_run(_: PathBuf, _: bool, _: bool, _: bool, _: bool, _: Vec<OsString>) -> Result<()> {
    bail!("enforcement requires Linux")
}
