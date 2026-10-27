//! Attack-surface metric.
//!
//! Two numbers per seccomp rule set, both on one architecture:
//!
//! - **syscalls**: how many syscall numbers can be invoked with at least
//!   one argument combination.
//! - **weighted**: sum over allowed syscalls of the fraction of their
//!   *reference argument domain* the rules accept. The domain of a syscall
//!   is the cartesian product of the domains listed in
//!   [`crate::argspec`] for its by-value arguments (e.g. `mmap`: 8 `prot`
//!   values x 256 `flags` combinations). A syscall without a listed domain,
//!   or allowed unconditionally, weighs 1. Conditions on arguments outside
//!   the domain (fds, `ioctl` requests, `clone` flags...) are assumed
//!   satisfiable, so they never lower the weight: the metric only credits
//!   argument filtering it can count.
//!
//! The reduction of profile P against baseline B is `1 - P/B` for each
//! number.

use crate::argspec;
use crate::eval::rule_allows_point;
use crate::profile::{Seccomp, SyscallRule};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct SyscallWeight {
    pub name: String,
    pub weight: f64,
    /// Domain size the weight was measured on (1 when none).
    pub domain_points: usize,
    pub conditioned: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Surface {
    pub syscalls: usize,
    pub weighted: f64,
    /// Syscalls with at least one argument condition.
    pub conditioned: usize,
    /// Weight of conditioned syscalls whose conditions the metric could
    /// not credit (no domain): an upper bound of how much the weighted
    /// number overstates this rule set.
    pub uncredited_conditioned: f64,
    pub per_syscall: Vec<SyscallWeight>,
}

/// Cartesian product of the domains of `name`'s arguments.
fn domain_points(name: &str) -> Vec<Vec<(u8, u64)>> {
    let mut points: Vec<Vec<(u8, u64)>> = vec![Vec::new()];
    let mut any = false;
    for s in argspec::specs(name) {
        let Some(d) = s.domain else { continue };
        any = true;
        let vals = d();
        points = points
            .into_iter()
            .flat_map(|p| {
                vals.iter().map(move |&v| {
                    let mut q = p.clone();
                    q.push((s.index, v));
                    q
                })
            })
            .collect();
    }
    if any {
        points
    } else {
        Vec::new()
    }
}

pub fn weight(rule: &SyscallRule) -> SyscallWeight {
    let conditioned = !rule.rules.is_empty();
    if !conditioned {
        return SyscallWeight {
            name: rule.name.clone(),
            weight: 1.0,
            domain_points: 1,
            conditioned,
        };
    }
    let pts = domain_points(&rule.name);
    if pts.is_empty() {
        return SyscallWeight {
            name: rule.name.clone(),
            weight: 1.0,
            domain_points: 1,
            conditioned,
        };
    }
    let ok = pts.iter().filter(|p| rule_allows_point(rule, p)).count();
    SyscallWeight {
        name: rule.name.clone(),
        weight: ok as f64 / pts.len() as f64,
        domain_points: pts.len(),
        conditioned,
    }
}

pub fn measure(s: &Seccomp) -> Surface {
    let per: Vec<SyscallWeight> = s.syscalls.iter().map(weight).collect();
    Surface {
        syscalls: per.len(),
        weighted: per.iter().map(|w| w.weight).sum(),
        conditioned: per.iter().filter(|w| w.conditioned).count(),
        uncredited_conditioned: per
            .iter()
            .filter(|w| w.conditioned && w.domain_points == 1)
            .map(|w| w.weight)
            .sum(),
        per_syscall: per,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Reduction {
    pub baseline: String,
    pub baseline_syscalls: usize,
    pub baseline_weighted: f64,
    pub profile_syscalls: usize,
    pub profile_weighted: f64,
    /// `1 - profile/baseline` on syscall counts.
    pub syscalls: f64,
    /// `1 - profile/baseline` on weighted surfaces.
    pub weighted: f64,
    /// Same as `weighted` but giving the baseline's uncredited conditioned
    /// syscalls weight 0 (the most favourable reading for the baseline).
    pub weighted_conservative: f64,
}

pub fn reduction(name: &str, profile: &Surface, baseline: &Surface) -> Reduction {
    let lb = baseline.weighted - baseline.uncredited_conditioned;
    Reduction {
        baseline: name.to_owned(),
        baseline_syscalls: baseline.syscalls,
        baseline_weighted: baseline.weighted,
        profile_syscalls: profile.syscalls,
        profile_weighted: profile.weighted,
        syscalls: 1.0 - profile.syscalls as f64 / baseline.syscalls as f64,
        weighted: 1.0 - profile.weighted / baseline.weighted,
        weighted_conservative: 1.0 - profile.weighted / lb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argspec::Width;
    use crate::profile::{Cond, Op};

    fn rule(name: &str, rules: Vec<Vec<Cond>>) -> SyscallRule {
        SyscallRule {
            name: name.into(),
            nr: 0,
            rules,
        }
    }
    fn eq(arg: u8, v: u64) -> Cond {
        Cond {
            arg,
            width: Width::Dword,
            op: Op::Eq,
            value: v,
        }
    }

    #[test]
    fn unconditional_weighs_one() {
        assert_eq!(weight(&rule("mmap", vec![])).weight, 1.0);
        assert_eq!(weight(&rule("getpid", vec![])).weight, 1.0);
    }

    #[test]
    fn mmap_single_combination() {
        let w = weight(&rule("mmap", vec![vec![eq(2, 3), eq(3, 0x22)]]));
        assert_eq!(w.domain_points, 2048);
        assert!((w.weight - 1.0 / 2048.0).abs() < 1e-12);
    }

    #[test]
    fn conditions_outside_the_domain_are_not_credited() {
        // write: only an fd condition, no domain.
        let w = weight(&rule("write", vec![vec![eq(0, 1)]]));
        assert_eq!(w.weight, 1.0);
        assert!(w.conditioned);
        // openat: dirfd (no domain) + flags (domain) -> only flags counts.
        let w = weight(&rule(
            "openat",
            vec![vec![eq(0, crate::argspec::AT_FDCWD_DWORD), eq(2, 0x80000)]],
        ));
        assert!((w.weight - 1.0 / 1536.0).abs() < 1e-12);
    }

    #[test]
    fn docker_style_socket_rule() {
        let lt = Cond {
            arg: 0,
            width: Width::Qword,
            op: Op::Lt,
            value: 3,
        };
        let w = weight(&rule("socket", vec![vec![lt]]));
        // domains 0,1,2 of 46, any type
        assert!((w.weight - 3.0 / 46.0).abs() < 1e-12);
    }

    #[test]
    fn reduction_numbers() {
        let p = Seccomp {
            arch: "x86_64".into(),
            syscalls: vec![rule("read", vec![]), rule("write", vec![vec![eq(0, 1)]])],
        };
        let b = Seccomp {
            arch: "x86_64".into(),
            syscalls: (0..10).map(|_| rule("getpid", vec![])).collect(),
        };
        let r = reduction("b", &measure(&p), &measure(&b));
        assert!((r.syscalls - 0.8).abs() < 1e-12);
        assert!((r.weighted - 0.8).abs() < 1e-12);
        assert_eq!(measure(&p).uncredited_conditioned, 1.0);
    }
}
