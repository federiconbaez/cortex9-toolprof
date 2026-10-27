//! Userspace evaluation of seccomp rules, with the same semantics as the
//! compiled filter: a syscall is allowed if it is listed and any of its
//! rules has all its conditions true (or it has no rules).
//!
//! Used by `toolprof diff` (which trace events would a profile block) and
//! by the surface metric.

use crate::profile::{Cond, Op, Profile, SyscallRule};

pub fn cond_holds(c: &Cond, arg: u64) -> bool {
    let a = c.width.mask(arg);
    let v = c.width.mask(c.value);
    match c.op {
        Op::Eq => a == v,
        Op::Ne => a != v,
        Op::Lt => a < v,
        Op::Le => a <= v,
        Op::Gt => a > v,
        Op::Ge => a >= v,
        Op::MaskedEq { mask } => a & c.width.mask(mask) == v,
    }
}

/// Does `rule` allow a call with these arguments?
pub fn rule_allows(rule: &SyscallRule, args: &[u64; 6]) -> bool {
    rule.rules.is_empty()
        || rule
            .rules
            .iter()
            .any(|conj| conj.iter().all(|c| cond_holds(c, args[c.arg as usize])))
}

/// Does `profile` allow syscall `nr` with `args`?
pub fn allows(profile: &Profile, nr: u32, args: &[u64; 6]) -> bool {
    profile.syscall(nr).is_some_and(|r| rule_allows(r, args))
}

/// Like [`rule_allows`] for a partial assignment: conditions on arguments
/// not in `point` are taken as satisfiable.
pub fn rule_allows_point(rule: &SyscallRule, point: &[(u8, u64)]) -> bool {
    rule.rules.is_empty()
        || rule.rules.iter().any(|conj| {
            conj.iter()
                .all(|c| match point.iter().find(|(i, _)| *i == c.arg) {
                    Some((_, v)) => cond_holds(c, *v),
                    None => true,
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argspec::Width;

    fn c(arg: u8, op: Op, value: u64) -> Cond {
        Cond {
            arg,
            width: Width::Dword,
            op,
            value,
        }
    }

    #[test]
    fn operators() {
        assert!(cond_holds(&c(0, Op::Eq, 3), 3));
        assert!(cond_holds(&c(0, Op::Eq, 3), 0xdead_0000_0000_0003));
        assert!(cond_holds(&c(0, Op::Lt, 3), 2));
        assert!(!cond_holds(&c(0, Op::Lt, 3), 3));
        assert!(cond_holds(&c(0, Op::MaskedEq { mask: 0xf0 }, 0x10), 0x1f));
        assert!(!cond_holds(&c(0, Op::Ne, 1), 1));
    }

    #[test]
    fn disjunction_of_conjunctions() {
        let r = SyscallRule {
            name: "mmap".into(),
            nr: 9,
            rules: vec![
                vec![c(2, Op::Eq, 3), c(3, Op::Eq, 0x22)],
                vec![c(2, Op::Eq, 1), c(3, Op::Eq, 0x802)],
            ],
        };
        assert!(rule_allows(&r, &[0, 0, 3, 0x22, 0, 0]));
        assert!(rule_allows(&r, &[0, 0, 1, 0x802, 0, 0]));
        assert!(!rule_allows(&r, &[0, 0, 7, 0x22, 0, 0]));
        assert!(!rule_allows(&r, &[0, 0, 3, 0x802, 0, 0]));
        assert!(rule_allows_point(&r, &[(2, 3)]));
        assert!(!rule_allows_point(&r, &[(2, 7)]));
    }
}
