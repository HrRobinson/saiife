//! Capacity accounting and admission (spec §7.6).

use crate::template::Size;

/// Memory kept back for the host.
pub const RESERVE_MEM_MIB: u64 = 8192;
/// Threads kept back for the host.
pub const RESERVE_THREADS: u32 = 2;
/// Guest vCPUs allowed per usable host thread.
pub const VCPU_OVERCOMMIT: u32 = 2;
/// Free disk required beyond a box's own disk.
pub const DISK_HEADROOM_GIB: u64 = 30;
/// Per-box VMM overhead: the spike measured a 4 GiB guest plus 256 MiB per
/// box, so 5 boxes in 24 GiB.
pub const VMM_OVERHEAD_MIB: u64 = 256;

/// What the host offers, sampled live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostFacts {
    pub mem_total_mib: u64,
    pub mem_avail_mib: u64,
    pub threads: u32,
    pub disk_free_mib: u64,
    pub cpu_pct: Option<u8>,
}

/// What running boxes already hold. `mem_mib` is the sum of [`charge_mib`]
/// over the boxes holding capacity. Disk is not here: it uses the live free
/// figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Committed {
    pub mem_mib: u64,
    pub vcpus: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Memory { need_mib: u64, free_mib: u64 },
    Cpu { need: u32, free: u32 },
    Disk { need_mib: u64, free_mib: u64 },
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::Memory { need_mib, free_mib } => {
                format!("needs {need_mib} MiB of box memory, {free_mib} MiB is free")
            }
            Refusal::Cpu { need, free } => format!("needs {need} vCPUs, {free} is free"),
            Refusal::Disk { need_mib, free_mib } => {
                format!("needs {need_mib} MiB of disk (with headroom), {free_mib} MiB is free")
            }
        }
    }
}

/// One box's memory charge: its guest memory plus the VMM overhead.
pub fn charge_mib(s: &Size) -> u64 {
    s.mem_mib.saturating_add(VMM_OVERHEAD_MIB)
}

fn mem_budget(h: &HostFacts) -> u64 {
    h.mem_total_mib.saturating_sub(RESERVE_MEM_MIB)
}

fn vcpu_budget(h: &HostFacts) -> u32 {
    VCPU_OVERCOMMIT.saturating_mul(h.threads.saturating_sub(RESERVE_THREADS))
}

/// Admit a new box of size `s` given what is already committed.
pub fn admit(h: &HostFacts, c: &Committed, s: &Size) -> Result<(), Refusal> {
    let need = charge_mib(s);
    let free = mem_budget(h).saturating_sub(c.mem_mib);
    if need > free {
        return Err(Refusal::Memory {
            need_mib: need,
            free_mib: free,
        });
    }
    let free = vcpu_budget(h).saturating_sub(c.vcpus);
    if s.vcpus > free {
        return Err(Refusal::Cpu {
            need: s.vcpus,
            free,
        });
    }
    let need = DISK_HEADROOM_GIB
        .saturating_add(s.disk_gib)
        .saturating_mul(1024);
    if h.disk_free_mib < need {
        return Err(Refusal::Disk {
            need_mib: need,
            free_mib: h.disk_free_mib,
        });
    }
    Ok(())
}

/// Would a box of size `s` ever fit on this host, with nothing running?
pub fn fits_ever(h: &HostFacts, s: &Size) -> Result<(), Refusal> {
    admit(h, &Committed::default(), s)
}

/// `(total, free)` slots, counted in default-size boxes.
pub fn slots(h: &HostFacts, c: &Committed) -> (u32, u32) {
    let d = Size::default();
    let per_mem = charge_mib(&d).max(1);
    let per_cpu = u64::from(d.vcpus.max(1));
    let count = |mem: u64, cpu: u32| -> u32 {
        let n = (mem / per_mem).min(u64::from(cpu) / per_cpu);
        u32::try_from(n).unwrap_or(u32::MAX)
    };
    let total = count(mem_budget(h), vcpu_budget(h));
    let free = count(
        mem_budget(h).saturating_sub(c.mem_mib),
        vcpu_budget(h).saturating_sub(c.vcpus),
    );
    (total, free)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> HostFacts {
        HostFacts {
            mem_total_mib: 32768,
            mem_avail_mib: 30000,
            threads: 12,
            disk_free_mib: 500 * 1024,
            cpu_pct: None,
        }
    }

    #[test]
    fn charge_includes_overhead() {
        assert_eq!(VMM_OVERHEAD_MIB, 256);
        assert_eq!(charge_mib(&Size::default()), 4352);
        let big = Size {
            mem_mib: u64::MAX,
            ..Size::default()
        };
        assert_eq!(charge_mib(&big), u64::MAX);
    }

    #[test]
    fn owner_machine_fits_five_default_boxes() {
        let h = owner();
        assert_eq!(slots(&h, &Committed::default()), (5, 5));
        let c = Committed {
            mem_mib: 4 * 4352,
            vcpus: 8,
        };
        assert_eq!(slots(&h, &c), (5, 1));
    }

    fn host_with_free_mem(free: u64) -> HostFacts {
        HostFacts {
            mem_total_mib: free + RESERVE_MEM_MIB,
            ..owner()
        }
    }

    #[test]
    fn exact_fit_is_admitted() {
        let s = Size::default();
        let h = host_with_free_mem(s.mem_mib + 256);
        assert_eq!(admit(&h, &Committed::default(), &s), Ok(()));
    }

    #[test]
    fn one_mib_short_is_memory() {
        let s = Size::default();
        let h = host_with_free_mem(s.mem_mib + 256 - 1);
        assert_eq!(
            admit(&h, &Committed::default(), &s),
            Err(Refusal::Memory {
                need_mib: 4352,
                free_mib: 4351
            })
        );
    }

    #[test]
    fn cpu_limit_is_twenty_on_twelve_threads() {
        let h = owner();
        let s = Size {
            vcpus: 2,
            mem_mib: 128,
            ..Size::default()
        };
        let ok = Committed {
            mem_mib: 0,
            vcpus: 18,
        };
        assert_eq!(admit(&h, &ok, &s), Ok(()));
        let full = Committed {
            mem_mib: 0,
            vcpus: 19,
        };
        assert_eq!(admit(&h, &full, &s), Err(Refusal::Cpu { need: 2, free: 1 }));
    }

    #[test]
    fn disk_needs_headroom() {
        let h = HostFacts {
            disk_free_mib: 59 * 1024,
            ..owner()
        };
        assert!(matches!(
            admit(&h, &Committed::default(), &Size::default()),
            Err(Refusal::Disk { .. })
        ));
        let h = HostFacts {
            disk_free_mib: 60 * 1024,
            ..owner()
        };
        assert_eq!(admit(&h, &Committed::default(), &Size::default()), Ok(()));
    }

    #[test]
    fn never_fits_is_refused() {
        let s = Size {
            mem_mib: 65536,
            ..Size::default()
        };
        assert!(matches!(
            fits_ever(&owner(), &s),
            Err(Refusal::Memory { .. })
        ));
        assert_eq!(fits_ever(&owner(), &Size::default()), Ok(()));
    }

    #[test]
    fn tiny_host_has_no_slots() {
        let h = HostFacts {
            mem_total_mib: 4096,
            threads: 1,
            ..owner()
        };
        assert_eq!(slots(&h, &Committed::default()), (0, 0));
        let c = Committed {
            mem_mib: u64::MAX,
            vcpus: u32::MAX,
        };
        assert_eq!(slots(&owner(), &c), (5, 0));
        assert!(admit(&h, &c, &Size::default()).is_err());
    }

    #[test]
    fn message_text() {
        let m = Refusal::Memory {
            need_mib: 4352,
            free_mib: 2048,
        };
        assert_eq!(
            m.message(),
            "needs 4352 MiB of box memory, 2048 MiB is free"
        );
        let c = Refusal::Cpu { need: 2, free: 1 };
        assert_eq!(c.message(), "needs 2 vCPUs, 1 is free");
        let d = Refusal::Disk {
            need_mib: 61440,
            free_mib: 100,
        };
        assert_eq!(
            d.message(),
            "needs 61440 MiB of disk (with headroom), 100 MiB is free"
        );
    }
}
