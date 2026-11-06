//! Whether a peer's security label can be applied to the child it asks for.
//!
//! So that the child runs as the caller rather than as the daemon, the daemon
//! reads the peer's label from the transport (`SO_PEERSEC` on a Unix socket)
//! and writes it to `/proc/self/attr/exec` between fork and exec. Neither
//! interface names an LSM: the kernel answers both from the first "major" LSM
//! (SELinux, Smack or AppArmor) in its LSM order. Only SELinux treats that
//! label as an exec context:
//!
//! - AppArmor reports a profile (`unconfined`, `name (enforce)`) but its
//!   `attr/exec` accepts only `exec <profile>`, so writing the label back fails
//!   with `EINVAL` and nothing can be spawned.
//! - Smack has no exec attribute, so every write fails.
//!
//! The daemon therefore applies the label only when SELinux is the LSM behind
//! those interfaces. On any other host it runs the child without one, as it
//! would for a transport that reports no label.
//!
//! # Detection
//!
//! The question is "which LSM answers the unqualified interfaces", not "is
//! SELinux loaded". Upstream (checked against Linux 7.4) SELinux, Smack and
//! AppArmor are mutually exclusive (`LSM_FLAG_EXCLUSIVE`), so at most one is
//! active and the two questions have the same answer. Out-of-tree stacking
//! patches, such as Ubuntu's, can activate more than one. `SO_PEERSEC` and
//! `attr/exec` then still go to one LSM, by default the first major LSM in
//! the order. Taking the first major LSM is right in both cases. Checking only
//! whether SELinux is present could read one LSM's label and write it to
//! another, which is the bug this module exists to prevent.
//!
//! The probe tries these sources in order and stops at the first that can be
//! read:
//!
//! 1. `lsm_list_modules(2)` (Linux 6.8+) returns the active LSM IDs in the
//!    order the kernel calls them. It needs no filesystem, so it works in a
//!    minimal zone. It fails with `ENOSYS` on older kernels and may get
//!    `EPERM` from a seccomp filter.
//! 2. `/sys/kernel/security/lsm` (Linux 4.15+) is the same list, by name. It
//!    is only there when securityfs is mounted.
//! 3. `/proc/filesystems` lists `selinuxfs` only when SELinux was enabled at
//!    boot. The kernel registers selinuxfs only in that case, and clears the
//!    flag for any LSM it does not select. libselinux uses the same test. It
//!    does not show the order, so it cannot place SELinux on a stacked kernel.
//!    That case needs a kernel older than 6.8, out-of-tree patches, and no
//!    securityfs.
//!
//! If no source can be read (no `/proc` either), the label is still applied,
//! as before this check existed. That keeps the SELinux guarantee (the child
//! never silently runs under the daemon's context). It also costs nothing
//! elsewhere: without `/proc` the `attr/exec` write would fail anyway.
//!
//! These approaches were rejected:
//!
//! - `/proc/self/attr/selinux/exec` does not exist. Only `smack/` and
//!   `apparmor/` have LSM-specific directories under `attr/`.
//! - Checking whether selinuxfs is *mounted* (`/sys/fs/selinux`) depends on
//!   the mount namespace. Container runtimes often leave it out, so the
//!   context would be silently dropped on an SELinux host.
//! - Writing with `lsm_set_self_attr(LSM_ATTR_EXEC)` addressed to SELinux
//!   would name the target LSM, but `SO_PEERSEC` has no such variant. We would
//!   still not know which LSM produced the label, and it needs Linux 6.8+.
//!
//! The check runs once per process, in the daemon. Nothing here runs after
//! fork, so `pre_exec` stays async-signal-safe.

use std::io;
use std::sync::OnceLock;

/// LSM IDs, from `include/uapi/linux/lsm.h`.
const LSM_ID_SELINUX: u64 = 101;
const LSM_ID_SMACK: u64 = 102;
const LSM_ID_APPARMOR: u64 = 104;

/// `__NR_lsm_list_modules`. The number is shared by every architecture that
/// uses the common syscall table. The `libc` crate does not export it for
/// these targets. Any other architecture falls back to the files.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64",
))]
const SYS_LSM_LIST_MODULES: Option<libc::c_long> = Some(461);
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64",
)))]
const SYS_LSM_LIST_MODULES: Option<libc::c_long> = None;

const SECURITYFS_LSM: &str = "/sys/kernel/security/lsm";
const PROC_FILESYSTEMS: &str = "/proc/filesystems";

/// Which LSM answers `SO_PEERSEC` and `/proc/self/attr/exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LabelOwner {
    /// SELinux: a peer label is an SELinux context and is applied.
    SELinux,
    /// Another LSM, or none. A peer label is not an exec context.
    Other,
    /// No source could be read. Behave as before the check existed.
    Unknown,
}

impl LabelOwner {
    /// Whether a peer's label should be applied to the child.
    pub(crate) fn applies_peer_context(self) -> bool {
        self != LabelOwner::Other
    }
}

/// What the probe reads from the host. Tests substitute their own answers.
pub(crate) trait LsmHost {
    /// `lsm_list_modules(2)`: the active LSM IDs, in kernel order.
    fn list_modules(&self) -> io::Result<Vec<u64>>;
    /// Reads a whole file, such as `/sys/kernel/security/lsm`.
    fn read(&self, path: &str) -> io::Result<String>;
}

/// The running kernel.
pub(crate) struct KernelHost;

impl LsmHost for KernelHost {
    fn list_modules(&self) -> io::Result<Vec<u64>> {
        let Some(nr) = SYS_LSM_LIST_MODULES else {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        };
        const ID_SIZE: usize = size_of::<u64>();
        // Room for every LSM the kernel defines today. If a future kernel has
        // more, it returns E2BIG with the size it needs, and we retry.
        let mut ids = vec![0u64; 16];
        loop {
            let capacity = ids.len() * ID_SIZE;
            let mut size = capacity as u32;
            let rc = unsafe {
                libc::syscall(
                    nr,
                    ids.as_mut_ptr(),
                    &mut size as *mut u32,
                    0 as libc::c_ulong,
                )
            };
            if rc >= 0 {
                ids.truncate(rc as usize);
                return Ok(ids);
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::E2BIG) && size as usize > capacity {
                ids.resize((size as usize).div_ceil(ID_SIZE), 0);
                continue;
            }
            return Err(err);
        }
    }

    fn read(&self, path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }
}

/// Works out which LSM answers the unqualified label interfaces on `host`.
/// See the module docs for the order of sources and why.
pub(crate) fn label_owner(host: &dyn LsmHost) -> LabelOwner {
    if let Ok(ids) = host.list_modules() {
        return first_major(ids.into_iter().map(|id| match id {
            LSM_ID_SELINUX => Major::SELinux,
            LSM_ID_SMACK | LSM_ID_APPARMOR => Major::Other,
            _ => Major::Minor,
        }));
    }

    if let Ok(list) = host.read(SECURITYFS_LSM) {
        return first_major(list.trim().split(',').map(|name| match name {
            "selinux" => Major::SELinux,
            "smack" | "apparmor" => Major::Other,
            _ => Major::Minor,
        }));
    }

    if let Ok(filesystems) = host.read(PROC_FILESYSTEMS) {
        // Each line is "[nodev]\t<name>".
        let selinuxfs = filesystems
            .lines()
            .any(|line| line.split_whitespace().last() == Some("selinuxfs"));
        return if selinuxfs {
            LabelOwner::SELinux
        } else {
            LabelOwner::Other
        };
    }

    LabelOwner::Unknown
}

/// How an active LSM bears on the unqualified label interfaces.
enum Major {
    SELinux,
    /// Smack or AppArmor: a major LSM, but not one whose label is an exec context.
    Other,
    /// Does not answer those interfaces (Yama, Landlock, BPF, ...).
    Minor,
}

/// The owner is the first major LSM in kernel order. With none, nothing
/// answers `SO_PEERSEC`.
fn first_major(order: impl Iterator<Item = Major>) -> LabelOwner {
    for lsm in order {
        match lsm {
            Major::SELinux => return LabelOwner::SELinux,
            Major::Other => return LabelOwner::Other,
            Major::Minor => {}
        }
    }
    LabelOwner::Other
}

/// Whether this host's peer labels should be applied to children. The host
/// is probed on the first call, and the answer kept for the process's life.
pub(crate) fn applies_peer_context() -> bool {
    static OWNER: OnceLock<LabelOwner> = OnceLock::new();
    OWNER
        .get_or_init(|| label_owner(&KernelHost))
        .applies_peer_context()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with canned answers. `None` stands for an unavailable source.
    #[derive(Default)]
    struct FakeHost {
        modules: Option<Vec<u64>>,
        securityfs: Option<&'static str>,
        filesystems: Option<&'static str>,
    }

    impl LsmHost for FakeHost {
        fn list_modules(&self) -> io::Result<Vec<u64>> {
            self.modules
                .clone()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))
        }

        fn read(&self, path: &str) -> io::Result<String> {
            let contents = match path {
                SECURITYFS_LSM => self.securityfs,
                PROC_FILESYSTEMS => self.filesystems,
                _ => None,
            };
            contents
                .map(str::to_owned)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }

    // IDs from include/uapi/linux/lsm.h, besides the majors above.
    const CAPABILITY: u64 = 100;
    const YAMA: u64 = 105;
    const LOCKDOWN: u64 = 108;
    const BPF: u64 = 109;
    const LANDLOCK: u64 = 110;

    /// A typical Ubuntu (AppArmor) /proc/filesystems: no selinuxfs.
    const FILESYSTEMS_WITHOUT_SELINUX: &str =
        "nodev\tsysfs\nnodev\tproc\nnodev\tsecurityfs\n\text4\nnodev\tapparmorfs\n";
    const FILESYSTEMS_WITH_SELINUX: &str =
        "nodev\tsysfs\nnodev\tproc\nnodev\tselinuxfs\n\txfs\nnodev\tsecurityfs\n";

    #[test]
    fn syscall_apparmor_host_does_not_apply() {
        // Ubuntu's order: lockdown,capability,landlock,yama,apparmor,bpf.
        let host = FakeHost {
            modules: Some(vec![
                LOCKDOWN,
                CAPABILITY,
                LANDLOCK,
                YAMA,
                LSM_ID_APPARMOR,
                BPF,
            ]),
            ..Default::default()
        };
        assert_eq!(label_owner(&host), LabelOwner::Other);
        assert!(!label_owner(&host).applies_peer_context());
    }

    #[test]
    fn syscall_selinux_host_applies() {
        // Fedora's order: lockdown,capability,yama,selinux,bpf,landlock.
        let host = FakeHost {
            modules: Some(vec![
                LOCKDOWN,
                CAPABILITY,
                YAMA,
                LSM_ID_SELINUX,
                BPF,
                LANDLOCK,
            ]),
            ..Default::default()
        };
        assert_eq!(label_owner(&host), LabelOwner::SELinux);
        assert!(label_owner(&host).applies_peer_context());
    }

    #[test]
    fn syscall_smack_host_does_not_apply() {
        let host = FakeHost {
            modules: Some(vec![CAPABILITY, LSM_ID_SMACK]),
            ..Default::default()
        };
        assert_eq!(label_owner(&host), LabelOwner::Other);
    }

    #[test]
    fn syscall_no_major_lsm_does_not_apply() {
        let host = FakeHost {
            modules: Some(vec![CAPABILITY, LANDLOCK, YAMA]),
            ..Default::default()
        };
        assert_eq!(label_owner(&host), LabelOwner::Other);
        let empty = FakeHost {
            modules: Some(Vec::new()),
            ..Default::default()
        };
        assert_eq!(label_owner(&empty), LabelOwner::Other);
    }

    #[test]
    fn stacked_lsms_follow_the_first_major() {
        // AppArmor stacked ahead of SELinux answers the interfaces, so the peer
        // label is AppArmor's, even though SELinux is present.
        let apparmor_first = FakeHost {
            modules: Some(vec![CAPABILITY, LSM_ID_APPARMOR, LSM_ID_SELINUX]),
            ..Default::default()
        };
        assert_eq!(label_owner(&apparmor_first), LabelOwner::Other);

        let selinux_first = FakeHost {
            modules: Some(vec![CAPABILITY, LSM_ID_SELINUX, LSM_ID_APPARMOR]),
            ..Default::default()
        };
        assert_eq!(label_owner(&selinux_first), LabelOwner::SELinux);
    }

    #[test]
    fn syscall_outranks_the_files() {
        // When the syscall answers, the files are not consulted, even if they
        // would disagree.
        let host = FakeHost {
            modules: Some(vec![CAPABILITY, LSM_ID_APPARMOR]),
            securityfs: Some("capability,selinux"),
            filesystems: Some(FILESYSTEMS_WITH_SELINUX),
        };
        assert_eq!(label_owner(&host), LabelOwner::Other);
    }

    #[test]
    fn securityfs_used_without_the_syscall() {
        let apparmor = FakeHost {
            securityfs: Some("lockdown,capability,landlock,yama,apparmor,bpf\n"),
            filesystems: Some(FILESYSTEMS_WITH_SELINUX),
            ..Default::default()
        };
        assert_eq!(label_owner(&apparmor), LabelOwner::Other);

        let selinux = FakeHost {
            securityfs: Some("lockdown,capability,yama,selinux,bpf,landlock\n"),
            filesystems: Some(FILESYSTEMS_WITHOUT_SELINUX),
            ..Default::default()
        };
        assert_eq!(label_owner(&selinux), LabelOwner::SELinux);

        let stacked = FakeHost {
            securityfs: Some("capability,apparmor,selinux"),
            ..Default::default()
        };
        assert_eq!(label_owner(&stacked), LabelOwner::Other);
    }

    #[test]
    fn proc_filesystems_is_the_last_resort() {
        let selinux = FakeHost {
            filesystems: Some(FILESYSTEMS_WITH_SELINUX),
            ..Default::default()
        };
        assert_eq!(label_owner(&selinux), LabelOwner::SELinux);

        let other = FakeHost {
            filesystems: Some(FILESYSTEMS_WITHOUT_SELINUX),
            ..Default::default()
        };
        assert_eq!(label_owner(&other), LabelOwner::Other);
    }

    #[test]
    fn proc_filesystems_needs_an_exact_name() {
        let host = FakeHost {
            filesystems: Some("nodev\tnotselinuxfs\nnodev\tselinuxfs2\n"),
            ..Default::default()
        };
        assert_eq!(label_owner(&host), LabelOwner::Other);
    }

    #[test]
    fn nothing_readable_keeps_applying() {
        let host = FakeHost::default();
        assert_eq!(label_owner(&host), LabelOwner::Unknown);
        assert!(label_owner(&host).applies_peer_context());
    }

    /// On the machine running the tests, the syscall and securityfs must
    /// agree. This checks the syscall wrapper against the kernel's own text
    /// list. It is skipped where either is unavailable.
    #[test]
    fn live_syscall_agrees_with_securityfs() {
        let Ok(ids) = KernelHost.list_modules() else {
            eprintln!("lsm_list_modules unavailable; skipping");
            return;
        };
        let Ok(list) = KernelHost.read(SECURITYFS_LSM) else {
            eprintln!("{SECURITYFS_LSM} unreadable; skipping");
            return;
        };

        let names: Vec<&str> = list.trim().split(',').filter(|s| !s.is_empty()).collect();
        assert_eq!(
            ids.len(),
            names.len(),
            "syscall IDs {ids:?} vs securityfs {names:?}"
        );

        let from_syscall = label_owner(&FakeHost {
            modules: Some(ids),
            ..Default::default()
        });
        let from_securityfs = label_owner(&FakeHost {
            securityfs: Some(list.leak()),
            ..Default::default()
        });
        assert_eq!(from_syscall, from_securityfs);
    }
}
