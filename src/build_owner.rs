// billdfaster build-owner discovery.
//
// This module is not part of upstream sccache. It is added by a focused patch
// that lets the .8 compiler client name the local build process a distributed
// compile belongs to, and lets the daemon re-check that name against the
// kernel before it holds a build lease for it.
//
// Discovery walks the caller's ancestry, bounded by [`MAX_ANCESTRY_DEPTH`]
// steps and by the caller's own UID, and selects the *outermost* ancestor
// whose kernel-reported executable name is a recognized build driver. A
// compiler invoked by a build driver therefore names that driver's outermost
// build process (for example `make` above `cargo`), while a compiler invoked
// from an editor or a terminal has no recognized ancestor and claims no
// lease at all.
//
// Identity is always kernel-reported: the process id plus the kernel start
// token (macOS `pbi_start_tvsec`/`pbi_start_tvusec`, Linux the `starttime`
// field of `/proc/<pid>/stat`). The token changes when a pid is reused, so a
// lease can never outlive the exact process incarnation that owns it. Only
// the [`BuildOwner`] triple (pid, start token, uid) leaves this module:
// process names, paths, arguments and environments stay local.

use serde::{Deserialize, Serialize};

/// Hard bound on how many ancestors one discovery may inspect.
pub const MAX_ANCESTRY_DEPTH: usize = 64;

/// Bound on the executable name carried by [`ProcessIdentity`].
const MAX_PROCESS_NAME_BYTES: usize = 64;

/// Executable names that identify a local build driver.
///
/// `gnumake` is what the macOS command line tools report for `/usr/bin/make`;
/// `gmake` is the BSD spelling and `cargo`, `ninja`, `cmake` and `meson` are
/// matched by their own names.
const BUILD_PROCESS_NAMES: &[&str] = &[
    "cargo", "make", "gmake", "gnumake", "ninja", "cmake", "meson",
];

/// The local process a build lease belongs to.
///
/// This is the only owner metadata that ever crosses the daemon boundary, and
/// it never reaches the gateway.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct BuildOwner {
    /// Process id of the owning build process.
    pub pid: u32,
    /// Kernel start token of that exact process incarnation.
    pub start_token: u64,
    /// UID the owning process runs as.
    pub uid: u32,
}

/// One kernel-reported process identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// Process id this identity was read for.
    pub pid: u32,
    /// Parent process id.
    pub ppid: u32,
    /// Real UID the process runs as.
    pub uid: u32,
    /// Kernel start token of this process incarnation.
    pub start_token: u64,
    /// Bounded executable name as reported by the kernel.
    pub name: String,
}

/// The real UID of the current process.
pub fn current_uid() -> u32 {
    platform::current_uid()
}

/// Read the kernel identity of `pid`.
///
/// Returns `None` when the process does not exist, cannot be inspected (a
/// different user, or a kernel thread), or reports an identity this module
/// cannot use — never a partially filled identity.
pub fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return None;
    }
    platform::read_process_identity(pid)
}

/// Whether `name` is a recognized build-driver executable name.
pub fn is_build_process_name(name: &str) -> bool {
    BUILD_PROCESS_NAMES.contains(&name)
}

/// Discover the build owner of the current process, if any.
pub fn discover_build_owner() -> Option<BuildOwner> {
    discover_build_owner_from(std::process::id())
}

/// The build owner a compile request should name, if any.
///
/// Only a build with the distributed client can use a lease, so a build
/// without it never walks the process tree: no syscalls and no allocation are
/// spent on a pure local-cache compile.
#[cfg(feature = "dist-client")]
pub fn discover_build_owner_for_lease() -> Option<BuildOwner> {
    discover_build_owner()
}

/// See [`discover_build_owner_for_lease`] for the distributed case.
#[cfg(not(feature = "dist-client"))]
pub fn discover_build_owner_for_lease() -> Option<BuildOwner> {
    None
}

/// Discover the outermost recognized build ancestor of `start_pid`.
///
/// The walk stops at the first ancestor that is not owned by the current
/// user, cannot be inspected, or is the top of the process tree. Recognized
/// ancestors *below* that boundary are still eligible: the outermost one wins.
pub fn discover_build_owner_from(start_pid: u32) -> Option<BuildOwner> {
    discover_with(
        start_pid,
        &read_process_identity,
        &|identity| is_build_process_name(&identity.name),
        MAX_ANCESTRY_DEPTH,
    )
}

/// Whether `owner` still names exactly one live process of the current user.
///
/// This is the daemon's acceptance and liveness check: a reused pid, a
/// process that exited, a process of another user, and any special pid are
/// all rejected.
pub fn validate_build_owner(owner: &BuildOwner) -> bool {
    if owner.pid <= 1 || owner.pid == std::process::id() {
        return false;
    }
    let Some(identity) = read_process_identity(owner.pid) else {
        return false;
    };
    identity.uid == current_uid()
        && identity.uid == owner.uid
        && identity.start_token == owner.start_token
}

/// Bounded ancestry walk shared by production and tests.
///
/// `read` must return the kernel identity for exactly the requested pid, and
/// `is_build` decides which identities count as build drivers.
///
/// Every link is revalidated before it is followed: the process we just read
/// must still be the same incarnation with the same parent, and that parent
/// must not have started after its child (which would mean the parent pid was
/// reused by an unrelated process). A broken link ends the walk at the
/// ancestors already found below it.
fn discover_with(
    start_pid: u32,
    read: &dyn Fn(u32) -> Option<ProcessIdentity>,
    is_build: &dyn Fn(&ProcessIdentity) -> bool,
    max_depth: usize,
) -> Option<BuildOwner> {
    let own_uid = current_uid();
    let mut owner = None;
    let mut pid = start_pid;
    // The parent identity read while validating the link into `pid`, so each
    // process is read once per step.
    let mut pending: Option<ProcessIdentity> = None;
    for _ in 0..max_depth {
        if pid <= 1 {
            break;
        }
        let identity = match pending.take() {
            Some(identity) => identity,
            None => match read(pid) {
                // The chain is broken (the process exited, belongs to another
                // user, or cannot be inspected): keep the outermost recognized
                // ancestor found below it.
                Some(identity) => identity,
                None => break,
            },
        };
        if identity.uid != own_uid {
            break;
        }
        if is_build(&identity) {
            owner = Some(BuildOwner {
                pid: identity.pid,
                start_token: identity.start_token,
                uid: identity.uid,
            });
        }
        let parent = identity.ppid;
        if parent == 0 || parent == pid || parent == identity.pid {
            break;
        }
        // Revalidate the link before following it. A reused pid anywhere in
        // the chain must never turn an unrelated process into a build owner.
        let Some(recheck) = read(pid) else {
            break;
        };
        if recheck.start_token != identity.start_token || recheck.ppid != parent {
            break;
        }
        let Some(parent_identity) = read(parent) else {
            break;
        };
        if parent_identity.start_token > identity.start_token {
            // A parent cannot start after its child: this pid was reused.
            break;
        }
        pid = parent;
        pending = Some(parent_identity);
    }
    owner
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{MAX_PROCESS_NAME_BYTES, ProcessIdentity};
    use std::ffi::c_void;
    use std::ptr::addr_of_mut;

    /// `struct proc_bsdinfo` from `<libproc.h>`.
    #[repr(C)]
    pub(super) struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    /// `PROC_PIDTBSDINFO` from `<libproc.h>`.
    const PROC_PIDTBSDINFO: libc::c_int = 3;

    /// `SZOMB` from `<sys/proc.h>`: the process has exited and is waiting to
    /// be reaped. Its identity is still readable, but it owns nothing.
    const SZOMB: u32 = 5;

    /// Byte layout of the mirrored C struct, for the layout test.
    pub(super) const LAYOUT: (usize, usize, usize, usize) = (
        std::mem::size_of::<ProcBsdInfo>(),
        std::mem::offset_of!(ProcBsdInfo, pbi_comm),
        std::mem::offset_of!(ProcBsdInfo, pbi_name),
        std::mem::offset_of!(ProcBsdInfo, pbi_start_tvsec),
    );

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    pub(super) fn current_uid() -> u32 {
        // SAFETY: `getuid` has no preconditions.
        unsafe { libc::getuid() }
    }

    pub(super) fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
        let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<ProcBsdInfo>() as libc::c_int;
        // SAFETY: `info` is a live, correctly sized `proc_bsdinfo`.
        let written = unsafe {
            proc_pidinfo(
                pid as libc::c_int,
                PROC_PIDTBSDINFO,
                0,
                addr_of_mut!(info).cast::<c_void>(),
                size,
            )
        };
        if written != size {
            return None;
        }
        if info.pbi_status == SZOMB {
            // An exited, unreaped process must never hold a build lease.
            return None;
        }
        let name = decode_name(&info.pbi_comm).or_else(|| decode_name(&info.pbi_name))?;
        Some(ProcessIdentity {
            pid: info.pbi_pid,
            ppid: info.pbi_ppid,
            // The real UID, matching `getuid()` here and the `Uid:` real field
            // the Linux reader uses.
            uid: info.pbi_ruid,
            start_token: start_token(info.pbi_start_tvsec, info.pbi_start_tvusec)?,
            name,
        })
    }

    /// Combine the kernel start time into one token. `None` for the
    /// impossible zero start time, so an unknown identity is never accepted.
    fn start_token(seconds: u64, microseconds: u64) -> Option<u64> {
        if seconds == 0 && microseconds == 0 {
            return None;
        }
        Some(
            seconds
                .saturating_mul(1_000_000)
                .saturating_add(microseconds % 1_000_000),
        )
    }

    fn decode_name(raw: &[u8]) -> Option<String> {
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        let name = String::from_utf8_lossy(&raw[..end]);
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        Some(name.chars().take(MAX_PROCESS_NAME_BYTES).collect())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{MAX_PROCESS_NAME_BYTES, ProcessIdentity};
    use std::io::Read;

    /// Bound on the `/proc/<pid>/stat` prefix carrying the fields we need.
    const MAX_STAT_BYTES: u64 = 4096;
    /// Bound on the `/proc/<pid>/status` prefix carrying the `Uid:` line.
    const MAX_STATUS_BYTES: u64 = 8192;

    pub(super) fn current_uid() -> u32 {
        // SAFETY: `getuid` has no preconditions.
        unsafe { libc::getuid() }
    }

    pub(super) fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
        let stat = read_bounded(&format!("/proc/{pid}/stat"), MAX_STAT_BYTES)?;
        let stat = String::from_utf8_lossy(&stat);
        // `pid (comm) state ppid ... starttime ...`: the name may itself
        // contain spaces or parentheses, so the fields start after the last
        // closing parenthesis.
        let open = stat.find('(')?;
        let close = stat.rfind(')')?;
        if close <= open + 1 {
            return None;
        }
        let name: String = stat[open + 1..close]
            .chars()
            .take(MAX_PROCESS_NAME_BYTES)
            .collect();
        let mut fields = stat[close + 1..].split_whitespace();
        let state = fields.next()?;
        // An exited process that has not been reaped (`Z`, or `X`/`x` for a
        // dead task) still reports a full identity, but it owns nothing and
        // must never hold a build lease.
        if state.starts_with('Z') || state.starts_with('X') || state.starts_with('x') {
            return None;
        }
        let ppid: u32 = fields.next()?.parse().ok()?;
        // Fields 5..=21 sit between `ppid` and `starttime` (field 22).
        let start_token: u64 = fields.nth(17)?.parse().ok()?;
        let uid = read_uid(pid)?;
        Some(ProcessIdentity {
            pid,
            ppid,
            uid,
            start_token,
            name,
        })
    }

    fn read_uid(pid: u32) -> Option<u32> {
        let status = read_bounded(&format!("/proc/{pid}/status"), MAX_STATUS_BYTES)?;
        let status = String::from_utf8_lossy(&status);
        let line = status.lines().find(|line| line.starts_with("Uid:"))?;
        let mut fields = line.split_whitespace();
        let _key = fields.next()?;
        fields.next()?.parse().ok()
    }

    fn read_bounded(path: &str, limit: u64) -> Option<Vec<u8>> {
        let file = std::fs::File::open(path).ok()?;
        let mut buffer = Vec::new();
        file.take(limit).read_to_end(&mut buffer).ok()?;
        Some(buffer)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::ProcessIdentity;

    pub(super) fn current_uid() -> u32 {
        0
    }

    pub(super) fn read_process_identity(_pid: u32) -> Option<ProcessIdentity> {
        None
    }
}

#[cfg(all(test, unix))]
mod test {
    use super::*;
    use crate::test::utils::{kill_process, owner_of_child, spawn_sleep_process, wait_until};
    use std::collections::{HashMap, VecDeque};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    /// Layout guard: the Rust mirror of `struct proc_bsdinfo` must stay
    /// byte-compatible with `<libproc.h>`.
    #[cfg(target_os = "macos")]
    #[test]
    fn proc_bsdinfo_layout_is_stable() {
        assert_eq!(platform::LAYOUT, (136, 48, 64, 120));
    }

    #[test]
    fn build_process_names_are_matched_exactly() {
        for name in [
            "cargo", "make", "gmake", "gnumake", "ninja", "cmake", "meson",
        ] {
            assert!(is_build_process_name(name), "{name} must be recognized");
        }
        for name in [
            "",
            "make.exe",
            "make2",
            "notmake",
            "MAKE",
            "Make",
            "cargo-1.80",
            "gcc",
            "rustc",
            "cc",
            "sccache",
            "sh",
            "bash",
            "ninja-build",
            "cmake3",
            "gnumake4",
        ] {
            assert!(
                !is_build_process_name(name),
                "{name} must not be recognized"
            );
        }
    }

    fn table(entries: &[(u32, u32, u32, u64, &str)]) -> HashMap<u32, ProcessIdentity> {
        entries
            .iter()
            .map(|(pid, ppid, uid, token, name)| {
                (
                    *pid,
                    ProcessIdentity {
                        pid: *pid,
                        ppid: *ppid,
                        uid: *uid,
                        start_token: *token,
                        name: (*name).to_owned(),
                    },
                )
            })
            .collect()
    }

    fn discover_from_table(
        table: &HashMap<u32, ProcessIdentity>,
        start_pid: u32,
        max_depth: usize,
    ) -> Option<BuildOwner> {
        discover_with(
            start_pid,
            &|pid| table.get(&pid).cloned(),
            &|identity| is_build_process_name(&identity.name),
            max_depth,
        )
    }

    fn identity(pid: u32, ppid: u32, uid: u32, token: u64, name: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            ppid,
            uid,
            start_token: token,
            name: name.to_owned(),
        }
    }

    /// Walk a chain whose kernel answers are scripted one read at a time, so a
    /// link can be replaced underneath the walk.
    fn discover_from_script(
        script: Vec<ProcessIdentity>,
        start_pid: u32,
        max_depth: usize,
    ) -> Option<BuildOwner> {
        let remaining = std::cell::RefCell::new(VecDeque::from(script));
        discover_with(
            start_pid,
            &move |_pid| remaining.borrow_mut().pop_front(),
            &|identity| is_build_process_name(&identity.name),
            max_depth,
        )
    }

    #[test]
    fn outermost_recognized_ancestor_is_selected() {
        let uid = current_uid();
        // rustc -> cargo -> sh -> make -> launcher; a parent always starts
        // before its child, so tokens decrease up the chain.
        let table = table(&[
            (100, 101, uid, 5, "rustc"),
            (101, 102, uid, 4, "cargo"),
            (102, 103, uid, 3, "sh"),
            (103, 104, uid, 2, "make"),
            (104, 0, uid, 1, "launchd"),
        ]);
        assert_eq!(
            discover_from_table(&table, 100, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 103,
                start_token: 2,
                uid
            })
        );
        // Starting inside the build picks the same owner.
        assert_eq!(
            discover_from_table(&table, 101, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 103,
                start_token: 2,
                uid
            })
        );
    }

    #[test]
    fn innermost_match_wins_when_it_is_the_only_one() {
        let uid = current_uid();
        let table = table(&[
            (100, 101, uid, 3, "rustc"),
            (101, 102, uid, 2, "cargo"),
            (102, 0, uid, 1, "sh"),
        ]);
        assert_eq!(
            discover_from_table(&table, 100, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 101,
                start_token: 2,
                uid
            })
        );
    }

    #[test]
    fn a_foreign_uid_boundary_hides_everything_above_it() {
        let uid = current_uid();
        // rustc -> make(uid) -> root sh -> root make
        let table = table(&[
            (100, 101, uid, 5, "rustc"),
            (101, 102, uid, 4, "make"),
            (102, 103, uid.wrapping_add(1), 3, "sh"),
            (103, 104, uid.wrapping_add(1), 2, "make"),
            (104, 0, 0, 1, "launchd"),
        ]);
        assert_eq!(
            discover_from_table(&table, 100, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 101,
                start_token: 4,
                uid
            })
        );
    }

    #[test]
    fn a_broken_chain_keeps_the_ancestors_below_it() {
        let uid = current_uid();
        // 102 cannot be inspected at all.
        let table = table(&[(100, 101, uid, 2, "rustc"), (101, 102, uid, 1, "make")]);
        assert_eq!(
            discover_from_table(&table, 100, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 101,
                start_token: 1,
                uid
            })
        );
    }

    #[test]
    fn an_unrecognized_chain_yields_no_owner() {
        let uid = current_uid();
        let table = table(&[
            (100, 101, uid, 3, "sccache"),
            (101, 102, uid, 2, "sh"),
            (102, 0, uid, 1, "launchd"),
        ]);
        assert_eq!(discover_from_table(&table, 100, MAX_ANCESTRY_DEPTH), None);
        // A missing start process is not an owner either.
        assert_eq!(discover_from_table(&table, 999, MAX_ANCESTRY_DEPTH), None);
    }

    #[test]
    fn the_walk_is_bounded_by_depth() {
        let uid = current_uid();
        let mut entries = Vec::new();
        for pid in 10_000..10_039u32 {
            entries.push((pid, pid + 1, uid, u64::from(20_000 - pid), "sh"));
        }
        // The only recognized ancestor sits 39 steps above the start.
        entries.push((10_039, 10_040, uid, 9_961, "make"));
        entries.push((10_040, 0, uid, 9_960, "launchd"));
        let table = table(&entries);
        assert_eq!(discover_from_table(&table, 10_000, 8), None);
        assert_eq!(
            discover_from_table(&table, 10_000, 64),
            Some(BuildOwner {
                pid: 10_039,
                start_token: 9_961,
                uid
            })
        );
    }

    #[test]
    fn self_parent_loops_and_zero_parents_terminate() {
        let uid = current_uid();
        let table = table(&[(100, 100, uid, 1, "make"), (200, 0, uid, 2, "make")]);
        assert_eq!(
            discover_from_table(&table, 100, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 100,
                start_token: 1,
                uid
            })
        );
        assert_eq!(
            discover_from_table(&table, 200, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 200,
                start_token: 2,
                uid
            })
        );
    }

    #[test]
    fn the_start_process_itself_may_be_the_build_driver() {
        let uid = current_uid();
        let table = table(&[(100, 1, uid, 7, "ninja")]);
        assert_eq!(
            discover_from_table(&table, 100, MAX_ANCESTRY_DEPTH),
            Some(BuildOwner {
                pid: 100,
                start_token: 7,
                uid
            })
        );
    }

    /// A validated chain is followed link by link.
    #[test]
    fn a_validated_chain_selects_the_outermost_build_ancestor() {
        let uid = current_uid();
        let owner = discover_from_script(
            vec![
                identity(100, 101, uid, 10, "rustc"),
                identity(100, 101, uid, 10, "rustc"),
                identity(101, 102, uid, 5, "make"),
                identity(101, 102, uid, 5, "make"),
                identity(102, 0, uid, 1, "launchd"),
            ],
            100,
            MAX_ANCESTRY_DEPTH,
        );
        assert_eq!(
            owner,
            Some(BuildOwner {
                pid: 101,
                start_token: 5,
                uid
            })
        );
    }

    /// The child is replaced between the two reads of one step: the link it
    /// claims must not be followed.
    #[test]
    fn a_reused_child_pid_stops_the_walk() {
        let uid = current_uid();
        let owner = discover_from_script(
            vec![
                identity(100, 101, uid, 10, "rustc"),
                // Same pid, new incarnation: not the process we read.
                identity(100, 101, uid, 11, "make"),
            ],
            100,
            MAX_ANCESTRY_DEPTH,
        );
        assert_eq!(owner, None);
    }

    /// The child was reparented between the reads: the parent it reported is
    /// no longer its parent.
    #[test]
    fn a_reparented_child_stops_the_walk() {
        let uid = current_uid();
        let owner = discover_from_script(
            vec![
                identity(100, 101, uid, 10, "rustc"),
                identity(100, 999, uid, 10, "rustc"),
            ],
            100,
            MAX_ANCESTRY_DEPTH,
        );
        assert_eq!(owner, None);
    }

    /// The parent pid belongs to a later, unrelated process: following it
    /// would hand the build to a stranger.
    #[test]
    fn a_parent_that_started_after_its_child_is_rejected() {
        let uid = current_uid();
        let owner = discover_from_script(
            vec![
                identity(100, 101, uid, 10, "rustc"),
                identity(100, 101, uid, 10, "rustc"),
                // 101 was reused by a process that started later.
                identity(101, 0, uid, 99, "make"),
            ],
            100,
            MAX_ANCESTRY_DEPTH,
        );
        assert_eq!(owner, None);
        // A recognized ancestor below the broken link is still kept.
        let owner = discover_from_script(
            vec![
                identity(100, 101, uid, 10, "make"),
                identity(100, 101, uid, 10, "make"),
                identity(101, 0, uid, 99, "cargo"),
            ],
            100,
            MAX_ANCESTRY_DEPTH,
        );
        assert_eq!(
            owner,
            Some(BuildOwner {
                pid: 100,
                start_token: 10,
                uid
            })
        );
    }

    #[test]
    fn own_identity_is_kernel_reported_and_stable() {
        let pid = std::process::id();
        let identity = read_process_identity(pid).expect("own identity");
        assert_eq!(identity.pid, pid);
        assert_eq!(identity.uid, current_uid());
        assert_ne!(identity.start_token, 0);
        assert!(!identity.name.is_empty());
        assert_eq!(read_process_identity(pid).as_ref(), Some(&identity));
        // The current process is never accepted as a build owner: a lease
        // must never be pinned to the daemon itself.
        assert!(!validate_build_owner(&BuildOwner {
            pid,
            start_token: identity.start_token,
            uid: identity.uid,
        }));
    }

    #[test]
    fn a_live_child_identity_dies_with_the_process() {
        let mut child = spawn_sleep_process();
        let pid = child.id();
        let identity = read_process_identity(pid).expect("child identity");
        assert_eq!(identity.pid, pid);
        assert_eq!(identity.ppid, std::process::id());
        assert_eq!(identity.uid, current_uid());
        let owner = BuildOwner {
            pid,
            start_token: identity.start_token,
            uid: identity.uid,
        };
        assert!(validate_build_owner(&owner));
        kill_process(&mut child);
        assert!(
            wait_until(Duration::from_secs(10), || read_process_identity(pid)
                .is_none()),
            "the exited child still reports a kernel identity"
        );
        assert!(!validate_build_owner(&owner));
    }

    /// Identity is the `(pid, start token)` pair. Start tokens are
    /// per-process kernel values (Linux clock ticks since boot, macOS start
    /// time), not a global sequence, so only the pair identifies an
    /// incarnation.
    #[test]
    fn process_identity_is_the_pid_and_start_token_pair() {
        let mut first = spawn_sleep_process();
        let mut second = spawn_sleep_process();
        let first_identity = read_process_identity(first.id()).expect("first identity");
        let second_identity = read_process_identity(second.id()).expect("second identity");
        assert_ne!(first.id(), second.id());
        assert_ne!(
            (first_identity.pid, first_identity.start_token),
            (second_identity.pid, second_identity.start_token),
            "two live processes must not share one identity"
        );
        // Each process keeps its own pair across reads.
        for child in [&first, &second] {
            let identity = read_process_identity(child.id()).expect("identity");
            let again = read_process_identity(child.id()).expect("identity");
            assert_eq!(
                (identity.pid, identity.start_token),
                (again.pid, again.start_token)
            );
        }
        // A reused pid is a different incarnation of the same pid, which is
        // exactly what the pair distinguishes.
        assert!(!validate_build_owner(&BuildOwner {
            pid: first_identity.pid,
            start_token: first_identity.start_token.wrapping_add(1),
            uid: first_identity.uid,
        }));
        assert!(validate_build_owner(&BuildOwner {
            pid: first_identity.pid,
            start_token: first_identity.start_token,
            uid: first_identity.uid,
        }));
        kill_process(&mut first);
        kill_process(&mut second);
    }

    /// A process that exited but has not been reaped still answers kernel
    /// identity queries; it must not validate as a live build owner.
    #[test]
    fn an_unreaped_exited_process_is_not_a_live_owner() {
        let mut child = spawn_sleep_process();
        let owner = owner_of_child(&child);
        assert!(validate_build_owner(&owner));
        // Signal without reaping: the child stays a zombie until `wait`.
        let _ = child.kill();
        assert!(
            wait_until(Duration::from_secs(10), || !validate_build_owner(&owner)),
            "an exited, unreaped process still validated as a live owner"
        );
        assert!(
            read_process_identity(owner.pid).is_none(),
            "a zombie must not report a process identity"
        );
        // Reap for cleanup.
        kill_process(&mut child);
    }

    #[test]
    fn validate_rejects_stale_tokens_foreign_uids_and_special_pids() {
        let mut child = spawn_sleep_process();
        let identity = read_process_identity(child.id()).expect("child identity");
        // A reused pid: same pid, different incarnation.
        assert!(!validate_build_owner(&BuildOwner {
            pid: identity.pid,
            start_token: identity.start_token.wrapping_add(1),
            uid: identity.uid,
        }));
        // A different user's process can never be a lease owner.
        assert!(!validate_build_owner(&BuildOwner {
            pid: identity.pid,
            start_token: identity.start_token,
            uid: identity.uid.wrapping_add(1),
        }));
        for pid in [0, 1] {
            assert!(!validate_build_owner(&BuildOwner {
                pid,
                start_token: identity.start_token,
                uid: identity.uid,
            }));
        }
        // A pid that is not running at all.
        let dead = BuildOwner {
            pid: u32::MAX - 1,
            start_token: identity.start_token,
            uid: identity.uid,
        };
        assert!(!validate_build_owner(&dead));
        kill_process(&mut child);
    }

    /// Ancestors of `pid` (including itself) as far as the kernel lets us
    /// look, for assertions about real process trees.
    fn ancestors_of(pid: u32) -> Vec<u32> {
        let mut ancestors = Vec::new();
        let mut current = pid;
        for _ in 0..MAX_ANCESTRY_DEPTH {
            let Some(identity) = read_process_identity(current) else {
                break;
            };
            ancestors.push(identity.pid);
            if identity.ppid <= 1 || identity.ppid == identity.pid {
                break;
            }
            current = identity.ppid;
        }
        ancestors
    }

    /// A real three-process chain (`sh` -> `sh` -> `sleep`) whose pids the
    /// test learns from the chain itself.
    struct RealChain {
        outer: Child,
        outer_pid: u32,
        inner_pid: u32,
        leaf_pid: u32,
        /// Held so the chain's pid files outlive `start`.
        _directory: tempfile::TempDir,
    }

    impl RealChain {
        fn start() -> RealChain {
            let directory = tempfile::tempdir().expect("tempdir");
            let inner_pid_file = directory.path().join("inner.pid");
            let leaf_pid_file = directory.path().join("leaf.pid");
            // `$$` is the inner shell, `$!` the backgrounded leaf. The
            // trailing `true` keeps the outer shell from exec'ing the inner
            // one, so both levels stay observable.
            let inner = format!(
                "echo $$ > {}; sleep 60 & echo $! > {}; wait",
                inner_pid_file.display(),
                leaf_pid_file.display()
            );
            let outer = Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("/bin/sh -c '{inner}' ; true"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn the chain");
            let outer_pid = outer.id();
            let read_pid = |path: &std::path::Path| -> u32 {
                let mut value = None;
                assert!(
                    wait_until(Duration::from_secs(10), || {
                        value = std::fs::read_to_string(path)
                            .ok()
                            .and_then(|text| text.trim().parse().ok());
                        value.is_some()
                    }),
                    "the chain did not report {}",
                    path.display()
                );
                value.expect("pid was read")
            };
            let inner_pid = read_pid(&inner_pid_file);
            let leaf_pid = read_pid(&leaf_pid_file);
            RealChain {
                outer,
                outer_pid,
                inner_pid,
                leaf_pid,
                _directory: directory,
            }
        }

        fn stop(mut self) {
            let _ = self.outer.kill();
            let _ = self.outer.wait();
            for pid in [self.inner_pid, self.leaf_pid] {
                // SAFETY: `kill` on a pid we spawned; the result is ignored.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
            }
        }
    }

    #[test]
    fn real_process_chain_selects_the_outermost_matching_ancestor() {
        let chain = RealChain::start();
        assert_ne!(chain.outer_pid, chain.inner_pid);
        assert_ne!(chain.inner_pid, chain.leaf_pid);

        let outer_or_inner = |identity: &ProcessIdentity| {
            identity.pid == chain.outer_pid || identity.pid == chain.inner_pid
        };
        let owner = discover_with(
            chain.leaf_pid,
            &read_process_identity,
            &outer_or_inner,
            MAX_ANCESTRY_DEPTH,
        )
        .expect("the chain must have a recognized ancestor");
        assert_eq!(owner.pid, chain.outer_pid);
        let identity = read_process_identity(chain.outer_pid).expect("outer identity");
        assert_eq!(owner.start_token, identity.start_token);
        assert_eq!(owner.uid, identity.uid);
        assert!(validate_build_owner(&owner));

        // Only the inner shell is recognized: the walk still crosses the
        // real parent link between the two shells.
        let owner = discover_with(
            chain.leaf_pid,
            &read_process_identity,
            &|identity| identity.pid == chain.inner_pid,
            MAX_ANCESTRY_DEPTH,
        )
        .expect("the inner shell must be found");
        assert_eq!(owner.pid, chain.inner_pid);

        // Starting at the leaf's parent changes nothing.
        let owner = discover_with(
            chain.inner_pid,
            &read_process_identity,
            &|identity| identity.pid == chain.outer_pid,
            MAX_ANCESTRY_DEPTH,
        )
        .expect("the outer shell must be found");
        assert_eq!(owner.pid, chain.outer_pid);

        chain.stop();
    }

    #[test]
    fn real_build_driver_is_found_with_the_default_predicate() {
        let directory = tempfile::tempdir().expect("tempdir");
        let recipe_pid_file = directory.path().join("recipe.pid");
        let makefile = directory.path().join("Makefile");
        std::fs::write(
            &makefile,
            format!(
                "all:\n\t@echo $$$$ > {}; sleep 60\n",
                recipe_pid_file.display()
            ),
        )
        .expect("makefile");
        let Ok(mut make) = Command::new("make")
            .arg("-f")
            .arg(&makefile)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            eprintln!("skipping: no make on this host");
            return;
        };
        let mut recipe_pid = None;
        assert!(
            wait_until(Duration::from_secs(10), || {
                recipe_pid = std::fs::read_to_string(&recipe_pid_file)
                    .ok()
                    .and_then(|text| text.trim().parse().ok());
                recipe_pid.is_some()
            }),
            "make never started the recipe"
        );
        let recipe_pid = recipe_pid.expect("recipe pid");

        let owner = discover_build_owner_from(recipe_pid)
            .expect("a recipe under make must have a recognized build ancestor");
        let ancestors = ancestors_of(make.id());
        assert!(
            ancestors.contains(&owner.pid),
            "owner {} is not an ancestor of the spawned make ({ancestors:?})",
            owner.pid
        );
        let identity = read_process_identity(owner.pid).expect("owner identity");
        assert!(is_build_process_name(&identity.name));
        assert_eq!(owner.start_token, identity.start_token);
        assert_eq!(owner.uid, identity.uid);
        assert!(validate_build_owner(&owner));

        let _ = make.kill();
        let _ = make.wait();
        // SAFETY: best-effort cleanup of the recipe shell.
        unsafe {
            libc::kill(recipe_pid as libc::pid_t, libc::SIGKILL);
        }
    }
}
