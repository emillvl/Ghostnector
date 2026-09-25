//! The privilege-dropping launch helper.
//!
//! This is the only component that turns "the control plane asked for a session" into "the user's
//! shell is running inside the namespace". It is deliberately a **separate, tiny process**: the
//! delicate sequence below (enter a namespace, build a mount namespace, drop every capability and
//! identity, exec) must not run inside the long-lived helper, where a mistake would affect every
//! group, and a forked child of a threaded process must not do surprising things.
//!
//! What it accepts is an id and the root-owned state directory, both from `appd`'s own
//! configuration — never from a client:
//!
//! ```text
//! ghostnector-appd-launch --id <N> --uid <UID> --state-dir <PATH>
//! ```
//!
//! It derives everything else itself: the namespace name (`ghapp<N>`), the resolver configuration
//! (`<state-dir>/<N>/resolv.conf`), and the shell, home and gid from the passwd database for the
//! uid. The sequence, in order, is the security property:
//!
//! 1. enter the namespace (`setns`, the `CAP_SYS_ADMIN` step);
//! 2. unshare the mount namespace, make `/` private, and bind the group's `resolv.conf` over
//!    `/etc/resolv.conf`, so name resolution inside the shell goes to the chokepoint;
//! 3. `setgroups([])`, `setgid`, `setuid` to the invoking user — the identity switch the kernel
//!    requires `CAP_SETGID`/`CAP_SETUID` for, and which also clears the granted capability sets;
//! 4. clear every capability set that can grant a capability, and refuse to continue if any
//!    ambient capability survives;
//! 5. `exec` the passwd-defined shell with a fixed environment.
//!
//! Steps 3 and 4 are the drop; step 5 is the exec. The M8.3 gate proves the result: the shell sees
//! every granting capability set empty, the namespace's routes, and the chokepoint resolver file.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use caps::{CapSet, CapsHashSet};
use ghostnector_spec::app::{valid_interface_name, APP_NETNS_PREFIX, MAX_APP_GROUPS};
use nix::mount::{mount, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::unistd::{Gid, Uid, User};

/// Where `ip netns` keeps its named namespaces (iproute2's fixed choice).
const NETNS_DIR: &str = "/run/netns";

/// The environment the shell starts with. Fixed: the helper does not import the caller's
/// environment, and it never passes anything a client supplied.
const SHELL_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug)]
struct Options {
    id: u32,
    uid: u32,
    state_dir: PathBuf,
}

fn usage() -> String {
    "ghostnector-appd-launch --id <N> --uid <UID> --state-dir <PATH>".to_string()
}

fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut id: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut values = arguments.into_iter().peekable();
    while let Some(option) = values.next() {
        let mut value = || {
            values
                .next()
                .ok_or_else(|| format!("'{option}' needs a value"))
        };
        match option.as_str() {
            "--id" => {
                let raw = value()?;
                let parsed: u32 = raw
                    .parse()
                    .map_err(|_| format!("'{raw}' is not a group id"))?;
                if parsed == 0 || parsed as usize > MAX_APP_GROUPS {
                    return Err(format!("group id {parsed} is outside 1..={MAX_APP_GROUPS}"));
                }
                id = Some(parsed);
            }
            "--uid" => {
                let raw = value()?;
                let parsed: u32 = raw.parse().map_err(|_| format!("'{raw}' is not a uid"))?;
                if parsed == 0 {
                    return Err("refusing to launch a session as root".to_string());
                }
                uid = Some(parsed);
            }
            "--state-dir" => {
                let raw = value()?;
                if !raw.starts_with('/') {
                    return Err("the state directory must be absolute".to_string());
                }
                state_dir = Some(PathBuf::from(raw));
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    Ok(Options {
        id: id.ok_or("--id is required")?,
        uid: uid.ok_or("--uid is required")?,
        state_dir: state_dir.ok_or("--state-dir is required")?,
    })
}

/// A file that will be executed on behalf of a dropped-identity process must be root-owned and not
/// writable by anyone else, or "the passwd shell" means nothing.
fn check_root_file(path: &Path, what: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{what} '{}' is not absolute", path.display()));
    }
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("{what} '{}': {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{what} '{}' is not a regular file", path.display()));
    }
    if metadata.uid() != 0 {
        return Err(format!("{what} '{}' is not root-owned", path.display()));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{what} '{}' is writable by group or others",
            path.display()
        ));
    }
    Ok(())
}

fn drop_every_capability() -> Result<(), String> {
    // Ambient first: it is what survives an exec, so clearing it is the one that matters most.
    caps::clear(None, CapSet::Ambient).map_err(|error| format!("ambient: {error}"))?;
    // The bounding set is deliberately not touched: dropping from it needs CAP_SETPCAP, which this
    // component does not hold, and a bounding entry cannot grant a capability by itself. What a
    // running shell can hold is the four sets below.
    for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        caps::clear(None, set).map_err(|error| format!("{set:?}: {error}"))?;
    }
    let left: CapsHashSet =
        caps::read(None, CapSet::Ambient).map_err(|error| format!("reading ambient: {error}"))?;
    if !left.is_empty() {
        return Err("ambient capabilities survived the drop".to_string());
    }
    Ok(())
}

fn main() -> ExitCode {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("ghostnector-appd-launch: {error}\n{}", usage());
            return ExitCode::from(2);
        }
    };

    if let Err(error) = run(&options) {
        eprintln!("ghostnector-appd-launch: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(options: &Options) -> Result<(), String> {
    let user = User::from_uid(Uid::from_raw(options.uid))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no user with uid {}", options.uid))?;
    let home = user.dir.clone();
    let shell = user.shell.clone();
    let user_name = user.name.clone();
    let gid = user.gid;

    let netns_name = format!("{APP_NETNS_PREFIX}{}", options.id);
    if !valid_interface_name(&netns_name) {
        return Err("the derived namespace name is not usable".to_string());
    }
    let netns_path = PathBuf::from(NETNS_DIR).join(&netns_name);
    let resolv = options
        .state_dir
        .join(options.id.to_string())
        .join("resolv.conf");
    check_root_file(&shell, "the shell")?;
    check_root_file(&resolv, "the resolver configuration")?;
    if !resolv.starts_with(&options.state_dir) {
        return Err("the resolver configuration is outside the state directory".to_string());
    }

    // 0. Standard input/output are already the accepted session connection.
    let netns = std::fs::File::open(&netns_path)
        .map_err(|error| format!("namespace '{}': {error}", netns_path.display()))?;

    // 1. The namespace. This is the CAP_SYS_ADMIN step.
    setns(&netns, CloneFlags::CLONE_NEWNET)
        .map_err(|error| format!("cannot enter '{netns_name}': {error}"))?;

    // 2. A private mount namespace with the group's resolver configuration over /etc/resolv.conf.
    unshare(CloneFlags::CLONE_NEWNS).map_err(|error| format!("cannot unshare mounts: {error}"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|error| format!("cannot make / private: {error}"))?;
    mount(
        Some(resolv.as_path()),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|error| format!("cannot bind {}: {error}", resolv.display()))?;

    // 3. Every identity goes first: supplementary groups, then the group, then the user. The kernel
    //    requires CAP_SETGID/CAP_SETUID for these, and clears the granted capability sets on the
    //    switch to a nonzero uid.
    nix::unistd::setgroups(&[]).map_err(|error| format!("cannot clear groups: {error}"))?;
    nix::unistd::setgid(Gid::from_raw(gid.as_raw()))
        .map_err(|error| format!("cannot set gid {gid}: {error}"))?;
    nix::unistd::setuid(Uid::from_raw(options.uid))
        .map_err(|error| format!("cannot set uid {}: {error}", options.uid))?;
    if Uid::effective().as_raw() != options.uid {
        return Err("the uid change did not take effect".to_string());
    }

    // 4. Every granting capability goes, explicitly, after the identity switch. Dropping is always
    //    permitted; the check refuses to continue if anything survived.
    drop_every_capability()?;

    // 5. The shell, from the passwd database, with a fixed environment. Standard output already
    //    goes to the session connection.
    let environment = [
        ("HOME", home.display().to_string()),
        ("USER", user_name.clone()),
        ("LOGNAME", user_name),
        ("SHELL", shell.display().to_string()),
        ("PATH", SHELL_PATH.to_string()),
    ];

    let status = Command::new(&shell)
        .env_clear()
        .envs(environment)
        .status()
        .map_err(|error| format!("cannot run '{}': {error}", shell.display()))?;

    // The session's exit status is the shell's exit status.
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(list: &[&str]) -> Vec<String> {
        list.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn the_arguments_are_an_id_a_uid_and_a_root_owned_directory() {
        let options = parse(arguments(&[
            "--id",
            "7",
            "--uid",
            "1000",
            "--state-dir",
            "/run/x",
        ]))
        .expect("valid arguments");
        assert_eq!(options.id, 7);
        assert_eq!(options.uid, 1000);
        assert_eq!(options.state_dir, PathBuf::from("/run/x"));
    }

    #[test]
    fn the_arguments_cannot_name_a_namespace_a_shell_or_a_command() {
        for bad in [
            vec![
                "--netns",
                "ghapp1",
                "--uid",
                "1000",
                "--state-dir",
                "/run/x",
            ],
            vec![
                "--shell",
                "/bin/sh",
                "--uid",
                "1000",
                "--state-dir",
                "/run/x",
            ],
            vec!["--command", "id", "--uid", "1000", "--state-dir", "/run/x"],
            vec!["--id", "7", "--uid", "1000", "--state-dir", "relative"],
            vec!["--id", "7", "--uid", "0", "--state-dir", "/run/x"],
            vec!["--id", "0", "--uid", "1000", "--state-dir", "/run/x"],
            vec!["--id", "33", "--uid", "1000", "--state-dir", "/run/x"],
        ] {
            assert!(parse(arguments(&bad)).is_err(), "{bad:?}");
        }
        assert!(parse(arguments(&["--id", "7", "--uid", "1000"])).is_err());
    }

    #[test]
    fn the_executed_file_must_be_root_owned_and_not_writable() {
        assert!(check_root_file(Path::new("/bin/sh"), "the shell").is_ok());
        assert!(check_root_file(Path::new("sh"), "the shell").is_err());
        assert!(check_root_file(Path::new("/definitely/not/here"), "the shell").is_err());
        assert!(check_root_file(Path::new("/usr"), "the shell").is_err());
    }
}
