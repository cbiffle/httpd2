use crate::args::CommonArgs;
use crate::err::ServeError;

use nix::unistd::{Uid, Gid};

/// Drops the set of privileges requested in `args`. At minimum, this changes
/// the CWD; at most, it chroots and changes to an unprivileged user.
pub fn drop_privs(log: &slog::Logger, args: &CommonArgs) -> Result<(), ServeError> {
    std::env::set_current_dir(&args.root)?;

    if args.should_chroot {
        nix::unistd::chroot(&args.root)?;
    }
    if let Some(gid) = args.gid {
        nix::unistd::setgid(gid)?;

        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                // Darwin-based platforms have done something goofy with
                // setgroups, and nix have decided not to include it for some
                // reason, instead citing some Mac-specific daemon you're
                // supposed to talk to.
                //
                // But our use case of "set a single group as a root user"
                // appears to be well supported, so, it seems like we can get
                // basic Darwin support by bypassing nix.
                //
                // Safety: this call is unsafe because it is equivalent to
                // dereferencing a raw pointer. libc provides no explicit safety
                // docs (Boooooo) but from the POSIX docs, I can infer that the
                // contract we need to uphold here is: the pointer we pass is
                // valid, the count is correct, and the pointed-to data is
                // proper size_ts.
                if unsafe { libc::setgroups(1, &gid.as_raw()) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            } else {
                // Normal POSIX platforms:
                nix::unistd::setgroups(&[gid])?;
            }
        }
    }
    if let Some(uid) = args.uid {
        nix::unistd::setuid(uid)?;
    }
    slog::info!(
        log,
        "privs";
        "cwd" => %args.root.display(),
        "chroot" => args.should_chroot,
        "setuid" => args.uid.map(Uid::as_raw),
        "setgid" => args.gid.map(Gid::as_raw),
    );

    Ok(())
}


