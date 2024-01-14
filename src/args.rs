//! Server argument parsing.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use nix::unistd::{Gid, Uid};

#[derive(Parser)]
pub struct CommonArgs {
    /// Specifies that the server should chroot into ROOT. You basically always
    /// want ths, unless you're running the server as an unprivileged user.
    #[clap(short = 'c', long = "chroot")]
    pub should_chroot: bool,
    /// Address and port to bind.
    #[clap(
        short = 'A',
        long,
        default_value = "[::]:8000",
        value_name = "ADDR:PORT"
    )]
    pub addr: SocketAddr,
    /// User to switch to via setuid before serving. Required if the server is
    /// started as root.
    #[clap(
        short = 'U',
        long,
        value_parser = parse_uid,
        value_name = "UID"
    )]
    pub uid: Option<Uid>,
    /// Group to switch to via setgid before serving.
    #[clap(
        short = 'G',
        long,
        value_parser = parse_gid,
        value_name = "GID"
    )]
    pub gid: Option<Gid>,
    /// Selects a logging backend.
    #[clap(long, default_value = "stderr", value_name = "NAME")]
    pub log: Log,
    /// Adds User-Agent header contents, if provided, to request log output.
    #[clap(long)]
    pub log_user_agent: bool,
    /// Adds Referer header contents, if provided, to request log output.
    #[clap(long)]
    pub log_referer: bool,
    /// Don't include timestamps in the log. This may be useful if output is
    /// timestamped by an external entity such as journald or syslog.
    #[clap(long)]
    pub suppress_log_timestamps: bool,
    /// How long our resources can be cached elsewhere, in seconds.
    #[clap(
        long,
        default_value = "3600",
        value_name = "SECS"
    )]
    pub default_max_age: usize,
    /// Send the HTTP Strict-Transport-Security header, instructing clients not
    /// to use unencrypted HTTP to access this site.
    #[clap(long)]
    pub hsts: bool,
    /// Send the upgrade-insecure-requests directive, instructing clients to
    /// convert http URLs to https.
    #[clap(long)]
    pub upgrade: bool,
    /// Maximum number of simultaneous connections to allow.
    #[clap(long, default_value = "100000", value_name = "COUNT")]
    pub max_connections: usize,
    /// Maximum number of concurrent streams (HTTP/2) or pipelined requests
    /// (HTTP/1.1) to allow per connection.
    #[clap(long, default_value = "10", value_name = "COUNT")]
    pub max_streams: u32,
    /// Maximum duration of a connection in seconds. This timer elapses whether
    /// or not the connection is active.
    #[clap(
        long,
        default_value = "181",
        value_parser = seconds,
        value_name="SECS"
    )]
    pub connection_time_limit: Duration,
    /// Core worker threads to maintain. These will be started immediately, and
    /// kept alive while the server is idle, to respond to requests quickly. If
    /// not provided, this will equal the number of CPUs.
    #[clap(long)]
    pub core_threads: Option<usize>,

    /// Path of directory to serve (and, if --chroot is provided, the new root
    /// directory).
    #[clap(value_name = "ROOT")]
    pub root: PathBuf,
}

pub trait HasCommonArgs {
    fn common(&self) -> &CommonArgs;
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Log {
    Stderr,
    #[cfg(feature = "journald")]
    Journald,
}

fn parse_uid(val: &str) -> Result<Uid, std::num::ParseIntError> {
    val.parse::<libc::uid_t>().map(Uid::from_raw)
}

fn parse_gid(val: &str) -> Result<Gid, std::num::ParseIntError> {
    val.parse::<libc::gid_t>().map(Gid::from_raw)
}

fn seconds(val: &str) -> Result<Duration, std::num::ParseFloatError> {
    val.parse::<f64>().map(Duration::from_secs_f64)
}
