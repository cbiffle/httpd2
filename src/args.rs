//! Server argument parsing.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::arg_enum;
use hyper::header::HeaderValue;
use nix::unistd::{Gid, Uid};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "httpd2")]
pub struct Args {
    /// Path to the server private key file.
    #[structopt(
        short,
        long,
        default_value = "localhost.key",
        value_name = "PATH"
    )]
    pub key_path: PathBuf,
    /// Path to the server certificate file.
    #[structopt(
        short = "r",
        long,
        default_value = "localhost.crt",
        value_name = "PATH"
    )]
    pub cert_path: PathBuf,
    /// Specifies that the server should chroot into ROOT. You basically always
    /// want ths, unless you're running the server as an unprivileged user.
    #[structopt(short = "c", long = "chroot")]
    pub should_chroot: bool,
    /// Address and port to bind.
    #[structopt(
        short = "A",
        long,
        default_value = "[::]:8000",
        value_name = "ADDR:PORT"
    )]
    pub addr: SocketAddr,
    /// User to switch to via setuid before serving. Required if the server is
    /// started as root.
    #[structopt(
        short = "U",
        long,
        parse(try_from_str = parse_uid),
        value_name = "UID"
    )]
    pub uid: Option<Uid>,
    /// Group to switch to via setgid before serving.
    #[structopt(
        short = "G",
        long,
        parse(try_from_str=parse_gid),
        value_name = "GID"
    )]
    pub gid: Option<Gid>,
    /// Send the HTTP Strict-Transport-Security header, instructing clients not
    /// to use unencrypted HTTP to access this site.
    #[structopt(long)]
    pub hsts: bool,
    /// Send the upgrade-insecure-requests directive, instructing clients to
    /// convert http URLs to https.
    #[structopt(long)]
    pub upgrade: bool,
    /// Selects a logging backend.
    #[structopt(long, default_value = "stderr", value_name = "NAME")]
    pub log: Log,
    /// How long our resources can be cached elsewhere, in seconds.
    #[structopt(
        long = "max-age",
        default_value = "3600",
        parse(try_from_str = cache_control),
        value_name = "SECS"
    )]
    pub cache_control: HeaderValue,
    /// Maximum number of simultaneous connections to allow.
    #[structopt(long, default_value = "100000", value_name = "COUNT")]
    pub max_connections: usize,
    /// Maximum number of concurrent streams (HTTP/2) or pipelined requests
    /// (HTTP/1.1) to allow per connection.
    #[structopt(long, default_value = "10", value_name = "COUNT")]
    pub max_streams: u32,
    /// Maximum duration of a connection in seconds. This timer elapses whether
    /// or not the connection is active.
    #[structopt(
        long,
        default_value = "181",
        parse(try_from_str = seconds),
        value_name="SECS"
    )]
    pub connection_time_limit: Duration,
    /// Core worker threads to maintain. These will be started immediately, and
    /// kept alive while the server is idle, to respond to requests quickly. If
    /// not provided, this will equal the number of CPUs.
    #[structopt(long)]
    pub core_threads: Option<usize>,
    /// Maximum number of worker threads to start. Threads are started in
    /// response to load, and shut down when not used. The actual thread count
    /// will be above this number, because not all threads are workers.
    #[structopt(long, default_value = "128")]
    pub max_threads: usize,

    /// Path of directory to serve (and, if --chroot is provided, the new root
    /// directory).
    #[structopt(value_name = "ROOT")]
    pub root: PathBuf,
}

// TODO: looks like Clap's arg_enum doesn't allow variant attributes.
#[cfg(not(feature = "journald"))]
arg_enum! {
    #[derive(Copy, Clone, Debug)]
    pub enum Log {
        Stderr,
    }
}

#[cfg(feature = "journald")]
arg_enum! {
    #[derive(Copy, Clone, Debug)]
    pub enum Log {
        Stderr,
        Journald,
    }
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

fn cache_control(val: &str) -> Result<HeaderValue, std::num::ParseIntError> {
    val.parse::<u64>().map(|n| {
        HeaderValue::from_str(&format!("cache-control: max-age={}", n)).unwrap()
    })
}
