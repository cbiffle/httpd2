//! Server argument parsing.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use hyper::header::HeaderValue;
use nix::unistd::{Gid, Uid};

#[derive(Parser)]
#[clap(name = "httpd2")]
pub struct Args {
    /// Path to the server private key file.
    #[clap(
        short,
        long,
        default_value = "localhost.key",
        value_name = "PATH"
    )]
    pub key_path: PathBuf,
    /// Path to the server certificate file.
    #[clap(
        short = 'r',
        long,
        default_value = "localhost.crt",
        value_name = "PATH"
    )]
    pub cert_path: PathBuf,
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
    /// Send the HTTP Strict-Transport-Security header, instructing clients not
    /// to use unencrypted HTTP to access this site.
    #[clap(long)]
    pub hsts: bool,
    /// Send the upgrade-insecure-requests directive, instructing clients to
    /// convert http URLs to https.
    #[clap(long)]
    pub upgrade: bool,
    /// Selects a logging backend.
    #[clap(long, default_value = "stderr", value_name = "NAME")]
    pub log: Log,
    /// Adds User-Agent header contents, if provided, to request log output.
    #[clap(long)]
    pub log_user_agent: bool,
    /// Adds Referer header contents, if provided, to request log output.
    #[clap(long)]
    pub log_referer: bool,
    /// How long our resources can be cached elsewhere, in seconds.
    #[clap(
        long = "max-age",
        default_value = "3600",
        value_parser = cache_control,
        value_name = "SECS"
    )]
    pub cache_control: HeaderValue,
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
    /// Maximum number of worker threads to start, to handle blocking filesystem
    /// operations. Threads are started in response to load, and shut down when
    /// not used. The actual thread count will be above this number, because not
    /// all threads are workers. Larger numbers will improve performance for
    /// large numbers of concurrent requests, at the expense of RAM.
    #[clap(long, default_value = "10")]
    pub max_threads: usize,

    /// Path of directory to serve (and, if --chroot is provided, the new root
    /// directory).
    #[clap(value_name = "ROOT")]
    pub root: PathBuf,
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

fn cache_control(val: &str) -> Result<HeaderValue, std::num::ParseIntError> {
    val.parse::<u64>().map(|n| {
        HeaderValue::from_str(&format!("cache-control: max-age={}", n)).unwrap()
    })
}
