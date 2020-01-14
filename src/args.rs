//! Server argument parsing.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::arg_enum;
use hyper::header::HeaderValue;
use nix::unistd::{Gid, Uid};

const DEFAULT_IP: std::net::Ipv6Addr = std::net::Ipv6Addr::UNSPECIFIED;
const DEFAULT_PORT: u16 = 8000;

pub struct Args {
    pub root: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
    pub should_chroot: bool,
    pub addr: SocketAddr,
    pub uid: Option<Uid>,
    pub gid: Option<Gid>,
    pub hsts: bool,
    pub upgrade: bool,
    pub log: Log,
    pub cache_control: HeaderValue,
    pub max_connections: usize,
    pub max_streams: u32,
    pub connection_time_limit: Duration,
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

pub fn get_args() -> Result<Args, clap::Error> {
    let matches = clap::App::new("httpd2")
        .arg(
            clap::Arg::with_name("chroot")
                .short("c")
                .long("chroot")
                .help(
                    "Specifies that the server should chroot into DIR. You\n\
                     basically always want this, unless you're running the\n\
                     server as an unprivileged user.",
                ),
        )
        .arg(
            clap::Arg::with_name("addr")
                .short("A")
                .long("addr")
                .takes_value(true)
                .value_name("ADDR:PORT")
                .validator(is_sockaddr)
                .help("Address and port to bind."),
        )
        .arg(
            clap::Arg::with_name("uid")
                .short("U")
                .long("uid")
                .takes_value(true)
                .value_name("UID")
                .validator(is_uid)
                .help("User to switch to via setuid before serving."),
        )
        .arg(
            clap::Arg::with_name("gid")
                .short("G")
                .long("gid")
                .takes_value(true)
                .value_name("GID")
                .validator(is_gid)
                .help("Group to switch to via setgid before serving."),
        )
        .arg(
            clap::Arg::with_name("key_path")
                .short("k")
                .long("key-path")
                .takes_value(true)
                .value_name("PATH")
                .default_value("localhost.key")
                .help("Location of TLS private key."),
        )
        .arg(
            clap::Arg::with_name("cert_path")
                .short("r")
                .long("cert-path")
                .takes_value(true)
                .value_name("PATH")
                .default_value("localhost.crt")
                .help("Location of TLS certificate."),
        )
        .arg(
            clap::Arg::with_name("hsts")
                .help("Whether to send the Strict-Transport-Security header")
                .long("hsts"),
        )
        .arg(
            clap::Arg::with_name("upgrade")
                .help("Whether to send the upgrade-insecure-requests directive")
                .long("upgrade"),
        )
        .arg(
            clap::Arg::with_name("log")
                .help("Selects a logging backend")
                .long("log")
                .short("l")
                .possible_values(&Log::variants())
                .default_value("stderr")
                .case_insensitive(true),
        )
        .arg(
            clap::Arg::with_name("max_age")
                .help("How long resource can be cached, in seconds")
                .long("max-age")
                .takes_value(true)
                .value_name("SECS")
                .default_value("3600"),
        )
        .arg(
            clap::Arg::with_name("max_connections")
                .help("Max number of simultaneous connections to accept")
                .long("max-connections")
                .takes_value(true)
                .value_name("COUNT")
                .default_value("100000"),
        )
        .arg(
            clap::Arg::with_name("max_streams")
                .help("Max number of concurrent streams per connection")
                .long("max-streams")
                .takes_value(true)
                .value_name("COUNT")
                .default_value("10"),
        )
        .arg(
            clap::Arg::with_name("connection_time_limit")
                .help("Maximum duration a single connection can stay open.")
                .long("max-conn-time")
                .takes_value(true)
                .value_name("SECS")
                .default_value("181"),
        )
        .arg(
            clap::Arg::with_name("DIR")
                .help("Path to serve")
                .required(true)
                .index(1),
        )
        .get_matches();

    fn is_uid(val: String) -> Result<(), String> {
        val.parse::<libc::uid_t>()
            .map(|_| ())
            .map_err(|_| "can't parse as UID".to_string())
    }

    fn is_gid(val: String) -> Result<(), String> {
        val.parse::<libc::uid_t>()
            .map(|_| ())
            .map_err(|_| "can't parse as GID".to_string())
    }

    fn is_sockaddr(val: String) -> Result<(), String> {
        val.parse::<SocketAddr>()
            .map(|_| ())
            .map_err(|_| "can't parse as addr:port".to_string())
    }

    use clap::value_t;

    Ok(Args {
        root: PathBuf::from(matches.value_of("DIR").unwrap()),
        key_path: PathBuf::from(matches.value_of("key_path").unwrap()),
        cert_path: PathBuf::from(matches.value_of("cert_path").unwrap()),
        should_chroot: matches.is_present("chroot"),
        addr: value_t!(matches, "addr", SocketAddr)
            .unwrap_or(SocketAddr::from((DEFAULT_IP, DEFAULT_PORT))),

        uid: matches
            .value_of("uid")
            .map(|uid| Uid::from_raw(uid.parse::<libc::uid_t>().unwrap())),
        gid: matches
            .value_of("gid")
            .map(|gid| Gid::from_raw(gid.parse::<libc::gid_t>().unwrap())),

        hsts: matches.is_present("hsts"),
        upgrade: matches.is_present("upgrade"),
        log: value_t!(matches, "log", Log).unwrap(),

        cache_control: {
            let max_age = value_t!(matches, "max_age", u64).unwrap();
            HeaderValue::from_str(&format!("max-age={}", max_age)).unwrap()
        },
        max_connections: value_t!(matches, "max_connections", usize).unwrap(),
        max_streams: value_t!(matches, "max_streams", u32).unwrap(),
        connection_time_limit: Duration::from_secs(
            value_t!(matches, "connection_time_limit", u64).unwrap(),
        ),
    })
}
