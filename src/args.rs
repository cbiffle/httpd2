//! Server argument parsing.

use std::net::SocketAddr;

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

    let root = matches.value_of("DIR").unwrap();
    let key_path = matches.value_of("key_path").unwrap();
    let cert_path = matches.value_of("cert_path").unwrap();
    let should_chroot = matches.is_present("chroot");
    let addr = value_t!(matches, "addr", SocketAddr)
        .unwrap_or(SocketAddr::from((DEFAULT_IP, DEFAULT_PORT)));

    let uid = matches
        .value_of("uid")
        .map(|uid| Uid::from_raw(uid.parse::<libc::uid_t>().unwrap()));
    let gid = matches
        .value_of("gid")
        .map(|gid| Gid::from_raw(gid.parse::<libc::gid_t>().unwrap()));

    Ok(Args {
        root: std::path::PathBuf::from(root),
        key_path: std::path::PathBuf::from(key_path),
        cert_path: std::path::PathBuf::from(cert_path),
        should_chroot,
        addr,
        uid,
        gid,
    })
}

