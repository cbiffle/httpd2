mod err;
mod percent;
mod picky;
mod traversal;
mod serve;

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use hyper::service::service_fn;

use rustls::{NoClientAuth, ProtocolVersion, ServerConfig};

use tokio::stream::StreamExt;
use tokio_rustls::TlsAcceptor;

use self::err::ServeError;

const DEFAULT_IP: std::net::Ipv6Addr = std::net::Ipv6Addr::UNSPECIFIED;
const DEFAULT_PORT: u16 = 8000;

struct Args {
    root: std::path::PathBuf,
    key_path: std::path::PathBuf,
    cert_path: std::path::PathBuf,
    should_chroot: bool,
    addr: SocketAddr,
    uid: Option<nix::unistd::Uid>,
    gid: Option<nix::unistd::Gid>,
}

fn get_args() -> Result<Args, clap::Error> {
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
    let should_chroot = value_t!(matches, "chroot", bool).unwrap_or(false);
    let addr = value_t!(matches, "addr", SocketAddr)
        .unwrap_or(SocketAddr::from((DEFAULT_IP, DEFAULT_PORT)));
    println!("{:?}", addr);

    let uid = matches.value_of("uid").map(|uid| {
        nix::unistd::Uid::from_raw(uid.parse::<libc::uid_t>().unwrap())
    });
    let gid = matches.value_of("gid").map(|gid| {
        nix::unistd::Gid::from_raw(gid.parse::<libc::gid_t>().unwrap())
    });

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

fn load_key_and_cert(
    key_path: &Path,
    cert_path: &Path,
) -> io::Result<(rustls::PrivateKey, Vec<rustls::Certificate>)> {
    let key = rustls::internal::pemfile::pkcs8_private_keys(
        &mut io::BufReader::new(std::fs::File::open(key_path)?),
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            "can't load private key (bad file?)",
        )
    })?
    .pop()
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "no keys found in private key file",
        )
    })?;
    let cert_chain = rustls::internal::pemfile::certs(&mut io::BufReader::new(
        std::fs::File::open(cert_path)?,
    ))
    .map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "can't load certificate")
    })?;
    Ok((key, cert_chain))
}

fn drop_privs(args: &Args) -> Result<(), ServeError> {
    std::env::set_current_dir(&args.root)?;
    if args.should_chroot {
        nix::unistd::chroot(&args.root)?;
    }
    if let Some(gid) = args.gid {
        nix::unistd::setgid(gid)?;
        nix::unistd::setgroups(&[gid])?;
    }
    if let Some(uid) = args.uid {
        nix::unistd::setuid(uid)?;
    }
    Ok(())
}

async fn start(log: slog::Logger) -> Result<(), ServeError> {
    // Go ahead and parse arguments before dropping privileges, since they
    // control whether we drop privileges, among other things.
    let args = match get_args() {
        Ok(args) => args,
        Err(e) => e.exit(),
    };

    // Things that need to get done while root:
    // - Binding to privileged ports.
    // - Reading SSL private key.
    // - Chrooting.

    let (key, cert_chain) = load_key_and_cert(&args.key_path, &args.cert_path)?;

    let mut listener = tokio::net::TcpListener::bind(&args.addr).await?;

    // Dropping privileges here...
    drop_privs(&args)?;

    let tls_acceptor = {
        let mut config = ServerConfig::new(NoClientAuth::new());
        config.set_single_cert(cert_chain, key)?;
        config.versions =
            vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    };
    let http = hyper::server::conn::Http::new();

    let mut incoming = listener.incoming();
    let connection_counter = AtomicU64::new(0);
    while let Some(stream) = incoming.next().await {
        if let Ok(socket) = stream {
            let log = log.new(slog::o!(
                "peer" => socket.peer_addr().map(|sa| sa.to_string()).unwrap_or_else(|_| "UNKNOWN".to_string()),
                "cid" => connection_counter.fetch_add(1, Ordering::Relaxed),
            ));
            let tls_acceptor = tls_acceptor.clone();
            let http = http.clone();
            tokio::spawn(async move {
                match tls_acceptor.accept(socket).await {
                    Ok(stream) => {
                        use rustls::Session;

                        let session = stream.get_ref().1;
                        slog::debug!(
                            log,
                            "ALPN result: {:?}",
                            std::str::from_utf8(
                                session.get_alpn_protocol().unwrap_or(b"NONE")
                            )
                            .unwrap_or("BOGUS")
                            .to_string()
                        );
                        let request_counter = AtomicU64::new(0);
                        let r = http
                        .serve_connection(stream, service_fn(|x| {
                            let log = log.new(slog::o!(
                                "rid" => request_counter.fetch_add(1, Ordering::Relaxed),
                            ));
                            serve::files(log, x)
                        }))
                        .await;
                        if let Err(e) = r {
                            slog::debug!(log, "error in connection: {}", e);
                        }
                        slog::info!(log, "connection closed");
                    }
                    Err(e) => {
                        slog::warn!(log, "error in TLS handshake: {}", e);
                    }
                }
            });
        } else {
            slog::warn!(log, "error accepting");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    use slog::Drain;

    let decorator = slog_term::PlainDecorator::new(std::io::stderr());
    let drain = slog_term::FullFormat::new(decorator)
        .use_original_order()
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain).chan_size(1024).build().fuse();
    let log = slog::Logger::root(drain, slog::o!());

    start(log).await.expect("server failed")
}
