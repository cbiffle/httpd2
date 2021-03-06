mod args;
mod err;
mod log;
mod percent;
mod picky;
mod serve;
mod sync;
mod traversal;

use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};

use nix::unistd::{Gid, Uid};

use rustls::{
    Certificate, NoClientAuth, PrivateKey, ProtocolVersion, ServerConfig,
};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use structopt::StructOpt;

use self::args::{Args, Log};
use self::err::ServeError;
use self::sync::SharedSemaphore;

#[cfg(feature = "system_allocator")]
#[global_allocator]
static GLOBAL: std::alloc::System = std::alloc::System;

/// Main server entry point.
fn main() {
    use futures::future::FutureExt;
    use slog::Drain;

    // Go ahead and parse arguments before dropping privileges, since they
    // control whether we drop privileges, among other things.
    let args = Args::from_args();

    let log = match args.log {
        Log::Stderr => {
            // Produce boring plain text.
            let decorator = slog_term::PlainDecorator::new(std::io::stderr());
            // Pack everything onto one line, with the largest scope at left.
            let drain = slog_term::FullFormat::new(decorator)
                .use_original_order()
                .build()
                .fuse();
            // Don't block the server until a bunch of records have built up.
            let drain =
                slog_async::Async::new(drain).chan_size(1024).build().fuse();
            slog::Logger::root(drain, slog::o!())
        }
        #[cfg(feature = "journald")]
        Log::Journald => {
            let drain = slog_journald::JournaldDrain.ignore_res();
            // Don't block the server until a bunch of records have built up.
            let drain =
                slog_async::Async::new(drain).chan_size(1024).build().fuse();
            slog::Logger::root(drain, slog::o!())
        }
    };

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .max_blocking_threads(args.max_threads)
        .worker_threads(args.core_threads.unwrap_or_else(num_cpus::get))
        .enable_all()
        .build()
        .unwrap()
        .block_on(start(args, log).map(Result::unwrap))
}

/// Starts up a server.
async fn start(args: Args, log: slog::Logger) -> Result<(), ServeError> {
    // Sanity check configuration.
    let root = Uid::from_raw(0);
    if Uid::current() == root {
        if !args.should_chroot {
            eprintln!("Running as root without chroot?!");
            std::process::exit(1);
        }
        if args.uid.is_none() || args.uid == Some(root) {
            eprintln!("Provide a lower privileged user ID with -U <uid>");
            std::process::exit(1);
        }
    }

    // Things that need to get done while root:
    // - Binding to privileged ports.
    // - Reading SSL private key.
    // - Chrooting.

    let (key, cert_chain) = load_key_and_cert(&args.key_path, &args.cert_path)?;

    let listener = tokio::net::TcpListener::bind(&args.addr).await?;

    // Dropping privileges here...
    drop_privs(&log, &args)?;

    let (tls_acceptor, http) = configure_server_bits(&args, key, cert_chain)?;
    let args = Arc::new(args);

    slog::info!(log, "serving"; "addr" => args.addr);

    // Accept loop:
    let connection_counter = AtomicU64::new(0);
    let connection_permits = SharedSemaphore::new(args.max_connections);
    loop {
        let permit = connection_permits.acquire().await;
        if let Ok((socket, peer)) = listener.accept().await {
            // New connection received. Add metadata to the logger.
            let log = log.new(slog::o!(
                "cid" => connection_counter.fetch_add(1, Ordering::Relaxed),
            ));
            // Clone the acceptor handle and HTTP config so they can be moved
            // into the connection future below.
            let tls_acceptor = tls_acceptor.clone();
            let http = http.clone();
            let args = args.clone();
            // Spawn the connection future.
            tokio::spawn(async move {
                let _permit = permit;
                // Now that we're in the connection-specific task, do the actual
                // TLS accept and connection setup process.
                match tls_acceptor.accept(socket).await {
                    Ok(stream) => {
                        serve_connection(args, log, http, stream, peer).await
                    }
                    Err(e) => {
                        // TLS negotiation failed. In my observations so far,
                        // this mostly happens when a client speaks HTTP (or
                        // nonsense) to an HTTPS port.
                        slog::warn!(log, "error in TLS handshake: {}", e);
                    }
                }
            });
        } else {
            // Taking the next incoming connection from the socket failed. In
            // practice, this means that the server is out of file descriptors.
            slog::warn!(log, "error accepting");
        }
    }
}

/// Connection handler. Returns a future that processes requests on `stream`.
async fn serve_connection(
    args: Arc<Args>,
    log: slog::Logger,
    http: Http,
    stream: TlsStream<TcpStream>,
    peer: std::net::SocketAddr,
) {
    // Announce the connection and record the parameters we have.
    {
        use rustls::Session;
        let session = stream.get_ref().1;
        let alpn =
            std::str::from_utf8(session.get_alpn_protocol().unwrap_or(b"NONE"))
                .unwrap_or("BOGUS");
        slog::info!(
            log,
            "connect";
            "peer" => peer,
            "alpn" => alpn,
            "tls" => ?session.get_protocol_version().unwrap(),
            "cipher" => ?session.get_negotiated_ciphersuite().unwrap().suite,
        );
    }

    // Begin handling requests. The request_counter tracks
    // request IDs within this connection.
    let request_counter = AtomicU64::new(0);
    let connection_server = http.serve_connection(
        stream,
        service_fn(|x| handle_request(args.clone(), &log, &request_counter, x)),
    );
    match timeout(args.connection_time_limit, connection_server).await {
        Err(_) => {
            slog::info!(log, "closed"; "cause" => "timeout");
        }
        Ok(conn_result) => match conn_result {
            Ok(_) => slog::info!(log, "closed"),
            Err(e) => {
                slog::info!(log, "closed"; "cause" => "error");
                slog::debug!(log, "error"; "msg" => %e);
            }
        },
    }
}

/// Request handler. This mostly defers to the `serve` module right now.
fn handle_request(
    args: Arc<Args>,
    log: &slog::Logger,
    request_counter: &AtomicU64,
    req: Request<Body>,
) -> impl Future<Output = Result<Response<Body>, ServeError>> {
    // Select a request ID and tag our logger with it.
    serve::files(
        args,
        log.new(slog::o!(
            "rid" => request_counter
            .fetch_add(1, Ordering::Relaxed),
        )),
        req,
    )
}

/// Loads TLS credentials from the filesystem using synchronous operations.
fn load_key_and_cert(
    key_path: &Path,
    cert_path: &Path,
) -> io::Result<(PrivateKey, Vec<Certificate>)> {
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

/// Drops the set of privileges requested in `args`. At minimum, this changes
/// the CWD; at most, it chroots and changes to an unprivileged user.
fn drop_privs(log: &slog::Logger, args: &Args) -> Result<(), ServeError> {
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

/// Configure TLS and HTTP options for the server.
fn configure_server_bits(
    args: &Args,
    private_key: PrivateKey,
    cert_chain: Vec<Certificate>,
) -> Result<(TlsAcceptor, Http), ServeError> {
    // Configure TLS and HTTP.
    let tls_acceptor = {
        // Don't require authentication.
        let mut config = ServerConfig::new(NoClientAuth::new());
        // We're using only this single identity.
        config.set_single_cert(cert_chain, private_key)?;
        // Prefer TLS1.3 but support 1.2.
        config.versions =
            vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
        // Prefer HTTP/2 but support 1.1.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    };
    // Configure Hyper.
    let mut http = Http::new();
    http.http2_max_concurrent_streams(Some(args.max_streams));
    http.max_buf_size(16384); // down from 400kiB default

    Ok((tls_acceptor, http))
}
