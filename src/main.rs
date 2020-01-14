mod args;
mod err;
mod percent;
mod picky;
mod serve;
mod traversal;
mod sync;

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

use nix::unistd::Uid;

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

/// Main server entry point.
#[tokio::main]
async fn main() {
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

    start(args, log).await.expect("server failed")
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

    let mut listener = tokio::net::TcpListener::bind(&args.addr).await?;

    // Dropping privileges here...
    drop_privs(&log, &args)?;

    let (tls_acceptor, http) = configure_server_bits(&args, key, cert_chain)?;
    let args = Arc::new(args);

    slog::info!(log, "serving {}", args.addr);

    // Accept loop:
    let connection_counter = AtomicU64::new(0);
    let connection_permits = SharedSemaphore::new(args.max_connections);
    loop {
        let permit = connection_permits.acquire().await;
        if let Ok((socket, peer)) = listener.accept().await {
            // New connection received. Add metadata to the logger.
            let log = log.new(slog::o!(
                "peer" => peer.to_string(),
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
                        serve_connection(args, log, http, stream).await
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
) {
    // Record the actual protocol we wound up using after
    // ALPN.
    {
        use rustls::Session;

        let session = stream.get_ref().1;
        let protocol =
            std::str::from_utf8(session.get_alpn_protocol().unwrap_or(b"NONE"))
                .unwrap_or("BOGUS");
        slog::info!(log, "conn {}", protocol);
    }

    // Begin handling requests. The request_counter tracks
    // request IDs within this connection.
    let request_counter = AtomicU64::new(0);
    let connection_server = http
        .serve_connection(
            stream,
            service_fn(|x| {
                handle_request(args.clone(), &log, &request_counter, x)
            }),
        );
    match timeout(args.connection_time_limit, connection_server).await {
        Err(_) => {
            slog::info!(log, "connection closed (timeout)");
        }
        Ok(conn_result) => {
            if let Err(e) = conn_result {
                // In practice, there's always at least one of these
                // at the end of the connection, and I haven't
                // figured out a way to distinguish the typical
                // cases from atypical -- so log at a low level.
                slog::debug!(log, "error in connection: {}", e);
            }
            // This is for observing connection duration.
            slog::info!(log, "connection closed");
        }
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
    slog::info!(log, "cwd: {:?}", args.root);

    if args.should_chroot {
        nix::unistd::chroot(&args.root)?;
        slog::info!(log, "in chroot");
    }
    if let Some(gid) = args.gid {
        nix::unistd::setgid(gid)?;
        nix::unistd::setgroups(&[gid])?;
        slog::info!(log, "gid: {}", gid);
    }
    if let Some(uid) = args.uid {
        nix::unistd::setuid(uid)?;
        slog::info!(log, "uid: {}", uid);
    }
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
