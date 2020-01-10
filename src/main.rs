mod args;
mod err;
mod percent;
mod picky;
mod serve;
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

use nix::unistd::Uid;

use rustls::{
    Certificate, NoClientAuth, PrivateKey, ProtocolVersion, ServerConfig,
};

use tokio::net::TcpStream;
use tokio::stream::StreamExt;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use self::args::{get_args, Args};
use self::err::ServeError;

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

async fn start(log: slog::Logger) -> Result<(), ServeError> {
    // Go ahead and parse arguments before dropping privileges, since they
    // control whether we drop privileges, among other things.
    let args = match get_args() {
        Ok(args) => args,
        Err(e) => e.exit(),
    };

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

    let (tls_acceptor, http) = configure_server_bits(key, cert_chain)?;

    slog::info!(log, "serving {}", args.addr);

    // Accept loop:
    let mut incoming = listener.incoming();
    let connection_counter = AtomicU64::new(0);
    while let Some(stream) = incoming.next().await {
        if let Ok(socket) = stream {
            // New connection received. Add metadata to the logger.
            let log = log.new(slog::o!(
                "peer" => socket.peer_addr()
                    .map(|sa| sa.to_string())
                    .unwrap_or_else(|_| "UNKNOWN".to_string()),
                "cid" => connection_counter.fetch_add(1, Ordering::Relaxed),
            ));
            // Clone the acceptor handle and HTTP config so they can be moved
            // into the connection future below.
            let tls_acceptor = tls_acceptor.clone();
            let http = http.clone();
            // Spawn the connection future.
            tokio::spawn(async move {
                // Now that we're in the connection-specific task, do the actual
                // TLS accept and connection setup process.
                match tls_acceptor.accept(socket).await {
                    Ok(stream) => serve_connection(log, http, stream).await,
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

    Ok(())
}

/// Configure TLS and HTTP options for the server.
fn configure_server_bits(
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
    // Currently Hyper's default configuration is fine with me.
    let http = Http::new();

    Ok((tls_acceptor, http))
}

async fn serve_connection(
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
                .unwrap_or("BOGUS")
                .to_string();
        slog::debug!(log, "ALPN result: {}", protocol);
    }

    // Begin handling requests. The request_counter tracks
    // request IDs within this connection.
    let request_counter = AtomicU64::new(0);
    let r = http
        .serve_connection(
            stream,
            service_fn(|x| handle_request(&log, &request_counter, x)),
        )
        .await;
    if let Err(e) = r {
        // In practice, there's always at least one of these
        // at the end of the connection, and I haven't
        // figured out a way to distinguish the typical
        // cases from atypical -- so log at a low level.
        slog::debug!(log, "error in connection: {}", e);
    }
    // This is for observing connection duration.
    slog::info!(log, "connection closed");
}

fn handle_request(
    log: &slog::Logger,
    request_counter: &AtomicU64,
    req: Request<Body>,
) -> impl Future<Output = Result<Response<Body>, ServeError>> {
    // Select a request ID and tag our logger with it.
    serve::files(
        log.new(slog::o!(
            "rid" => request_counter
            .fetch_add(1, Ordering::Relaxed),
        )),
        req,
    )
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
