//! `httpd2` command line server binary.
//!
//! This module is responsible for command line argument parsing, environment
//! variable processing, setting up logging, and managing the threadpool for
//! dispatching requests.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper::service::service_fn;

use nix::unistd::Uid;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use clap::Parser;

use httpd2::args::{CommonArgs, Log, HasCommonArgs};
use httpd2::err::ServeError;
use httpd2::sync::SharedSemaphore;
use httpd2::serve;
use httpd2::security;

/// When requested (by the `system_allocator` feature) this forces the allocator
/// to use the one provided by the system, rather than any fancier version Rust
/// provides. This is important for using heap profiling tools, but should not
/// be necessary in production.
#[cfg(feature = "system_allocator")]
#[global_allocator]
static GLOBAL: std::alloc::System = std::alloc::System;

/// Command line interface.
#[derive(Parser)]
#[clap(name = "httpd2")]
pub struct Args {
    #[clap(flatten)]
    common: CommonArgs,

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

    /// Maximum number of worker threads to start, to handle blocking filesystem
    /// operations. Threads are started in response to load, and shut down when
    /// not used. The actual thread count will be above this number, because not
    /// all threads are workers. Larger numbers will improve performance for
    /// large numbers of concurrent requests, at the expense of RAM.
    #[clap(long, default_value = "10")]
    pub max_threads: usize,

    /// Maximum time a client can spend setting up TLS. This process tends to be
    /// very fast, and only happens once per connection, so we can be more
    /// aggressive than the overall connection time limit.
    #[clap(
        long,
        default_value = "10",
        value_parser = httpd2::args::seconds,
        value_name="SECS"
    )]
    pub tls_handshake_time_limit: Duration,
}

impl HasCommonArgs for Args {
    fn common(&self) -> &CommonArgs {
        &self.common
    }
}

/// Main server entry point.
fn main() {
    use futures::future::FutureExt;
    use slog::Drain;

    // Go ahead and parse arguments before dropping privileges, since they
    // control whether we drop privileges, among other things.
    let args = Args::parse();

    let log = match args.common.log {
        Log::Stderr => {
            // Produce boring plain text.
            let decorator = slog_term::PlainDecorator::new(std::io::stderr());
            // Pack everything onto one line, with the largest scope at left.
            let mut fmt = slog_term::FullFormat::new(decorator)
                .use_original_order();
            if args.common.suppress_log_timestamps {
                fmt = fmt.use_custom_timestamp(|_| Ok(()));
            }
            let drain = fmt.build().fuse();
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

    let mut mime_map = httpd2::serve::default_content_type_map();
    for (key, value) in std::env::vars() {
        if let Some(ext) = key.strip_prefix("CT_") {
            slog::info!(log, "extension {ext} => content-type {value}");
            mime_map.insert(
                ext.to_string(),
                value.leak(),
            );
        }
    }
    let mime_map = Arc::new(mime_map);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .max_blocking_threads(args.max_threads)
        .worker_threads(args.common.core_threads.unwrap_or_else(num_cpus::get))
        .enable_all()
        .build()
        .unwrap()
        .block_on(start(args, log, mime_map).map(Result::unwrap))
}

/// Starts up a server.
///
/// This is our async entry point. We haven't dropped privileges yet when we
/// reach this point, because there are a couple of things we need to do first.
async fn start(
    args: Args,
    log: slog::Logger,
    mime_map: Arc<BTreeMap<String, &'static str>>,
) -> Result<(), ServeError> {
    // Sanity check configuration.
    let root = Uid::from_raw(0);
    if Uid::current() == root {
        if !args.common.should_chroot {
            eprintln!("Running as root without chroot?!");
            std::process::exit(1);
        }
        if args.common.uid.is_none() || args.common.uid == Some(root) {
            eprintln!("Provide a lower privileged user ID with -U <uid>");
            std::process::exit(1);
        }
    }

    // Things that need to get done while root:
    // - Binding to privileged ports.
    // - Reading SSL private key.
    // - Chrooting.

    let (key, cert_chain) = load_key_and_cert(&args.key_path, &args.cert_path)?;

    let listener = tokio::net::TcpListener::bind(&args.common.addr).await?;

    // Dropping privileges here...
    security::drop_privs(&log, args.common())?;

    let (tls_acceptor, http) = configure_server_bits(&args, key, cert_chain)?;
    let args = Arc::new(args);

    slog::info!(log, "serving"; "addr" => args.common.addr);

    // Accept loop:
    let connection_counter = AtomicU64::new(0);
    let connection_permits = SharedSemaphore::new(args.common.max_connections);
    loop {
        let permit = connection_permits.acquire().await;
        if let Ok((socket, peer)) = listener.accept().await {
            // New connection received. Add metadata to the logger.
            let log = log.new(slog::o!(
                "cid" => connection_counter.fetch_add(1, Ordering::Relaxed),
            ));
            slog::info!(
                log,
                "connect";
                "peer" => peer,
            );
            // Clone the acceptor handle and HTTP config so they can be moved
            // into the connection future below.
            let tls_acceptor = tls_acceptor.clone();
            let http = http.clone();
            let args = Arc::clone(&args);
            let mime_map = Arc::clone(&mime_map);
            // Spawn the connection future.
            tokio::spawn(async move {
                let _permit = permit;
                // Now that we're in the connection-specific task, do the actual
                // TLS accept and connection setup process.
                match timeout(args.tls_handshake_time_limit, tls_acceptor.accept(socket)).await {
                    Ok(Ok(stream)) => {
                        serve_connection(args, log, mime_map, http, stream).await
                    }
                    Ok(Err(e)) => {
                        // TLS negotiation failed. In my observations so far,
                        // this mostly happens when a client speaks HTTP (or
                        // nonsense) to an HTTPS port.
                        slog::info!(log, "tls-error"; "msg" => e);
                    }
                    Err(_) => {
                        // TLS negotiation timed out.
                        slog::info!(log, "tls-timeout");
                    }
                }
            });
        } else {
            // Taking the next incoming connection from the socket failed. In
            // practice, this means that the server is out of file descriptors.
            slog::warn!(log, "accept-error");
        }
    }
}

/// Connection handler. Returns a future that processes requests on `stream`.
async fn serve_connection(
    args: Arc<Args>,
    log: slog::Logger,
    mime_map: Arc<BTreeMap<String, &'static str>>,
    http: ConnBuilder<TokioExecutor>,
    stream: TlsStream<TcpStream>,
) {
    // Announce the connection and record the parameters we have.
    {
        let session = stream.get_ref().1;
        let alpn =
            std::str::from_utf8(session.alpn_protocol().unwrap_or(b"NONE"))
                .unwrap_or("BOGUS");
        slog::info!(
            log,
            "tls-init";
            "alpn" => alpn,
            "tls" => ?session.protocol_version().unwrap(),
            "cipher" => ?session.negotiated_cipher_suite().unwrap().suite(),
        );
    }

    // Begin handling requests. The request_counter tracks
    // request IDs within this connection.
    let request_counter = AtomicU64::new(0);
    // The self_defense channel allows any request on the connection to warn the
    // others.
    let (self_defense_send, mut self_defense_recv) = tokio::sync::mpsc::channel(1);
    let connection_server = pin!(http.serve_connection(
        hyper_util::rt::tokio::TokioIo::new(stream),
        service_fn(|x| {
            let mime_map = Arc::clone(&mime_map);
            // Select a new request ID and tag our logger with it.
            let log = log.new(slog::o!(
                    "rid" => request_counter
                    .fetch_add(1, Ordering::Relaxed),
            ));
            let self_defense = self_defense_send.clone();
            let args = args.clone();
            async move {
                let result = serve::files(
                    args,
                    log,
                    mime_map,
                    x,
                ).await;
                // Convert a Defense error in _one_ stream into a problem for
                // _all_ streams.
                if let Err(ServeError::Defense(_)) = result {
                    self_defense.try_send(()).ok();
                }
                result
            }
        }),
    ));
    let timeout_sleep = tokio::time::sleep(args.common.connection_time_limit);
    tokio::select! {
        // Normally, we expect to get here when the connection wraps up.
        conn_result = connection_server => {
            match conn_result {
                Ok(_) => slog::info!(log, "closed"),
                Err(e) => {
                    slog::info!(log, "closed"; "cause" => "error");
                    slog::debug!(log, "error"; "msg" => %e);
                }
            }
        }
        // Abort the connection (dropping it) if the self defense signal
        // triggers.
        _ = self_defense_recv.recv() => {
            slog::info!(log, "closed"; "cause" => "self-defense");
            // Note that we're not doing a `conn.graceful_shutdown()` here. We
            // could, though that would also require us to poll the connection
            // to completion. But the shutdown we want here is _not_ graceful,
            // since the client has misbehaved. We really do want to kill off
            // all activity related to all requests on the connection.
        }
        // Also drop the connection if it lives too long.
        _ = timeout_sleep => {
            slog::info!(log, "closed"; "cause" => "timeout");
        }
    }
}

/// Loads TLS credentials from the filesystem using synchronous operations.
///
/// Note that this probably needs to happen before dropping privileges, since
/// the keyfiles are generally not accessible in the serving root.
fn load_key_and_cert(
    key_path: &Path,
    cert_path: &Path,
) -> io::Result<(PrivateKeyDer<'static>, Vec<CertificateDer<'static>>)> {
    let key = rustls_pemfile::read_one(
        &mut io::BufReader::new(std::fs::File::open(key_path)?),
    ).map_err(|_| {
        io::Error::other("can't load private key (bad file?)")
    })?;
    let key = key.ok_or_else(|| {
        io::Error::other("no keys found in private key file")
    })?;
    let key = match key {
        rustls_pemfile::Item::Pkcs8Key(der) => der.into(),
        rustls_pemfile::Item::Sec1Key(der) => der.into(),
        _ => return Err(io::Error::other("unsupported private key type")),
    };
    let cert_chain = rustls_pemfile::certs(&mut io::BufReader::new(
        std::fs::File::open(cert_path)?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| {
        io::Error::other("can't load certificate")
    })?;
    Ok((key, cert_chain))
}

/// Configure TLS and HTTP options for the server.
fn configure_server_bits(
    args: &Args,
    private_key: PrivateKeyDer<'static>,
    cert_chain: Vec<CertificateDer<'static>>,
) -> Result<(TlsAcceptor, ConnBuilder<TokioExecutor>), ServeError> {
    // Configure TLS and HTTP.
    let tls_acceptor = {
        let mut config = ServerConfig::builder()
            // Don't require authentication.
            .with_no_client_auth()
            // We're using only this single identity.
            .with_single_cert(cert_chain, private_key)?;
        // Prefer HTTP/2 but support 1.1.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    };
    // Configure Hyper.
    let mut http = ConnBuilder::new(TokioExecutor::new());
    http.http2()
        .max_concurrent_streams(Some(args.common.max_streams))
        .max_frame_size(16384);
    http.http1()
        .max_buf_size(16384); // down from 400kiB default

    Ok((tls_acceptor, http))
}
