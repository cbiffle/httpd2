use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use bytes::Bytes;
use http_body_util::Empty;
use httpd2::log::OptionKV;
use hyper::body::Incoming;
use hyper::http::HeaderValue;
use hyper::http::uri::{Scheme, Authority};
use hyper::server::conn::http1::Builder as ConnBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response, Method, Uri, StatusCode};

use nix::unistd::{Gid, Uid};

use tokio::net::TcpStream;
use tokio::time::timeout;

use clap::Parser;

use httpd2::args::{CommonArgs, Log, HasCommonArgs};
use httpd2::err::ServeError;
use httpd2::sync::SharedSemaphore;

#[cfg(feature = "system_allocator")]
#[global_allocator]
static GLOBAL: std::alloc::System = std::alloc::System;

#[derive(Parser)]
#[clap(name = "http301d")]
pub struct Args {
    #[clap(flatten)]
    common: CommonArgs,

    /// Target for redirects.
    #[structopt(value_name = "HOST")]
    pub default_host: String,
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

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(args.common.core_threads.unwrap_or_else(num_cpus::get))
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
    // - Chrooting.

    let listener = tokio::net::TcpListener::bind(&args.common.addr).await?;

    // Dropping privileges here...
    drop_privs(&log, args.common())?;

    let http = configure_server_bits(&args)?;
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
            let http = http.clone();
            let args = args.clone();
            // Spawn the connection future.
            tokio::spawn(async move {
                let _permit = permit;
                // Now that we're in the connection-specific task, do the actual
                // connection setup process.
                serve_connection(args, log, http, socket).await
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
    http: ConnBuilder,
    stream: TcpStream,
) {
    // Begin handling requests. The request_counter tracks
    // request IDs within this connection.
    let request_counter = AtomicU64::new(0);
    let connection_server = http.serve_connection(
        hyper_util::rt::tokio::TokioIo::new(stream),
        service_fn(|x| handle_request(args.clone(), &log, &request_counter, x)),
    );
    match timeout(args.common.connection_time_limit, connection_server).await {
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

async fn handle_request(
    args: Arc<Args>,
    log: &slog::Logger,
    request_counter: &AtomicU64,
    req: Request<Incoming>,
) -> Result<Response<Empty<Bytes>>, ServeError> {
    let log = log.new(slog::o!(
        "rid" => request_counter.fetch_add(1, Ordering::Relaxed),
    ));
    // We log all requests, whether or not they will be served.
    let method = req.method();
    let uri = req.uri();
    let ua = req.headers().get(hyper::header::USER_AGENT).map(|v| {
        slog::o!("user-agent" => format!("{v:?}"))
    });
    let rfr = if args.common().log_referer {
        req.headers().get(hyper::header::REFERER).map(|v| {
            // Again using HeaderValue's Debug impl.
            slog::o!("referrer" => format!("{v:?}"))
        })
    } else {
        None
    };
    slog::info!(
        log,
        "{}", method;
        "uri" => %uri,
        "version" => ?req.version(),
        OptionKV::from(ua),
        OptionKV::from(rfr),
    );
    match method {
        &Method::GET | &Method::HEAD => {
            let mut https_uri_parts = uri.clone().into_parts();
            https_uri_parts.scheme = Some(Scheme::HTTPS);
            if https_uri_parts.authority.is_none() {
                https_uri_parts.authority = Some(Authority::from_str(&args.default_host).unwrap());
            }
            let https_uri = Uri::try_from(https_uri_parts).unwrap();
            let mut response = Response::new(Empty::new());
            *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
            response.headers_mut().insert(
                hyper::header::LOCATION,
                HeaderValue::from_str(&https_uri.to_string()).unwrap(),
            );

            Ok(response)
        }
        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Empty::new())
                .unwrap())
        }
    }
}

/// Drops the set of privileges requested in `args`. At minimum, this changes
/// the CWD; at most, it chroots and changes to an unprivileged user.
fn drop_privs(log: &slog::Logger, args: &CommonArgs) -> Result<(), ServeError> {
    std::env::set_current_dir(&args.root)?;

    if args.should_chroot {
        nix::unistd::chroot(&args.root)?;
    }
    if let Some(gid) = args.gid {
        nix::unistd::setgid(gid)?;

        #[cfg(target_os = "macos")]
        unsafe {
            if libc::setgroups(1, &gid.as_raw()) != 0 {
                eprintln!("Error with libc::setgroups");
                std::process::exit(1);
            }
        }

        #[cfg(not(target_os = "macos"))]
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

/// Configure HTTP options for the server.
fn configure_server_bits(
    _args: &Args,
) -> Result<ConnBuilder, ServeError> {
    // Configure HTTP.
    let mut http = ConnBuilder::new();
    http.max_buf_size(16384);
    Ok(http)
}
