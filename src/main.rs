use std::net::SocketAddr;
use std::io;
use std::sync::Arc;
use std::path::Path;
use std::time::SystemTime;
use std::ffi::OsStr;

use hyper::{Body, Method, Request, Response, StatusCode};
use hyper::service::{service_fn};

use rustls::{NoClientAuth, ServerConfig, ProtocolVersion};

use tokio::stream::StreamExt;
use tokio::fs;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{self, Decoder};

#[derive(Debug)]
enum ServeError {
    Hyper(hyper::Error),
    Io(io::Error),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ServeError::Hyper(e) => write!(f, "{}", e),
            ServeError::Io(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServeError::Hyper(e) => Some(e),
            ServeError::Io(e) => Some(e),
        }
    }
}

impl From<hyper::Error> for ServeError {
    fn from(x: hyper::Error) -> Self {
        ServeError::Hyper(x)
    }
}

impl From<io::Error> for ServeError {
    fn from(x: io::Error) -> Self {
        ServeError::Io(x)
    }
}

enum FileOrDir {
    File { file: fs::File, content_type: &'static str, len: u64, modified: SystemTime, },
    Dir,
}

async fn picky_open(path: &Path) -> Result<FileOrDir, io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let file = fs::File::open(path).await?;
    let meta = file.metadata().await?;
    let mode = meta.permissions().mode();

    if mode & 0o444 != 0o444 || mode & 0o101 == 0o001 {
        Err(io::Error::new(io::ErrorKind::NotFound, "perms"))
    } else if meta.is_file() { 
        Ok(FileOrDir::File {
            file,
            content_type: map_content_type(path),
            len: meta.len(),
            modified: meta.modified().unwrap(),
        })
    } else if meta.is_dir() {
        Ok(FileOrDir::Dir)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "type"))
    }
}

async fn picky_open_with_redirect(path: &mut String) -> Result<FileOrDir, io::Error> {
    match picky_open(Path::new(path)).await? {
        FileOrDir::Dir => {
            path.push_str("/index.html");
            picky_open(Path::new(path)).await
        },
        r => Ok(r),
    }
}

async fn picky_open_with_redirect_and_gzip(path: &mut String) -> Result<(FileOrDir, Option<&'static str>), io::Error> {
    match picky_open_with_redirect(path).await? {
        FileOrDir::Dir => Ok((FileOrDir::Dir, None)),
        FileOrDir::File { file, len, content_type, modified } => {
            path.push_str(".gz");
            match picky_open(Path::new(path)).await {
                Ok(FileOrDir::File { file, len, modified: cmod, .. }) if cmod >= modified => Ok((FileOrDir::File { file, len, content_type, modified }, Some("gzip"))),
                _ => Ok((FileOrDir::File {file, len, content_type, modified}, None)),
            }
        },
    }
}

fn map_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(OsStr::to_str) {
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "text/javascript",
        Some("woff2") => "font/woff2",
        Some("png") => "image/png",
        _ => "text/plain",
    }
}

async fn hello_world(req: Request<Body>) -> Result<Response<Body>, ServeError> {
    let mut response = Response::new(Body::empty());

    let mut accept_gzip = false;
    for list in req.headers().get_all(hyper::header::ACCEPT_ENCODING).iter() {
        if let Ok(list) = list.to_str() {
            if list.split(",").any(|item| item.trim() == "gzip") {
                accept_gzip = true;
                break;
            }
        }
    }

    match (req.method(), req.uri().path()) {
        (&Method::GET, path) => {
            let mut sanitized = String::with_capacity(path.len() + 1);
            sanitized.push_str("./");
            for c in path.chars() {
                match c {
                    // Squash NUL to underscore.
                    '\0' => sanitized.push('_'),
                    // Drop duplicate slashes.
                    '/' if sanitized.ends_with("/") => (),
                    // Add one dot to any dot after slash to avoid traversal.
                    '.' if sanitized.ends_with("/") => sanitized.push(':'),
                    // Otherwise, fine, we'll give it a try.
                    _ => sanitized.push(c),
                }
            }
            println!("path: {}", sanitized);

            let open_result = if accept_gzip {
                picky_open_with_redirect_and_gzip(&mut sanitized).await
            } else {
                picky_open_with_redirect(&mut sanitized).await.map(|f| (f, None))
            };
            match open_result {
                Ok((FileOrDir::File { file, content_type, len, modified }, enc)) => {
                    *response.body_mut() = Body::wrap_stream(
                    codec::BytesCodec::new()
                        .framed(file)
                        .map(|b| b.map(bytes::BytesMut::freeze)));
                    response.headers_mut().insert(hyper::header::CONTENT_LENGTH, len.into());
                    response.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static(content_type));
                    if let Some(enc) = enc {
                        response.headers_mut().insert(hyper::header::CONTENT_ENCODING, hyper::header::HeaderValue::from_static(enc));
                    }
                }
                _ => {
                    *response.status_mut() = StatusCode::NOT_FOUND;
                }
            }
        }
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    }

    Ok(response)
}

#[tokio::main]
async fn main() {
    use clap::value_t;

    // Go ahead and parse arguments before dropping privileges, since they
    // control whether we drop privileges, among other things.
    let matches = clap::App::new("httpd2")
        .arg(clap::Arg::with_name("chroot")
            .short("c")
            .long("chroot")
            .help("Specifies that the server should chroot into DIR. You\n\
                   basically always want this, unless you're running the\n\
                   server as an unprivileged user."))
        .arg(clap::Arg::with_name("addr")
            .short("A")
            .long("addr")
            .takes_value(true)
            .value_name("ADDR:PORT")
            .help("Address and port to bind."))
        .arg(clap::Arg::with_name("uid")
            .short("U")
            .long("uid")
            .takes_value(true)
            .value_name("UID")
            .help("User to switch to via setuid before serving."))
        .arg(clap::Arg::with_name("gid")
            .short("G")
            .long("gid")
            .takes_value(true)
            .value_name("GID")
            .help("Group to switch to via setgid before serving."))
        .arg(clap::Arg::with_name("DIR")
            .help("Path to serve")
            .required(true)
            .index(1))
        .get_matches();

    let path = matches.value_of("DIR").unwrap();
    let should_chroot = value_t!(matches, "chroot", bool).unwrap_or(false);
    let addr = value_t!(matches, "addr", SocketAddr)
        .unwrap_or(SocketAddr::from(([0,0,0,0], 8000)));
    let uid = if let Some(uid) = matches.value_of("uid") {
        Some(uid.parse::<libc::uid_t>().expect("bad UID value"))
    } else {
        None
    };
    let gid = if let Some(gid) = matches.value_of("gid") {
        Some(gid.parse::<libc::gid_t>().expect("bad GID value"))
    } else {
        None
    };

    // Things that need to get done while root:
    // - Binding to privileged ports.
    // - Reading SSL private key.
    // - Chrooting.

    let key = rustls::internal::pemfile::pkcs8_private_keys(
        &mut io::BufReader::new(
            std::fs::File::open("localhost.key").expect("can't open localhost.key")
        )
    ).expect("can't load key").pop().expect("no keys?");
    let cert_chain = rustls::internal::pemfile::certs(
        &mut io::BufReader::new(
            std::fs::File::open("localhost.crt").expect("can't open localhost.crt")
        )
    ).expect("can't load cert");

    let mut listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Could not bind");

    // Beginning to drop privileges here

    std::env::set_current_dir(&path).expect("can't cwd");
    if should_chroot {
        nix::unistd::chroot(&*path).expect("can't chroot");
    }
    if let Some(gid) = gid {
        let gid = nix::unistd::Gid::from_raw(gid);
        nix::unistd::setgid(gid).expect("can't setgid");
        nix::unistd::setgroups(&[gid]).expect("can't setgid");
    }
    if let Some(uid) = uid {
        let uid = nix::unistd::Uid::from_raw(uid);
        nix::unistd::setuid(uid).expect("can't setuid");
    }

    // All privileges dropped.

    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_single_cert(cert_chain, key).expect("can't set cert");
    config.versions = vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    let http = hyper::server::conn::Http::new();
    // TODO settings here

    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        if let Ok(socket) = stream {
            let tls_acceptor = tls_acceptor.clone();
            let http = http.clone();
            tokio::spawn(async move {
                if let Ok(stream) = tls_acceptor.accept(socket).await {
                    let r = http.serve_connection(stream, service_fn(hello_world)).await;
                    match r {
                        Ok(_) => (),
                        Err(e) => eprintln!("error in connection: {}", e),
                    }
                } else {
                    eprintln!("error in handshake");
                }
            });
        } else {
            eprintln!("error accepting");
        }
    }
}
