use std::net::SocketAddr;
use std::fs;
use std::io;
use std::sync::Arc;

use hyper::{Body, Method, Request, Response, StatusCode};
use hyper::error::Error;
use hyper::service::{service_fn};

use rustls::{NoClientAuth, ServerConfig, ProtocolVersion};

use tokio::stream::StreamExt;
use tokio_rustls::TlsAcceptor;

async fn hello_world(req: Request<Body>) -> Result<Response<Body>, Error> {
    let mut response = Response::new(Body::empty());

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("try POSTing data to /echo");
        }
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    }

    Ok(response)
}

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let mut config = ServerConfig::new(NoClientAuth::new());
    let key = rustls::internal::pemfile::pkcs8_private_keys(
        &mut io::BufReader::new(
            fs::File::open("localhost.key").expect("can't open localhost.key")
        )
    ).expect("can't load key").pop().expect("no keys?");
    let cert_chain = rustls::internal::pemfile::certs(
        &mut io::BufReader::new(
            fs::File::open("localhost.crt").expect("can't open localhost.crt")
        )
    ).expect("can't load cert");
    config.set_single_cert(cert_chain, key).expect("can't set cert");
    config.versions = vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    if let Some(path) = path {
        nix::unistd::chroot(&*path).expect("can't chroot");
    }

    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    let mut listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Could not bind");

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
