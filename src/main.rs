use std::net::SocketAddr;

use futures::TryStreamExt;

use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::error::Error;
use hyper::service::{make_service_fn, service_fn};

async fn hello_world(req: Request<Body>) -> Result<Response<Body>, Error> {
    let mut response = Response::new(Body::empty());

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("try POSTing data to /echo");
        }
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        }
        (&Method::POST, "/echo/uppercase") => {
            let mapping = req
                .into_body()
                .map_ok(|chunk| {
                    chunk.iter()
                        .map(|byte| byte.to_ascii_uppercase())
                        .collect::<Vec<_>>()
                });
            *response.body_mut() = Body::wrap_stream(mapping);
        }
        (&Method::POST, "/echo/reverse") => {
            let full_body = hyper::body::to_bytes(req.into_body()).await?;
            let reversed = full_body.iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>();
            *response.body_mut() = reversed.into();
        }
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    }

    Ok(response)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler")
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let svc = make_service_fn(|_conn| async {
        Ok::<_, Error>(service_fn(hello_world))
    });

    let server = Server::bind(&addr)
        .serve(svc)
        .with_graceful_shutdown(shutdown_signal());

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
