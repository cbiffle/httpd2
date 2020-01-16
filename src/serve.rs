use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;

use hyper::header::HeaderValue;
use hyper::{Body, Method, Request, Response, StatusCode};

use tokio::stream::StreamExt;
use tokio_util::codec::{self, Decoder};

use crate::args::Args;
use crate::err::ServeError;
use crate::log::OptionKV;
use crate::picky::{self, File};
use crate::{percent, traversal};

/// Attempts to serve a file in response to `req`.
pub async fn files(
    args: Arc<Args>,
    log: slog::Logger,
    req: Request<Body>,
) -> Result<Response<Body>, ServeError> {
    // We log all requests, whether or not they will be served.
    let method = req.method();
    let uri = req.uri();
    slog::info!(
        log,
        "{}", method;
        "uri" => %uri,
        "version" => ?req.version(),
    );

    // Other than logging, we defer work to the latest reasonable point, to
    // reduce the load of bogus requests on the server. This means that bogus
    // requests will incur lower latency than legit ones, but the only
    // side-channel that opens should be the ability to probe what public files
    // exist on the filesystem ... which is exactly what the HTTP server is for.

    let mut response = Response::new(Body::empty());

    let mut accept_gzip = false;
    let mut response_info = match (method, uri.path()) {
        (&Method::GET, path) | (&Method::HEAD, path) => {
            // Sanitize the path using a derivative of publicfile's algorithm.
            // It appears that Hyper blocks non-ASCII characters.
            let mut sanitized = sanitize_path(path);

            // Scan the request headers to see if gzip compressed responses are
            // OK. We need to do this before consulting the filesystem, but it's
            // fairly quick.
            for list in
                req.headers().get_all(hyper::header::ACCEPT_ENCODING).iter()
            {
                if let Ok(list) = list.to_str() {
                    if list.split(",").any(|item| item.trim() == "gzip") {
                        accept_gzip = true;
                        break;
                    }
                }
            }

            // Now, see what the path yields.
            let open_result = picky_open_with_redirect_and_gzip(
                &log,
                &mut sanitized,
                accept_gzip,
            )
            .await;

            match open_result {
                Ok((file, enc)) => {
                    // Collect the caller's cache date, if present. Because the
                    // date format is fixed as of HTTP/1.1, and because caches
                    // send the *exact* previous date in if-modified-since, we
                    // can get away with doing an exact bytewise date comparison
                    // rather than parsing.
                    let if_modified_since = req
                        .headers()
                        .get(hyper::header::IF_MODIFIED_SINCE)
                        .and_then(|value| value.to_str().ok());

                    let modified = httpdate::fmt_http_date(file.modified);

                    let cached = if_modified_since == Some(&*modified);

                    set_response_headers(
                        &*args,
                        &mut response,
                        &file,
                        Some(modified),
                        enc,
                    );

                    if method == Method::GET {
                        if cached {
                            *response.status_mut() = StatusCode::NOT_MODIFIED;
                            ResponseInfo::Success(None)
                        } else {
                            let len = file.len;
                            set_file_as_body(&mut response, file);
                            ResponseInfo::Success(Some(Served {
                                len,
                                encoding: enc.unwrap_or("raw"),
                            }))
                        }
                    } else {
                        ResponseInfo::Success(None)
                    }
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    ResponseInfo::Error(ErrorContext::Error(e), None)
                }
            }
        }
        _ => {
            // Any other request method falls here.
            *response.status_mut() = StatusCode::NOT_FOUND;
            ResponseInfo::Error(ErrorContext::Fixed("bad method"), None)
        }
    };

    if let ResponseInfo::Error(_, srv) = &mut response_info {
        // Attempt to present the user with an error page.
        slog::debug!(log, "searching for error page");
        // TODO: it would be nice to break the picky combinators out, so I could
        // have picky_open_with_gzip (no redirect) here.
        let mut redirect = "./errors/404.html".to_string();
        let err_result =
            picky_open_with_redirect_and_gzip(&log, &mut redirect, accept_gzip)
                .await;
        if let Ok((error_page, enc)) = err_result {
            *srv = Some(Served {
                len: error_page.len,
                encoding: enc.unwrap_or("raw"),
            });
            set_response_headers(&*args, &mut response, &error_page, None, enc);
            set_file_as_body(&mut response, error_page);
        }
    }

    let log_kv = slog::o!("status" => response.status().as_u16());
    let srv_kv = match &response_info {
        ResponseInfo::Error(_, os) | ResponseInfo::Success(os) => {
            os.as_ref().map(|s| {
                slog::o!(
                    "len" => s.len,
                    "enc" => s.encoding,
                )
            })
        }
    };
    match response_info {
        ResponseInfo::Error(ErrorContext::Fixed(ctx), _) => slog::info!(
            log,
            "response";
            log_kv,
            "err" => ctx,
            OptionKV::from(srv_kv),
        ),
        ResponseInfo::Error(ErrorContext::Error(e), _) => slog::info!(
            log,
            "response";
            log_kv,
            "err" => %e,
            OptionKV::from(srv_kv),
        ),
        ResponseInfo::Success(_) => slog::info!(
            log,
            "response";
            log_kv,
            OptionKV::from(srv_kv),
        ),
    }

    Ok(response)
}

enum ErrorContext {
    Fixed(&'static str),
    Error(picky::Error),
}

enum ResponseInfo {
    Error(ErrorContext, Option<Served>),
    Success(Option<Served>),
}

struct Served {
    len: u64,
    encoding: &'static str,
}

fn set_response_headers(
    args: &Args,
    response: &mut Response<Body>,
    file: &File,
    modified_fmt: Option<String>,
    enc: Option<&'static str>,
) {
    let headers = response.headers_mut();

    headers.insert(hyper::header::CONTENT_LENGTH, file.len.into());
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static(file.content_type),
    );
    headers.insert(
        hyper::header::LAST_MODIFIED,
        HeaderValue::from_str(
            &modified_fmt
                .unwrap_or_else(|| httpdate::fmt_http_date(file.modified)),
        )
        .unwrap(),
    );
    headers.insert(
        hyper::header::VARY,
        HeaderValue::from_name(hyper::header::ACCEPT_ENCODING),
    );
    headers.insert(hyper::header::CACHE_CONTROL, args.cache_control.clone());
    if let Some(enc) = enc {
        headers.insert(
            hyper::header::CONTENT_ENCODING,
            HeaderValue::from_static(enc),
        );
    }
    if args.hsts {
        headers.insert(
            hyper::header::STRICT_TRANSPORT_SECURITY,
            // TODO: this should be larger, I'm keeping it low
            // for testing.
            HeaderValue::from_static("max-age=60"),
        );
    }
    if args.upgrade {
        headers.insert(
            hyper::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("upgrade-insecure-requests;"),
        );
    }
}

fn set_file_as_body(response: &mut Response<Body>, file: File) {
    *response.body_mut() = Body::wrap_stream(
        codec::BytesCodec::new()
            .framed(file.file)
            .map(|b| b.map(bytes::BytesMut::freeze)),
    );
}

/// Extends `picky::open` with directory redirect handling.
///
/// If `path` turns out to be a directory, this routine will retry the
/// `picky_open` to search for an `index.html` file within that directory. If
/// the `index.html` has the appropriate permissions and is a regular file, the
/// open operation succeeds, returning its contents.
async fn picky_open_with_redirect(
    log: &slog::Logger,
    path: &mut String,
) -> Result<File, picky::Error> {
    // Performance optimization: if the path is *syntactically* a directory,
    // i.e. it ends in a slash, pre-append the `index.html`. This reduces
    // filesystem round trips (and thus the number of blocking operations
    // affecting the thread pool) by 1, and improved a particular load benchmark
    // by 18% at the time of writing.
    let trailing_slash = path.ends_with("/");
    if trailing_slash {
        path.push_str("index.html");
    }

    match picky::open(log, Path::new(path), map_content_type).await {
        Err(picky::Error::Directory) if !trailing_slash => {
            slog::debug!(log, "--> index.html");
            path.push_str("/index.html");
            picky::open(log, Path::new(path), map_content_type).await
        }
        r => r,
    }
}

/// Extends `picky_open_with_redirect` with selection of precompressed
/// alternate files.
///
/// When `picky_open_with_redirect` finds a readable regular file at `path`,
/// this routine will retry to search for a compressed version of the file with
/// the same name and the `.gz` extension appended. If the compressed version
/// exists, passes `picky_open`'s criteria, *and* has a last-modified date at
/// least as recent as the original file, then it is substituted.
///
/// Importantly, the content-type judgment for the *original*, non-compressed
/// file, is preserved.
///
/// Returns the normal `File` result, plus an optional `Content-Encoding` value
/// if an alternate encoding was selected.
async fn picky_open_with_redirect_and_gzip(
    log: &slog::Logger,
    path: &mut String,
    accept_gzip: bool,
) -> Result<(File, Option<&'static str>), picky::Error> {
    let file = picky_open_with_redirect(log, path).await?;

    if !accept_gzip {
        return Ok((file, None));
    }

    open_precompressed(log, path, file).await
}

async fn open_precompressed(
    log: &slog::Logger,
    path: &mut String,
    file: File,
) -> Result<(File, Option<&'static str>), picky::Error> {
    slog::debug!(log, "checking for precompressed alternate");
    path.push_str(".gz");
    // Note that we're "inferring" the old content-type.
    match picky::open(log, Path::new(path), |_| file.content_type).await {
        Ok(cfile) if cfile.modified >= file.modified => {
            slog::debug!(log, "serving gzip");
            // Preserve mod date of original content.
            Ok((
                File {
                    modified: file.modified,
                    ..cfile
                },
                Some("gzip"),
            ))
        }
        _ => {
            // If the compressed alternative isn't available, or if it
            // predates the actual content, ignore it.
            slog::debug!(log, "serving uncompressed");
            Ok((file, None))
        }
    }
}

/// Guesses the `Content-Type` of a file based on its path.
///
/// Currently, this is hardcoded based on file extensions, like we're Windows.
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

fn sanitize_path(path: &str) -> String {
    traversal::sanitize(percent::decode(path.chars())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_and_sanitize() {
        assert_eq!(sanitize_path("%2f"), "./");
        assert_eq!(sanitize_path("%2f%2F"), "./");
        assert_eq!(sanitize_path("%2f%2e%2e"), "./:.");
        assert_eq!(sanitize_path("%2f%2e%2e%00"), "./:._");
    }
}
