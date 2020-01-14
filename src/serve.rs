use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hyper::header::HeaderValue;
use hyper::{Body, Method, Request, Response, StatusCode};

use tokio::stream::StreamExt;
use tokio_util::codec::{self, Decoder};

use crate::args::Args;
use crate::err::ServeError;
use crate::log::OptionKV;
use crate::picky::{self, File, FileOrDir};
use crate::{percent, traversal};

/// Attempts to serve a file in response to `req`.
pub async fn files(
    args: Arc<Args>,
    log: slog::Logger,
    req: Request<Body>,
) -> Result<Response<Body>, ServeError> {
    let mut response = Response::new(Body::empty());

    // Fetch the date of the caller's cached copy. We bump this forward by one
    // second because httpdate truncates outgoing timestamps, causing the
    // higher-precision filesystem timestamps to almost always be *after* the
    // IMS timestamp due to non-zero nanoseconds.
    // Pro: caching works.
    // Con: multiple updates in less than a second may be missed.
    let if_modified_since = req
        .headers()
        .get(hyper::header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .map(|ims| ims + Duration::from_secs(1));
    slog::debug!(log, "IMS: {:?}", if_modified_since);

    // Scan the request headers to see if gzip compressed responses are OK.
    let mut accept_gzip = false;
    for list in req.headers().get_all(hyper::header::ACCEPT_ENCODING).iter() {
        if let Ok(list) = list.to_str() {
            if list.split(",").any(|item| item.trim() == "gzip") {
                accept_gzip = true;
                break;
            }
        }
    }

    let method = req.method();
    let uri = req.uri();
    slog::info!(
        log,
        "{}", method;
        "uri" => %uri,
        "version" => ?req.version(),
    );

    // Process GET requests.
    let mut response_info = match (method, uri.path()) {
        (&Method::GET, path) | (&Method::HEAD, path) => {
            // Sanitize the path using a derivative of publicfile's algorithm.
            // It appears that Hyper blocks non-ASCII characters.
            let mut sanitized = sanitize_path(path);

            // Now, see what the path yields.
            let open_result = picky_open_with_redirect_and_gzip(
                &log,
                &mut sanitized,
                accept_gzip,
            )
            .await;

            match open_result {
                Ok((FileOrDir::File(file), enc)) => {
                    let cached = if_modified_since
                        .map(|ims| file.modified <= ims)
                        .unwrap_or(false);
                    slog::debug!(log, "modified={:?}", file.modified);

                    set_response_headers(&*args, &mut response, &file, enc);

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
                // To avoid disclosing information, we signal any other case
                // as 404. Cases covered here include:
                // - Actual file not found.
                // - Permissions did not permit file to be served.
                // - One level of directory redirect followed, but still
                //   found a directory.
                Ok(_) => {
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    ResponseInfo::Error(
                        ErrorContext::Fixed("would serve directory"),
                        None,
                    )
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
        if let Ok((FileOrDir::File(error_page), enc)) = err_result {
            *srv = Some(Served {
                len: error_page.len,
                encoding: enc.unwrap_or("raw"),
            });
            set_response_headers(&*args, &mut response, &error_page, enc);
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
    Error(io::Error),
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
        HeaderValue::from_str(&httpdate::fmt_http_date(file.modified)).unwrap(),
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
) -> Result<FileOrDir, io::Error> {
    // Performance optimization: if the path is *syntactically* a directory,
    // i.e. it ends in a slash, pre-append the `index.html`. This reduces
    // filesystem round trips (and thus the number of blocking operations
    // affecting the thread pool) by 1, and improved a particular load benchmark
    // by 18% at the time of writing.
    if path.ends_with("/") {
        path.push_str("index.html");
    }

    match picky::open(log, Path::new(path), map_content_type).await? {
        FileOrDir::Dir => {
            slog::debug!(log, "--> index.html");
            path.push_str("/index.html");
            picky::open(log, Path::new(path), map_content_type).await
        }
        r => Ok(r),
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
/// Returns the normal `FileOrDir` result, plus an optional `Content-Encoding`
/// value if an alternate encoding was selected.
async fn picky_open_with_redirect_and_gzip(
    log: &slog::Logger,
    path: &mut String,
    accept_gzip: bool,
) -> Result<(FileOrDir, Option<&'static str>), io::Error> {
    match picky_open_with_redirect(log, path).await? {
        FileOrDir::File(file) if accept_gzip => {
            slog::debug!(log, "checking for precompressed alternate");
            path.push_str(".gz");
            // Note that we're "inferring" the old content-type.
            match picky::open(log, Path::new(path), |_| file.content_type).await
            {
                Ok(FileOrDir::File(cfile))
                    if cfile.modified >= file.modified =>
                {
                    slog::debug!(log, "serving gzip");
                    // Preserve mod date of original content.
                    Ok((
                        FileOrDir::File(File {
                            modified: file.modified,
                            ..cfile
                        }),
                        Some("gzip"),
                    ))
                }
                _ => {
                    slog::debug!(log, "serving uncompressed");
                    Ok((FileOrDir::File(file), None))
                }
            }
        }
        any => Ok((any, None)),
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
