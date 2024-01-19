use std::sync::Arc;
use std::ffi::OsStr;
use std::path::Path;
use std::pin::Pin;

use bytes::Bytes;
use enum_map::{Enum, EnumMap};
use futures::stream::StreamExt;

use hyper::body::{Body, Frame};
use hyper::header::HeaderValue;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use http_body_util::{StreamBody, BodyExt};

use tokio_util::codec::{self, Decoder};

use crate::args::{HasCommonArgs, CommonArgs};
use crate::err::{ServeError, DefenseError};
use crate::log::OptionKV;
use crate::picky::{self, File};
use crate::{percent, traversal};

fn empty() -> Pin<Box<dyn Body<Data = Bytes, Error = ServeError> + Send>> {
    Box::pin(http_body_util::Empty::new().map_err(|r| match r {}))
}

/// Attempts to serve a file in response to `req`.
pub async fn files(
    args: Arc<impl HasCommonArgs>,
    log: slog::Logger,
    req: Request<Incoming>,
) -> Result<Response<Pin<Box<dyn Body<Data = Bytes, Error = ServeError> + Send>>>, ServeError> {
    // We log all requests, whether or not they will be served.
    let method = req.method();
    let uri = req.uri();
    let ua = if args.common().log_user_agent {
        req.headers().get(hyper::header::USER_AGENT).map(|v| {
            // Use HeaderValue's Debug impl to safely print attacker-controlled
            // data.
            slog::o!("user-agent" => format!("{v:?}"))
        })
    } else {
        None
    };
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

    // Request-level defenses:

    // Check the request for a body. Deny if found.
    if req.size_hint().lower() != 0 || req.size_hint().upper() != Some(0) {
        slog::warn!(
            log,
            "defense";
            "cause" => "upload",
        );
        return Err(DefenseError.into());
    }

    // Other than logging, we defer work to the latest reasonable point, to
    // reduce the load of bogus requests on the server. This means that bogus
    // requests will incur lower latency than legit ones, but the only
    // side-channel that opens should be the ability to probe what public files
    // exist on the filesystem ... which is exactly what the HTTP server is for.

    let mut accept_encodings = EnumMap::default();
    let (mut response, mut response_info) = match (method, uri.path()) {
        (&Method::GET, path) | (&Method::HEAD, path) => {
            // Sanitize the path using a derivative of publicfile's algorithm.
            // It appears that Hyper blocks non-ASCII characters.
            let mut sanitized = sanitize_path(path);

            // Scan the request headers to see if compressed responses are OK.
            // We need to do this before consulting the filesystem, but it's
            // fairly quick.
            req
                .headers()
                // The header can technically be specified more than once.
                .get_all(hyper::header::ACCEPT_ENCODING)
                .iter()
                // Ignore any that aren't UTF-8.
                .filter_map(|list| list.to_str().ok())
                // Split them all at commas and merge them together.
                .flat_map(|list| list.split(','))
                // Collect the methods we recognize.
                .for_each(|name| match name.trim() {
                    "gzip" => accept_encodings[Encoding::Gzip] = true,
                    "br" => accept_encodings[Encoding::Brotli] = true,
                    _ => (),
                });

            // Now, see what the path yields.
            let open_result = picky_open_with_redirect_and_alt(
                &log,
                &mut sanitized,
                accept_encodings,
            )
            .await;

            match open_result {
                Ok((file, enc)) => {
                    // Collect the caller's cache date and etag, if present.
                    //
                    // Because the date format is fixed as of HTTP/1.1, and
                    // because caches send the *exact* previous date in
                    // if-modified-since, we can get away with doing an exact
                    // bytewise date comparison rather than parsing.
                    //
                    // ETag is already defined as an exact comparison.
                    let if_modified_since = req
                        .headers()
                        .get(hyper::header::IF_MODIFIED_SINCE)
                        .and_then(|value| value.to_str().ok());
                    let if_none_match = req
                        .headers()
                        .get(hyper::header::IF_NONE_MATCH)
                        .and_then(|value| value.to_str().ok());

                    let (resp, srv) = serve_file(
                        args.common(),
                        file,
                        enc,
                        if_modified_since,
                        if_none_match,
                        method == Method::GET,
                    );
                    (resp, ResponseInfo::Success(srv))
                }
                Err(e) => (
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(empty())
                        .unwrap(),
                    ResponseInfo::Error(ErrorContext::Error(e), None),
                ),
            }
        }
        // Any other request method falls here.
        _ => (
            Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(empty())
                .unwrap(),
            ResponseInfo::Error(ErrorContext::Fixed("bad method"), None),
        ),
    };

    if let ResponseInfo::Error(_, srv) = &mut response_info {
        // Attempt to present the user with an error page.
        slog::debug!(log, "searching for error page");

        let mut redirect =
            format!("./errors/{:03}.html", response.status().as_u16());
        // TODO: it would be nice to break the picky combinators out, so I could
        // have picky_open_with_alt (no redirect) here.
        let err_result =
            picky_open_with_redirect_and_alt(&log, &mut redirect, accept_encodings)
                .await;
        if let Ok((error_page, enc)) = err_result {
            let (mut r, s) = serve_file(args.common(), error_page, enc, None, None, true);
            *r.status_mut() = response.status();
            response = r;
            *srv = s;
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

/// Generates a `Response` with common headers initialized, and an empty body.
///
/// `args` is used to customize generation of some headers.
///
/// `len`, `content_type`, and `modified` are metadata of the file being served.
///
/// `enc` gives the content-encoding of the file, if it is not being served
/// plain.
fn start_response(
    args: &CommonArgs,
    len: u64,
    content_type: &'static str,
    modified: &str,
    etag: &str,
    ttl: Option<usize>,
    enc: Option<Encoding>,
) -> Response<Pin<Box<dyn Body<Data = Bytes, Error = ServeError> + Send>>> {
    let mut response = Response::new(empty());

    let headers = response.headers_mut();

    headers.insert(hyper::header::CONTENT_LENGTH, len.into());
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    headers.insert(
        hyper::header::VARY,
        HeaderValue::from_name(hyper::header::ACCEPT_ENCODING),
    );
    headers.insert(hyper::header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("max-age={}", ttl.unwrap_or(args.default_max_age))).unwrap()
    );
    headers.insert(
        hyper::header::LAST_MODIFIED,
        HeaderValue::from_str(modified).unwrap(),
    );
    headers.insert(
        hyper::header::ETAG,
        HeaderValue::from_str(etag).unwrap(),
    );
    if let Some(enc) = enc {
        headers.insert(hyper::header::CONTENT_ENCODING, enc.into());
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
    response
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
    let trailing_slash = path.ends_with('/');
    if trailing_slash {
        path.push_str("index.html");
    }

    match picky::open(log, Path::new(path), map_content_type, map_cache_ttl).await {
        Err(picky::Error::Directory) if !trailing_slash => {
            slog::debug!(log, "--> index.html");
            path.push_str("/index.html");
            picky::open(log, Path::new(path), map_content_type, map_cache_ttl).await
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
async fn picky_open_with_redirect_and_alt(
    log: &slog::Logger,
    path: &mut String,
    encodings: EnumMap<Encoding, bool>,
) -> Result<(File, Option<Encoding>), picky::Error> {
    let file = picky_open_with_redirect(log, path).await?;

    // If the caller isn't willing to accept any compressed encodings, we're
    // done.
    if encodings.values().all(|&accept| accept == false) {
        return Ok((file, None));
    }

    open_precompressed(log, path, file, encodings).await
}

async fn open_precompressed(
    log: &slog::Logger,
    path: &mut String,
    file: File,
    encodings: EnumMap<Encoding, bool>,
) -> Result<(File, Option<Encoding>), picky::Error> {
    slog::debug!(log, "checking for precompressed alternate");
    let path_orig_len = path.len();
    for (encoding, accepted) in encodings {
        if !accepted { continue; }

        path.push_str(encoding.file_extension());

        // Note that we're "inferring" the old content-type and TTL.
        match picky::open(log, Path::new(path), |_| file.content_type, |_| file.ttl).await {
            Ok(altfile) if altfile.modified >= file.modified => {
                slog::debug!(log, "serving {}", encoding.short_name());
                // Preserve mod date of original content.
                return Ok((
                        File {
                            modified: file.modified,
                            ..altfile
                        },
                        Some(encoding),
                ));
            }
            Ok(_) => {
                // We distinguish this case only to improve debug output; if
                // debug output is disabled, as is typical in production, it
                // collapses with the one below.
                slog::debug!(log, "alternate found for encoding {encoding:?} but is modified later than primary");
            }
            _ => {
                // If the compressed alternative isn't available, or if it
                // predates the actual content, ignore it.
                slog::debug!(log, "no alternate found for encoding {encoding:?}");
            }
        }
        path.truncate(path_orig_len);
    }

    Ok((file, None))
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
        Some("jpg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("xml") => "application/xml",
        Some("wasm") => "application/wasm",
        Some("bin") => "application/octet-stream",
        Some("pdf") => "application/pdf",
        _ => "text/plain",
    }
}

/// Optionally suggests a cache TTL for a resource based on its extension.
///
/// Currently hardcoded.
fn map_cache_ttl(path: &Path) -> Option<usize> {
    match path.extension().and_then(OsStr::to_str) {
        Some("css") | Some("js") | Some("png") | Some("jpg") | Some("wasm") | Some("gif") => Some(86_400),
        Some("woff2") => Some(86_400 * 30),
        Some("pdf") => Some(86_400),
        Some("xml") => Some(86_400),
        _ => None,
    }
}

fn sanitize_path(path: &str) -> String {
    traversal::sanitize(percent::decode(path.chars())).collect()
}

/// Content-Encodings we support. The order of variants in this enum determines
/// the order in which they're prioritized, from highest priority to lowest.
#[derive(Copy, Clone, Debug, Enum)]
enum Encoding {
    Brotli,
    Gzip,
}

impl Encoding {
    fn file_extension(&self) -> &'static str {
        match self {
            Self::Brotli => ".br",
            Self::Gzip => ".gz",
        }
    }

    /// Short names for the encodings as used in the Accept-Encodings headers.
    /// These are also logged.
    fn short_name(&self) -> &'static str {
        match self {
            Self::Brotli => "br",
            Self::Gzip => "gzip",
        }
    }
}

impl From<Encoding> for HeaderValue {
    fn from(e: Encoding) -> Self {
        HeaderValue::from_static(e.short_name())
    }
}

fn serve_file(
    args: &CommonArgs,
    file: File,
    encoding: Option<Encoding>,
    if_modified_since: Option<&str>,
    if_none_match: Option<&str>,
    send_body: bool,
) -> (Response<Pin<Box<dyn Body<Data = Bytes, Error = ServeError> + Send>>>, Option<Served>) {
    // Go ahead and format the modification date as a string, since we'll need
    // it for the response headers and the if-modified-since check (where
    // relevant). We unfortunately need to format this two different ways thanks
    // to ETag's requirement for quotes. Since we trust the output to be ASCII,
    // we can avoid the extra allocation by slicing the quoted representation as
    // follows:
    let http_date = httpdate::HttpDate::from(file.modified);
    let etag = format!("\"{http_date}\"");
    let modified = &etag[1..etag.len() - 1];

    // Check if-modified-since before handing off the modified string.
    let cached = if_modified_since == Some(modified)
        || if_none_match == Some(&*etag);

    // Construct the basic response.
    let mut response =
        start_response(args, file.len, file.content_type, modified, &*etag, file.ttl, encoding);

    // If a last-modified date was provided, and it matches, we want to
    // uniformly return a 304 without a body to both GET and HEAD requests.
    if cached || !send_body {
        if cached {
            *response.status_mut() = StatusCode::NOT_MODIFIED;
        }
        (response, None)
    } else {
        // !cached && send_body
        // A GET request without a matching last-modified.
        *response.body_mut() = Box::pin(StreamBody::new(
            codec::BytesCodec::new()
                .framed(file.file)
                .map(|b| b.map(bytes::BytesMut::freeze))
                .map(|b| b.map(Frame::data))
                .map(|r| r.map_err(ServeError::from))
        ));
        (
            response,
            Some(Served {
                len: file.len,
                encoding: match encoding {
                    None => "raw",
                    Some(e) => e.short_name(),
                },
            }),
        )
    }
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
