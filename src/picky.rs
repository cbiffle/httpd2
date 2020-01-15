//! Picky filesystem APIs for channeling djb.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;

use tokio::fs;

/// Information about an open file, including the file handle.
#[derive(Debug)]
pub struct File {
    /// An async handle to the file, open for read.
    pub file: fs::File,
    /// Length of the file in bytes.
    pub len: u64,
    /// Inferred content type of file.
    pub content_type: &'static str,
    /// Modification timestamp.
    pub modified: SystemTime,
}

/// Accesses a path for file serving, if it meets certain narrow criteria.
///
/// This operation is critical to the correctness of the server. It is careful
/// in several respects:
///
/// 1. To avoid TOCTOU issues, it opens files first and checks their metadata
///    second.
///
/// 2. Only files that are user/group/world readable are acknowledged to exist.
///
/// 3. Files that are world-X but not user-X are rejected, for reasons inherited
///    from publicfile that I don't quite recall.
///
/// If the path turns out to be a directory, returns `Error::Directory` only if
/// it meets all the above criteria, otherwise you'll get `Error::BadMode`.
pub async fn open(
    log: &slog::Logger,
    path: &Path,
    infer_content_type: impl FnOnce(&Path) -> &'static str,
) -> Result<File, Error> {
    slog::debug!(log, "picky_open({:?})", path);

    let file = fs::File::open(path).await.map_err(|e| {
        slog::debug!(log, "can't open: {}", e);
        e
    })?;
    let meta = file.metadata().await?;
    let mode = meta.permissions().mode();

    if mode & 0o444 != 0o444 || mode & 0o101 == 0o001 {
        slog::debug!(log, "mode {:#o} is not OK", mode);
        Err(Error::BadMode(mode))
    } else if meta.is_file() {
        slog::debug!(log, "opened");
        Ok(File {
            file,
            len: meta.len(),
            modified: meta.modified().unwrap(),
            content_type: infer_content_type(path),
        })
    } else if meta.is_dir() {
        slog::debug!(log, "found dir");
        Err(Error::Directory)
    } else {
        slog::debug!(log, "neither file nor dir");
        Err(Error::SpecialFile)
    }
}

#[derive(Debug)]
pub enum Error {
    BadMode(u32),
    Directory,
    SpecialFile,
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::BadMode(x) => write!(f, "mode {:#o}", x),
            Self::Directory => f.write_str("is dir"),
            Self::SpecialFile => f.write_str("is special"),
            Self::Io(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
