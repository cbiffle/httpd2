//! Picky filesystem APIs for channeling djb.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;

use tokio::fs;

/// Possible successful results from `open`.
#[derive(Debug)]
pub enum FileOrDir {
    /// We found a directory.
    Dir,
    /// We found a regular file, with permissions set such that we're willing to
    /// admit it exists.
    File(File),
}

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
/// If the path turns out to be a directory, returns `FileOrDir::Dir` only if it
/// meets all the above criteria.
pub async fn open(
    log: &slog::Logger,
    path: &Path,
    infer_content_type: impl FnOnce(&Path) -> &'static str,
) -> Result<FileOrDir, io::Error> {
    slog::debug!(log, "picky_open({:?})", path);

    let file = fs::File::open(path).await.map_err(|e| {
        slog::debug!(log, "can't open: {}", e);
        e
    })?;
    let meta = file.metadata().await?;
    let mode = meta.permissions().mode();

    if mode & 0o444 != 0o444 || mode & 0o101 == 0o001 {
        slog::debug!(log, "mode {:#o} is not OK", mode);
        Err(io::Error::new(io::ErrorKind::NotFound, "perms"))
    } else if meta.is_file() {
        slog::debug!(log, "opened");
        Ok(FileOrDir::File(File {
            file,
            len: meta.len(),
            modified: meta.modified().unwrap(),
            content_type: infer_content_type(path),
        }))
    } else if meta.is_dir() {
        slog::debug!(log, "found dir");
        Ok(FileOrDir::Dir)
    } else {
        slog::debug!(log, "neither file nor dir");
        Err(io::Error::new(io::ErrorKind::NotFound, "type"))
    }
}
