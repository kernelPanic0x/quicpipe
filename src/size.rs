//! Automatic input-size detection for the inlet.
//!
//! Parsing of `-s/--size` is delegated to `parse-size`, which understands
//! pv-style suffixes (`1k`, `500M`, `1.5GiB`, ...). This module only answers
//! the other question: can the size be discovered without being told?
//!
//! The inlet reads either a path or stdin (`-`). For a regular file the
//! metadata length is exact; for stdin redirected from a regular file we use
//! `fstat` and subtract the current offset, so `quicpipe inlet < file` gets an
//! accurate ETA without requiring `-s`. Pipes, sockets and devices stay
//! unknown, because no total exists to report.

use std::path::Path;

/// Best-effort size of the inlet's source, in bytes.
///
/// Returns `None` when the source has no meaningful total (a pipe, a
/// terminal, a missing path, a directory, ...). An empty regular file
/// correctly yields `Some(0)`.
pub fn detect(path: &Path) -> Option<u64> {
    if path.as_os_str() == "-" {
        stdin_remaining_bytes()
    } else {
        let metadata = std::fs::metadata(path).ok()?;
        metadata.is_file().then_some(metadata.len())
    }
}

/// The unread remainder of stdin when it refers to a regular file.
///
/// `lseek` is only meaningful for seekable descriptors, so a failure (pipe,
/// socket, tty) simply means "unknown". It reports the offset but leaves it
/// unchanged; the source thread remains the only reader.
#[cfg(unix)]
fn stdin_remaining_bytes() -> Option<u64> {
    // SAFETY: `fstat` only writes into the provided, zero-initialised struct
    // and is called with a valid descriptor constant.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(libc::STDIN_FILENO, std::ptr::addr_of_mut!(stat)) } != 0 {
        return None;
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let size = u64::try_from(stat.st_size).ok()?;
    let raw_offset = unsafe { libc::lseek(libc::STDIN_FILENO, 0, libc::SEEK_CUR) };
    let offset = u64::try_from(raw_offset).unwrap_or(0);
    Some(size.saturating_sub(offset))
}

#[cfg(not(unix))]
fn stdin_remaining_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::pedantic)]

    use super::*;

    #[test]
    fn a_regular_file_reports_its_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("in.bin");
        std::fs::write(&path, b"0123456789").expect("write");
        assert_eq!(detect(&path), Some(10));
    }

    #[test]
    fn an_empty_file_is_some_zero_not_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").expect("write");
        assert_eq!(detect(&path), Some(0));
    }

    #[test]
    fn a_directory_is_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(detect(dir.path()), None);
    }

    #[test]
    fn a_missing_path_is_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(detect(&dir.path().join("does-not-exist")), None);
    }
}
