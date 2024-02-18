use std::io;
use std::path::Path;

use fs4::tokio::AsyncFileExt;

/// The error type for the `create_file_cleanly` function.
#[derive(thiserror::Error, Debug)]
pub enum CleanFileCreationError<E: std::error::Error + Send + Sync + 'static> {
    #[error("The destination path is invalid (no filename)")]
    InvalidPath,

    #[error("The temporary file could not be created")]
    TempFileCreation(io::Error),

    #[error(
        "The temporary file could not be locked for writing after too many interrupted attempts"
    )]
    TooManyLockRetries,

    #[error("The temporary file could not be locked")]
    TempFileLocking(io::Error),

    #[error("The temporary file could not be truncated despite exclusive locked write access")]
    TempFileTruncation(io::Error),

    #[error("The temporary file is already being written to")]
    TempFileAlreadyBeingWrittenTo,

    #[error("The callback function indicated an error")]
    CallbackIndicatedError(E),

    #[error("The temporary file could not be renamed to the destination file")]
    RenameError(io::Error),
}

impl<E: std::error::Error + Send + Sync + 'static> From<CleanFileCreationError<E>> for io::Error {
    fn from(e: CleanFileCreationError<E>) -> io::Error {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

/// Creates a file at `dest_path` with the contents written by `write_fn`.
///
/// `write_fn` must drop the file before it returns.
///
/// This function tries to minimize the chance of leaving a partially-written file at the dest_path;
/// the final file is only created once the write function has returned successfully.
/// This is achieved by writing to a temporary file and then renaming it to the final file.
///
/// We lock the temporary file during writing in order to minimize interference by other processes,
/// for example if this very code is running in two processes at the same time.
///
/// The steps are:
///
/// 1. Create a temporary file in the same directory as the final file.
/// 2. Lock the temporary file for exclusive write access.
/// 3. Truncate the temporary file.
/// 4. Call `write_fn` with the temporary file, and wait for `write_fn` to complete successfully.
/// 5. Close (and automatically unlock) the temporary file.
/// 6. Rename the temporary file to the final file.
///
/// There is one problem here: Steps 5 and 6 are not atomic. Another process could inadvertently
/// mess with the temporary file in the time between closing (and unlocking) the temporary file
/// and renaming it - even if that other process tries to minimize its own damage by respecting
/// the file lock. If this happens, the rename step would rename the corrupted file.
/// For example, we'd get into this situation if, in the time between step 5 and 6,
/// another process runs steps 1 to 3.
/// No solution is attempted for this problem.
///
/// In regular failure cases (full disk, other IO errors, etc), we try to clean up the temporary
/// file. If this process is terminated before we can do so, the temporary file will be left
/// behind, but at least it will no longer be locked.
///
/// If the temporary file already exists and is locked, we return an error.
/// This happens if we are the second process in the scenario above, e.g. if we're called at a
/// time when the another process is somewhere between steps 2 and 5 on the same file.
pub async fn create_file_cleanly<E, F, G, V>(
    dest_path: &Path,
    write_fn: F,
) -> Result<V, CleanFileCreationError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
    G: std::future::Future<Output = Result<V, E>>,
    F: FnOnce(tokio::fs::File) -> G,
{
    let Some(file_name) = dest_path.file_name() else {
        return Err(CleanFileCreationError::InvalidPath);
    };

    // Create a temporary file in the same directory as the final file
    let temp_file_path = dest_path.with_file_name(format!("{}.part", file_name.to_string_lossy()));

    let write_result = {
        // Create the temporary file, or open it if it already exists.
        // Don't truncate it if it already exists because another process might
        // be writing to it and file opening does not consult file locks.
        let temp_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&temp_file_path)
            .await
            .map_err(CleanFileCreationError::TempFileCreation)?;

        // Lock the temporary file for exclusive write access.
        // We have a retry loop here because file locking can be interrupted by signals.
        for i in 0.. {
            match temp_file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        return Err(CleanFileCreationError::TempFileAlreadyBeingWrittenTo)
                    }
                    io::ErrorKind::Interrupted if i >= 5 => {
                        return Err(CleanFileCreationError::TooManyLockRetries)
                    }
                    io::ErrorKind::Interrupted => continue,
                    _ => return Err(CleanFileCreationError::TempFileLocking(e)),
                },
            }
        }

        // We now have the file open and locked for exclusive write access.
        // Truncate it, in case it already existed and had some content.
        temp_file
            .set_len(0)
            .await
            .map_err(CleanFileCreationError::TempFileTruncation)?;

        // Call the write function with the temporary file. We pass ownership of the
        // file to the write function. The write function is responsible for dropping
        // the file before it returns - this will close the file and unlock it.
        write_fn(temp_file).await
    };

    // The temp file is now unlocked and closed. We're not unlocking it explicitly;
    // closing it is supposed to unlock it.

    // If the write callback failed, propagate the error.
    let v = match write_result {
        Ok(v) => v,
        Err(write_error) => {
            // Remove the temporary file.
            let _ = tokio::fs::remove_file(&temp_file_path).await;
            return Err(CleanFileCreationError::CallbackIndicatedError(write_error));
        }
    };

    // Everything seems to have worked out. The file has been written to successfully.
    // Rename it to its final path.
    match tokio::fs::rename(&temp_file_path, dest_path).await {
        Ok(_) => Ok(v),
        Err(rename_error) => {
            // Renaming failed; remove the temporary file.
            let _ = tokio::fs::remove_file(&temp_file_path).await;
            Err(CleanFileCreationError::RenameError(rename_error))
        }
    }
}
