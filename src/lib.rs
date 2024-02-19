//! # symsrv
//!
//! This crate lets you download and cache symbol files from symbol servers,
//! according to the rules from the `_NT_SYMBOL_PATH` environment variable.
//!
//! It exposes an async API and uses `reqwest` and `tokio::fs`.
//!
//! The downloaded symbols are stored and never evicted.
//!
//! ## Microsoft Documentation
//!
//! - [Advanced SymSrv Use](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use)
//!
//! ## Example
//!
//! ```
//! use std::path::PathBuf;
//! use symsrv::{get_default_downstream_store, get_symbol_path_from_environment, SymsrvDownloader};
//!
//! # fn open_pdb_at_path(p: &std::path::Path) {}
//! #
//! # async fn wrapper() -> Result<(), symsrv::Error> {
//! // Parse the _NT_SYMBOL_PATH environment variable.
//! let symbol_path =
//!     get_symbol_path_from_environment("srv**https://msdl.microsoft.com/download/symbols");
//!
//! // Create a symbol cache which follows the _NT_SYMBOL_PATH recipe.
//! let default_downstream = get_default_downstream_store(); // "~/sym"
//! let symbol_cache = SymsrvDownloader::new(symbol_path, default_downstream.as_deref(), None);
//!
//! // Download and cache a PDB file.
//! let local_path = symbol_cache.get_file("dcomp.pdb", "648B8DD0780A4E22FA7FA89B84633C231").await?;
//!
//! // Use the PDB file.
//! open_pdb_at_path(&local_path);
//! # Ok(())
//! # }
//! ```

mod download;
mod file_creation;
mod poll_all;

use std::io::BufReader;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use async_compat::CompatExt;
use file_creation::{create_file_cleanly, CleanFileCreationError};
use poll_all::PollAllPreservingOrder;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

use crate::download::response_to_uncompressed_stream_with_progress;

/// The parsed representation of one entry in the (semicolon-separated list of entries in the) `_NT_SYMBOL_PATH` environment variable.
/// The syntax of this string is documented at <https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use>.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NtSymbolPathEntry {
    /// Sets a cache path that will be used for subsequent entries, and for any symbol paths that get added at runtime.
    /// Created for `cache*` entries.
    Cache(PathBuf),
    /// A fallback-and-cache chain with optional http / https symbol servers at the end.
    /// Created for `srv*` and `symsrv*` entries.
    Chain {
        /// Usually `symsrv.dll`. (`srv*...` is shorthand for `symsrv*symsrv.dll*...`.)
        dll: String,
        /// Any cache directories. The first directory is the "bottom-most" cache, and is always
        // checked first, and always stores uncompressed files.
        /// Any remaining directories are mid-level cache directories. These can store compressed files.
        cache_paths: Vec<CachePath>,
        /// Symbol server URLs. Can serve compressed or uncompressed files. Not used as a cache target.
        /// These are checked last.
        urls: Vec<String>,
    },
    /// A path where symbols can be found but which is not used as a cache target.
    /// Created for entries which are just a path.
    LocalOrShare(PathBuf),
}

/// A regular cache directory or a marker for the "default downstream store".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CachePath {
    /// A placeholder for the directory of the "default downstream store". This is used
    /// for empty cache items in the `_NT_SYMBOL_PATH`, e.g. if you have a `srv**URL` with
    /// two asterisks right after each other.
    DefaultDownstreamStore,

    /// The path to a directory where this cache is located.
    Path(PathBuf),
}

impl CachePath {
    pub fn to_path<'a>(&'a self, default_downstream_store: &'a Path) -> &'a Path {
        match self {
            CachePath::DefaultDownstreamStore => default_downstream_store,
            CachePath::Path(path) => path,
        }
    }
}

/// Currently returns ~/sym.
pub fn get_default_downstream_store() -> Option<PathBuf> {
    // The Windows Debugger chooses the default downstream store as follows (see
    // <https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use>):
    // > If you include two asterisks in a row where a downstream store would normally be specified,
    // > then the default downstream store is used. This store will be located in the sym subdirectory
    // > of the home directory. The home directory defaults to the debugger installation directory;
    // > this can be changed by using the !homedir extension or by setting the DBGHELP_HOMEDIR
    // > environment variable.
    //
    // Let's ignore the part about the "debugger installation directory" and put the default
    // store at ~/sym.
    let home_dir = dirs::home_dir()?;
    Some(home_dir.join("sym"))
}

/// Reads the `_NT_SYMBOL_PATH` environment variable and parses it.
/// The parsed path entries use ~/sym as the default downstream store.
pub fn get_symbol_path_from_environment(fallback_if_unset: &str) -> Vec<NtSymbolPathEntry> {
    parse_nt_symbol_path(
        std::env::var("_NT_SYMBOL_PATH")
            .ok()
            .as_deref()
            .unwrap_or(fallback_if_unset),
    )
}

/// Parse the value of the `_NT_SYMBOL_PATH` variable. The format of this variable
/// is a semicolon-separated list of entries, where each entry is an asterisk-separated
/// hierarchy of symbol locations which can be either directories or server URLs.
pub fn parse_nt_symbol_path(symbol_path: &str) -> Vec<NtSymbolPathEntry> {
    fn chain<'a>(dll_name: &str, parts: impl Iterator<Item = &'a str>) -> NtSymbolPathEntry {
        let mut cache_paths = Vec::new();
        let mut urls = Vec::new();
        for part in parts {
            if part.is_empty() {
                cache_paths.push(CachePath::DefaultDownstreamStore);
            } else if part.starts_with("http://") || part.starts_with("https://") {
                urls.push(part.into());
            } else {
                cache_paths.push(CachePath::Path(part.into()));
            }
        }
        NtSymbolPathEntry::Chain {
            dll: dll_name.to_string(),
            cache_paths,
            urls,
        }
    }

    symbol_path
        .split(';')
        .filter_map(|segment| {
            let mut parts = segment.split('*');
            let first = parts.next().unwrap();
            match first.to_ascii_lowercase().as_str() {
                "cache" => parts
                    .next()
                    .map(|path| NtSymbolPathEntry::Cache(path.into())),
                "srv" => Some(chain("symsrv.dll", parts)),
                "symsrv" => parts.next().map(|dll_name| chain(dll_name, parts)),
                _ => Some(NtSymbolPathEntry::LocalOrShare(first.into())),
            }
        })
        .collect()
}

/// The error type used in this crate.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// There was an error when interacting with the file system.
    #[error("IO error: {0}")]
    IoError(#[source] std::io::Error),

    /// The requested file was not found.
    #[error("The file was not found in the SymsrvDownloader.")]
    NotFound,

    /// No default downstream store was specified, but it was needed.
    #[error("No default downstream store was specified, but it was needed.")]
    NoDefaultDownstreamStore,

    /// The requested path does not have a file extension.
    #[error("The requested path does not have a file extension.")]
    NoExtension,

    /// The requested path does not have a recognized file extension.
    #[error("The requested path does not have a recognized file extension (exe/dll/pdb/dbg).")]
    UnrecognizedExtension,

    /// An internal error occurred: Couldn't join task
    #[error("An internal error occurred: Couldn't join task")]
    JoinError(#[from] tokio::task::JoinError),

    /// Generic error from `reqwest`.
    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] reqwest::Error),

    /// Unexpected Content-Encoding header.
    #[error("Unexpected Content-Encoding header: {0}")]
    UnexpectedContentEncoding(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<CleanFileCreationError<Error>> for Error {
    fn from(e: CleanFileCreationError<Error>) -> Error {
        match e {
            CleanFileCreationError::CallbackIndicatedError(e) => e,
            e => Error::IoError(e.into()),
        }
    }
}

/// The error type used in the observer notification [`SymsrvObserver::on_download_failed`].
#[derive(thiserror::Error, Debug)]
pub enum DownloadError {
    /// Opening the request failed.
    #[error("Opening the request failed")]
    OpenFailed,

    /// The download timed out.
    #[error("The download timed out")]
    Timeout,

    /// The server returned a non-success status code.
    #[error("The server returned status code {0}")]
    StatusError(http::StatusCode),

    /// The destination directory could not be created.
    #[error("The destination directory could not be created")]
    CouldNotCreateDestinationDirectory,

    /// The response used an unexpected Content-Encoding.
    #[error("The response used an unexpected Content-Encoding: {0}")]
    UnexpectedContentEncoding(String),

    /// An I/O error occurred in the middle of downloading.
    #[error("Error during downloading: {0}")]
    ErrorDuringDownloading(std::io::Error),

    /// Error while writing the downloaded file.
    #[error("Error while writing the downloaded file: {0}")]
    ErrorWhileWritingDownloadedFile(std::io::Error),

    /// Redirect-related error.
    #[error("Redirect-related error")]
    Redirect(Box<dyn std::error::Error + Send + Sync>),

    /// Other error.
    #[error("Other error: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

#[cfg(test)]
#[test]
fn test_download_error_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<DownloadError>();
}

impl From<reqwest::Error> for DownloadError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_status() {
            DownloadError::StatusError(e.status().unwrap())
        } else if e.is_request() {
            DownloadError::OpenFailed
        } else if e.is_redirect() {
            DownloadError::Redirect(e.into())
        } else if e.is_timeout() {
            DownloadError::Timeout
        } else {
            DownloadError::Other(e.into())
        }
    }
}

/// A trait for observing the behavior of a `SymsrvDownloader`.
/// This can be used for logging, displaying progress bars, expiring cached files, etc.
pub trait SymsrvObserver {
    /// Called when a new download is about to start, before the connection is established.
    ///
    /// The download ID is unique for each download.
    ///
    /// For each download ID, we guarantee that exactly one of the following methods
    /// will be called at the end of the download: `on_download_completed`,
    /// `on_download_failed`, or `on_download_canceled`.
    fn on_new_download_before_connect(&self, download_id: u64, url: &str);

    /// Called once the connection has been established and HTTP headers
    /// with a success status have arrived.
    fn on_download_started(&self, download_id: u64);

    /// Called frequently during the download, whenever a new chunk has been read.
    ///
    /// If the HTTP response is gzip-compressed, the number of bytes can refer to
    /// either the compressed or the uncompressed bytes - but it'll be consistent:
    /// Either both `bytes_so_far` and `total_bytes` refer to the compressed sizes,
    /// or both refer to the uncompressed sizes.
    ///
    /// If `total_bytes` is `None`, the total size is unknown.
    fn on_download_progress(&self, download_id: u64, bytes_so_far: u64, total_bytes: Option<u64>);

    /// Called when the download has completed successfully.
    ///
    /// Mutually exclusive with `on_download_failed` and `on_download_canceled` for a
    /// given download ID.
    fn on_download_completed(
        &self,
        download_id: u64,
        uncompressed_size_in_bytes: u64,
        time_until_headers: Duration,
        time_until_completed: Duration,
    );

    /// Called when the download has failed.
    ///
    /// This is quite common; the most common reason is [`DownloadError::StatusError`]
    /// with [`StatusCode::NOT_FOUND`](http::StatusCode::NOT_FOUND), for files which
    /// are not available on the server.
    ///
    /// Mutually exclusive with `on_download_completed` and `on_download_canceled` for a
    /// given download ID.
    fn on_download_failed(&self, download_id: u64, reason: DownloadError);

    /// Called when the download has been canceled.
    ///
    /// This does not indicate an error. We commonly attempt to download a file from
    /// multiple sources simultaneously, and cancel other downloads once one has succeeded.
    ///
    /// This function is also called if the user cancels the download by dropping the future
    /// returned from [`SymsrvDownloader::get_file`].
    ///
    /// Mutually exclusive with `on_download_completed` and `on_download_failed` for a
    /// given download ID.
    fn on_download_canceled(&self, download_id: u64);

    /// Called when a file has been created, for example because it was downloaded from
    /// a server, copied from a different cache directory, or extracted from a compressed
    /// file.
    fn on_file_created(&self, path: &Path, size_in_bytes: u64);

    /// Called when a file from the cache has been used to service a [`SymsrvDownloader::get_file`] call.
    ///
    /// This is only called for pre-existing files and not for newly-created files - newly-created
    /// files only trigger a call to `on_file_created`.
    ///
    /// Useful to guide expiration decisions.
    fn on_file_accessed(&self, path: &Path);

    /// Called when we were looking for a file in the cache, and it wasn't there. Used for
    /// debug logging.
    ///
    /// Also called if checking for file existence fails for any other reason.
    fn on_file_missed(&self, path: &Path);
}

static NEXT_DOWNLOAD_ID: AtomicU64 = AtomicU64::new(0);

/// Obtains symbols according to the instructions in the symbol path.
pub struct SymsrvDownloader {
    symbol_path: Vec<NtSymbolPathEntry>,
    default_downstream_store: Option<PathBuf>,
    observer: Option<Arc<dyn SymsrvObserver>>,
    client: reqwest::Client,
}

impl SymsrvDownloader {
    /// Create a new `SymsrvDownloader`.
    pub fn new(
        symbol_path: Vec<NtSymbolPathEntry>,
        default_downstream_store: Option<&Path>,
        observer: Option<Arc<dyn SymsrvObserver>>,
    ) -> Self {
        let builder = reqwest::Client::builder();

        // Turn off HTTP 2, in order to work around https://github.com/seanmonstar/reqwest/issues/1761 .
        let builder = builder.http1_only();

        // Turn off automatic decompression because it doesn't allow us to compute
        // download progress percentages: we'd only know the decompressed current
        // size and the compressed total size.
        // Instead, we do the streaming decompression manually, see download.rs.
        let builder = builder.no_gzip().no_brotli().no_deflate();

        // Create the client.
        // TODO: Add timeouts, user agent, maybe other settings
        // TODO: Propagate error
        let client = builder.build().unwrap();

        Self {
            symbol_path,
            default_downstream_store: default_downstream_store.map(ToOwned::to_owned),
            observer,
            client,
        }
    }

    /// This is the primary entry point to fetch symbols. Looks up the
    /// file according to the recipe in the symbol path, by searching
    /// cache directories, downloading symbols from servers, and uncompressing files
    /// as needed.
    ///
    /// If a matching file is found, a [`PathBuf`] to the uncompressed file on the local
    /// file system is returned.
    ///
    /// The file name can be the name of a PDB file or of a binary file (i.e. .exe or .dll).
    ///
    /// The syntax of the hash depends on the file type:
    ///
    ///  - For PDBs: The hash is `<GUID><age>`, with `<GUID>` in uppercase hex (no dashes)
    ///    and `<age>` in lowercase hex.
    ///  - For binaries: The hash is `<TIMESTAMP><imageSize>`, with `<TIMESTAMP>`
    ///    printed as eight uppercase hex digits (with leading zeros added as needed)
    ///    and `<imageSize>` in lowercase hex digits (no leading zeros).
    ///
    /// Examples:
    ///
    /// - `xul.pdb`, `B2A2B092E45739B84C4C44205044422E1`
    /// - `renderdoc.dll`, `61015E74442b000`
    ///
    /// The PDB hash is commonly created with the help of the `debugid` crate,
    /// using [`DebugId::breakpad()`](https://docs.rs/debugid/latest/debugid/struct.DebugId.html#method.breakpad).
    ///
    /// The binary hash (the "code ID") can be created using
    /// [`wholesym::PeCodeId`](https://docs.rs/wholesym/latest/wholesym/struct.PeCodeId.html).
    pub async fn get_file(&self, filename: &str, hash: &str) -> Result<PathBuf, Error> {
        self.get_file_impl(filename, hash, true).await
    }

    /// Same as [`get_file`](Self::get_file), but only checks cache directories.
    /// No downloads are attempted.
    pub async fn get_file_no_download(&self, filename: &str, hash: &str) -> Result<PathBuf, Error> {
        self.get_file_impl(filename, hash, false).await
    }

    pub async fn get_file_impl(
        &self,
        filename: &str,
        hash: &str,
        allow_downloads: bool,
    ) -> Result<PathBuf, Error> {
        let path: PathBuf = [filename, hash, filename].iter().collect();
        let rel_path_uncompressed = &path;
        let rel_path_compressed = create_compressed_path(rel_path_uncompressed)?;

        // This array will contain cache paths from `cache*` entries. These get added
        // once they are encountered. Once encountered, they apply to all subsequent
        // entries.
        let mut persisted_cache_paths: Vec<CachePath> = Vec::new();

        // Iterate all entries in the symbol path, checking them for matches one by one.
        for entry in &self.symbol_path {
            match entry {
                NtSymbolPathEntry::Cache(cache_dir) => {
                    let cache_path = CachePath::Path(cache_dir.into());
                    if persisted_cache_paths.contains(&cache_path) {
                        continue;
                    }

                    // Check if the symbol file is present in this cache. If found, also persist
                    // it to the previous cache paths.
                    if let Some(found_path) = self
                        .check_directory(
                            cache_dir,
                            &persisted_cache_paths,
                            rel_path_uncompressed,
                            &rel_path_compressed,
                        )
                        .await?
                    {
                        return Ok(found_path);
                    }

                    // Add this path to `persisted_cache_paths` so that any matches in the
                    // upcoming entries can be persisted to this cache.
                    persisted_cache_paths.push(cache_path);
                }
                NtSymbolPathEntry::Chain {
                    cache_paths, urls, ..
                } => {
                    // If the symbol file is found, it should also be persisted (copied) to all
                    // of these paths.
                    let mut parent_cache_paths = persisted_cache_paths.clone();

                    for cache_path in cache_paths {
                        if parent_cache_paths.contains(cache_path) {
                            continue;
                        }
                        parent_cache_paths.push(cache_path.clone());

                        // Check if the symbol file is present at this path. If found, also persist
                        // it to the previous cache paths.
                        let (_, parent_cache_paths) = parent_cache_paths.split_last().unwrap();
                        if let Some(cache_dir) = self.resolve_cache_path(cache_path) {
                            if let Some(found_path) = self
                                .check_directory(
                                    cache_dir,
                                    parent_cache_paths,
                                    rel_path_uncompressed,
                                    &rel_path_compressed,
                                )
                                .await?
                            {
                                return Ok(found_path);
                            }
                        }
                    }

                    // The symbol file was not found in any of the cache paths. Try to download it
                    // from the server URLs in this entry.
                    if !allow_downloads {
                        // We're not allowed to download anything. Go to the next entry.
                        continue;
                    }

                    // First, make sure we have a place to download to.
                    let (download_dest_cache, remaining_caches) = parent_cache_paths
                        .split_last()
                        .unwrap_or((&CachePath::DefaultDownstreamStore, &[]));
                    let download_dest_cache_dir = self
                        .resolve_cache_path(download_dest_cache)
                        .ok_or(Error::NoDefaultDownstreamStore)?;
                    let bottom_cache = parent_cache_paths
                        .first()
                        .unwrap_or(&CachePath::DefaultDownstreamStore);

                    // Make a list of URLs to try. For each URL, we try both the uncompressed and
                    // compressed file, in that order.
                    let mut file_urls = Vec::with_capacity(urls.len() * 2);
                    for server_url in urls {
                        file_urls.push((
                            url_join(server_url, rel_path_uncompressed.components()),
                            rel_path_uncompressed,
                            false,
                        ));
                        file_urls.push((
                            url_join(server_url, rel_path_compressed.components()),
                            &rel_path_compressed,
                            true,
                        ));
                    }

                    // Prepare requests to all candidate URLs. We are not actually starting these requests
                    // yet because we're not calling poll on the futures until we hit the await call in the loop below.
                    let response_futures: Vec<_> = file_urls
                        .into_iter()
                        .map(|(file_url, rel_path, is_compressed)| async move {
                            (
                                self.prepare_download_of_file(&file_url).await,
                                rel_path,
                                is_compressed,
                            )
                        })
                        .map(Box::pin)
                        .collect();

                    // Download the symbol file from the candidate URLs we've computed. If successful, also persist
                    // the file to the previous cache paths.
                    let mut response_futures = PollAllPreservingOrder::new(response_futures);
                    while let Some(next_response) = response_futures.next().await {
                        let (prepared_response, rel_path, is_compressed) = next_response;
                        let Some((notifier, response)) = prepared_response else {
                            // The request failed. Try the next URL.
                            continue;
                        };

                        // If we get here, the response headers indicated a success HTTP status.
                        // Proceed to download the file.
                        let Some(dest_path) = self
                            .download_file_to_cache(
                                notifier,
                                response,
                                rel_path,
                                download_dest_cache_dir,
                            )
                            .await
                        else {
                            continue;
                        };

                        // We have a file!
                        let uncompressed_dest_path = if is_compressed {
                            if let Some((_remaining_bottom_cache, remaining_mid_level_caches)) =
                                remaining_caches.split_first()
                            {
                                // Save the compressed file to the mid-level caches.
                                self.copy_file_to_caches(
                                    &rel_path_compressed,
                                    &dest_path,
                                    remaining_mid_level_caches,
                                )
                                .await;
                            }
                            // Extract the file into the bottom cache.
                            self.extract_to_file_in_cache(
                                &dest_path,
                                rel_path_uncompressed,
                                bottom_cache,
                            )
                            .await?
                        } else {
                            // The file is not compressed. Just copy to the other caches.
                            self.copy_file_to_caches(
                                rel_path_uncompressed,
                                &dest_path,
                                remaining_caches,
                            )
                            .await;
                            dest_path
                        };
                        return Ok(uncompressed_dest_path);
                    }
                }
                NtSymbolPathEntry::LocalOrShare(dir_path) => {
                    if persisted_cache_paths.contains(&CachePath::Path(dir_path.into())) {
                        continue;
                    }

                    // Check if the symbol file is present at this path. If found, also persist
                    // it to the previous cache paths.
                    if let Some(found_path) = self
                        .check_directory(
                            dir_path,
                            &persisted_cache_paths,
                            rel_path_uncompressed,
                            &rel_path_compressed,
                        )
                        .await?
                    {
                        return Ok(found_path);
                    };
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return whether a file is found at `path`, and notify the observer if not.
    async fn check_file_exists(&self, path: &Path) -> bool {
        let file_exists = matches!(tokio::fs::metadata(path).await, Ok(meta) if meta.is_file());
        if !file_exists {
            if let Some(observer) = self.observer.as_deref() {
                observer.on_file_missed(path);
            }
        }
        file_exists
    }

    fn resolve_cache_path<'a>(&'a self, cache_path: &'a CachePath) -> Option<&'a Path> {
        match cache_path {
            CachePath::Path(path) => Some(path),
            CachePath::DefaultDownstreamStore => self.default_downstream_store.as_deref(),
        }
    }

    /// Attempt to find the file on the local file system. This is done first, before any downloading
    /// is attempted. If a file is found, it is copied into the caches given by `parent_cache_paths`
    /// and uncompressed if needed. On success, the bottom-most cache in `parent_cache_paths` (i.e.
    /// the first entry) will always have the uncompressed file, and the other caches with have
    /// whichever file was found in `dir`.
    async fn check_directory(
        &self,
        dir: &Path,
        parent_cache_paths: &[CachePath],
        rel_path_uncompressed: &Path,
        rel_path_compressed: &Path,
    ) -> Result<Option<PathBuf>, Error> {
        let full_candidate_path = dir.join(rel_path_uncompressed);
        let full_candidate_path_compr = dir.join(rel_path_compressed);

        let (abs_path, is_compressed) = if self.check_file_exists(&full_candidate_path).await {
            (full_candidate_path, false)
        } else if self.check_file_exists(&full_candidate_path_compr).await {
            (full_candidate_path_compr, true)
        } else {
            return Ok(None);
        };

        // We found a file. Yay!

        if let Some(observer) = self.observer.as_deref() {
            observer.on_file_accessed(&abs_path);
        }

        let uncompressed_path = if is_compressed {
            if let Some((bottom_most_cache, mid_level_caches)) = parent_cache_paths.split_first() {
                // We have at least one cache, and the file is compressed.
                // Copy the compressed file to the mid-level caches, and uncompress the file
                // into the bottom-most cache.
                self.copy_file_to_caches(rel_path_compressed, &abs_path, mid_level_caches)
                    .await;
                self.extract_to_file_in_cache(&abs_path, rel_path_uncompressed, bottom_most_cache)
                    .await?
            } else {
                // We have no cache. Extract it into the default downstream cache.
                self.extract_to_file_in_cache(
                    &abs_path,
                    rel_path_uncompressed,
                    &CachePath::DefaultDownstreamStore,
                )
                .await?
            }
        } else {
            abs_path
        };

        Ok(Some(uncompressed_path))
    }

    /// Copy the file at `abs_path` to the cache directories given by `caches`, using
    /// `rel_path` to create the correct destination path for each cache.
    async fn copy_file_to_caches(&self, rel_path: &Path, abs_path: &Path, caches: &[CachePath]) {
        for cache_path in caches {
            if let Some(cache_dir) = self.resolve_cache_path(cache_path) {
                if let Ok(dest_path) = self
                    .make_dest_path_and_ensure_parent_dirs(rel_path, cache_dir)
                    .await
                {
                    // TODO: Check what happens if this process dies in the middle of copying
                    // - do we leave a half-copied file behind? Should we use `create_file_cleanly`?
                    if let Ok(copied_bytes) = tokio::fs::copy(&abs_path, &dest_path).await {
                        if let Some(observer) = self.observer.as_deref() {
                            observer.on_file_created(&dest_path, copied_bytes);
                        }
                    }
                }
            }
        }
    }

    /// Given a relative file path and a cache directory path, concatenate the two to make
    /// a destination path, and create the necessary directories so that a file can be stored
    /// at the destination path.
    async fn make_dest_path_and_ensure_parent_dirs(
        &self,
        rel_path: &Path,
        cache_path: &Path,
    ) -> Result<PathBuf, std::io::Error> {
        let dest_path = cache_path.join(rel_path);
        if let Some(dir) = dest_path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        Ok(dest_path)
    }

    /// Uncompress the cab-compressed `bytes` and store the result in a cache
    /// directory.
    async fn extract_to_file_in_cache(
        &self,
        compressed_input_path: &Path,
        rel_path: &Path,
        cache_path: &CachePath,
    ) -> Result<PathBuf, Error> {
        let cache_path = self
            .resolve_cache_path(cache_path)
            .ok_or(Error::NoDefaultDownstreamStore)?;
        let dest_path = self
            .make_dest_path_and_ensure_parent_dirs(rel_path, cache_path)
            .await?;
        let compressed_input_path = compressed_input_path.to_owned();

        let extracted_size = create_file_cleanly(&dest_path, |dest_file: tokio::fs::File| async {
            {
                let mut dest_file = dest_file.into_std().await;
                tokio::task::spawn_blocking(move || -> std::result::Result<u64, Error> {
                    let file = std::fs::File::open(&compressed_input_path)?;
                    let buf_read = BufReader::new(file);

                    let mut cabinet = cab::Cabinet::new(buf_read)?;
                    let file_name_in_cab = {
                        // Only pick the first file we encounter. That's the PDB.
                        let folder = cabinet.folder_entries().next().unwrap();
                        let file = folder.file_entries().next().unwrap();
                        file.name().to_string()
                    };
                    let mut reader = cabinet.read_file(&file_name_in_cab)?;
                    let bytes_written = std::io::copy(&mut reader, &mut dest_file)?;
                    Ok(bytes_written)
                })
                .await
                .expect("task panicked")
            }
        })
        .await?;

        if let Some(observer) = self.observer.as_deref() {
            observer.on_file_created(&dest_path, extracted_size);
        }
        Ok(dest_path)
    }

    async fn prepare_download_of_file(
        &self,
        url: &str,
    ) -> Option<(DownloadStatusReporter, reqwest::Response)> {
        let download_id = NEXT_DOWNLOAD_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(observer) = self.observer.as_deref() {
            observer.on_new_download_before_connect(download_id, url);
        }

        let reporter = DownloadStatusReporter::new(download_id, self.observer.clone());

        let request_builder = self.client.get(url);

        // Manually specify the Accept-Encoding header.
        // This would happen automatically if we hadn't turned off automatic
        // decompression for this reqwest client.
        let request_builder = request_builder.header("Accept-Encoding", "gzip");

        // Send the request and wait for the headers.
        let response_result = request_builder.send().await;

        // Check the HTTP status code.
        let response_result = response_result.and_then(|response| response.error_for_status());

        let response = match response_result {
            Ok(response) => response,
            Err(e) => {
                // The request failed, most commonly due to a 404 status code.
                reporter.download_failed(DownloadError::from(e));
                return None;
            }
        };

        Some((reporter, response))
    }

    /// Download the file at `url` into memory.
    async fn download_file_to_cache(
        &self,
        reporter: DownloadStatusReporter,
        response: reqwest::Response,
        rel_path: &Path,
        cache_dir: &Path,
    ) -> Option<PathBuf> {
        // We have a response with a success status code.
        let ts_after_status = Instant::now();
        let download_id = reporter.download_id();
        if let Some(observer) = self.observer.as_deref() {
            observer.on_download_started(download_id);
        }

        let dest_path = match self
            .make_dest_path_and_ensure_parent_dirs(rel_path, cache_dir)
            .await
        {
            Ok(dest_path) => dest_path,
            Err(_e) => {
                reporter.download_failed(DownloadError::CouldNotCreateDestinationDirectory);
                return None;
            }
        };

        let observer = self.observer.clone();
        let mut stream = match response_to_uncompressed_stream_with_progress(
            response,
            move |bytes_so_far, total_bytes| {
                if let Some(observer) = observer.as_deref() {
                    observer.on_download_progress(download_id, bytes_so_far, total_bytes)
                }
            },
        ) {
            Ok(stream) => stream,
            Err(download::Error::UnexpectedContentEncoding(encoding)) => {
                reporter.download_failed(DownloadError::UnexpectedContentEncoding(encoding));
                return None;
            }
        };

        let download_result: Result<u64, CleanFileCreationError<std::io::Error>> =
            create_file_cleanly(&dest_path, |mut dest_file: tokio::fs::File| async move {
                let uncompressed_size_in_bytes =
                    futures::io::copy(&mut stream, &mut dest_file.compat_mut()).await?;
                dest_file.flush().await?;
                Ok(uncompressed_size_in_bytes)
            })
            .await;

        let uncompressed_size_in_bytes = match download_result {
            Ok(size) => size,
            Err(CleanFileCreationError::CallbackIndicatedError(e)) => {
                reporter.download_failed(DownloadError::ErrorDuringDownloading(e));
                return None;
            }
            Err(e) => {
                reporter.download_failed(DownloadError::ErrorWhileWritingDownloadedFile(e.into()));
                return None;
            }
        };

        let ts_after_download = Instant::now();
        reporter.download_completed(
            uncompressed_size_in_bytes,
            ts_after_status,
            ts_after_download,
        );

        if let Some(observer) = self.observer.as_deref() {
            observer.on_file_created(&dest_path, uncompressed_size_in_bytes);
        }

        Some(dest_path)
    }
}

/// Convert a relative `Path` into a URL by appending the components to the
/// given base URL.
fn url_join(base_url: &str, components: std::path::Components) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        components
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    )
}

/// From a path to the uncompressed exe/dll/pdb file, create the path to the
/// compressed file, by replacing the last char of the file extension with
/// an underscore. These files are cab-compressed.
fn create_compressed_path(uncompressed_path: &Path) -> Result<PathBuf, Error> {
    let uncompressed_ext = match uncompressed_path.extension() {
        Some(ext) => match ext.to_string_lossy().deref() {
            "exe" => "ex_",
            "dll" => "dl_",
            "pdb" => "pd_",
            "dbg" => "db_",
            _ => return Err(Error::UnrecognizedExtension),
        },
        None => return Err(Error::NoExtension),
    };

    let mut compressed_path = uncompressed_path.to_owned();
    compressed_path.set_extension(uncompressed_ext);
    Ok(compressed_path)
}

/// A helper struct with a drop handler. This lets us detect when a download
/// is cancelled by dropping the future.
struct DownloadStatusReporter {
    /// Set to `None` when `download_failed()` or `download_completed()` is called.
    download_id: Option<u64>,
    observer: Option<Arc<dyn SymsrvObserver>>,
    ts_before_connect: Instant,
}

impl DownloadStatusReporter {
    pub fn new(download_id: u64, observer: Option<Arc<dyn SymsrvObserver>>) -> Self {
        Self {
            download_id: Some(download_id),
            observer,
            ts_before_connect: Instant::now(),
        }
    }

    pub fn download_id(&self) -> u64 {
        self.download_id.unwrap()
    }

    pub fn download_failed(mut self, e: DownloadError) {
        if let (Some(download_id), Some(observer)) = (self.download_id, self.observer.as_deref()) {
            observer.on_download_failed(download_id, e);
        }
        self.download_id = None;
        // Drop self. Now the Drop handler won't do anything.
    }

    pub fn download_completed(
        mut self,
        uncompressed_size_in_bytes: u64,
        ts_after_headers: Instant,
        ts_after_completed: Instant,
    ) {
        if let (Some(download_id), Some(observer)) = (self.download_id, self.observer.as_deref()) {
            let time_until_headers = ts_after_headers.duration_since(self.ts_before_connect);
            let time_until_completed = ts_after_completed.duration_since(self.ts_before_connect);
            observer.on_download_completed(
                download_id,
                uncompressed_size_in_bytes,
                time_until_headers,
                time_until_completed,
            );
        }
        self.download_id = None;
        // Drop self. Now the Drop handler won't do anything.
    }
}

impl Drop for DownloadStatusReporter {
    fn drop(&mut self) {
        if let (Some(download_id), Some(observer)) = (self.download_id, self.observer.as_deref()) {
            // We were dropped before a call to `download_failed` or `download_completed`.
            // This was most likely because the future we were stored in was dropped.
            // Tell the observer.
            observer.on_download_canceled(download_id);
        }
    }
}
