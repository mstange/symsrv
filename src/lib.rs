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
//! use symsrv::{get_default_downstream_store, get_symbol_path_from_environment, SymbolCache};
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
//! let symbol_cache = SymbolCache::new(symbol_path, default_downstream.as_deref(), false);
//!
//! // Download and cache a PDB file.
//! let relative_path: PathBuf =
//!     ["dcomp.pdb", "648B8DD0780A4E22FA7FA89B84633C231", "dcomp.pdb"].iter().collect();
//! let local_path = symbol_cache.get_file(&relative_path).await?;
//!
//! // Use the PDB file.
//! open_pdb_at_path(&local_path);
//! # Ok(())
//! # }
//! ```

use std::io::BufReader;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

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
    pub fn try_to_path<'a>(
        &'a self,
        default_downstream_store: Option<&'a Path>,
    ) -> Option<&'a Path> {
        match self {
            CachePath::DefaultDownstreamStore => default_downstream_store,
            CachePath::Path(path) => Some(path),
        }
    }

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
    #[error("The file was not found in the SymbolCache.")]
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
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

/// Obtains symbols according to the instructions in the symbol path.
pub struct SymbolCache {
    symbol_path: Vec<NtSymbolPathEntry>,
    verbose: bool,
    default_downstream_store: Option<PathBuf>,
}

impl SymbolCache {
    /// Create a new `SymbolCache`. If `verbose` is set to `true`, log messages
    /// will be printed to stderr.
    pub fn new(
        symbol_path: Vec<NtSymbolPathEntry>,
        default_downstream_store: Option<&Path>,
        verbose: bool,
    ) -> Self {
        Self {
            symbol_path,
            verbose,
            default_downstream_store: default_downstream_store.map(ToOwned::to_owned),
        }
    }

    /// This is the primary entry point to fetch symbols. It takes a relative
    /// `path` of the form `name.pdb\HEX\name.pdb`, and then looks up the
    /// file according to the recipe of this `SymbolCache`. That means it searches
    /// cache directories, downloads symbols as needed, and uncompresses files
    /// as needed.
    ///
    /// If a matching file is found, a `PathBuf` to the uncompressed file on the local
    /// file system is returned.
    ///
    /// The path should be a relative path to a symbol file. The file can be a PDB
    /// file or a binary (exe / dll). The syntax of these paths is as follows:
    ///
    ///  - For PDBs: `<pdbName>\<GUID><age>\<pdbName>`, with `<GUID>` in uppercase
    ///    and `<age>` in lowercase hex.
    ///    Example: `xul.pdb\B2A2B092E45739B84C4C44205044422E1\xul.pdb`
    ///  - For binaries: `<peName>\<TIMESTAMP><imageSize>\<peName>`, with `<TIMESTAMP>`
    ///    printed as eight uppercase hex digits (with leading zeros added as needed)
    ///    and `<imageSize>` in lowercase hex digits with as many digits as needed.
    ///    Example: `renderdoc.dll\61015E74442b000\renderdoc.dll`
    pub async fn get_file(&self, path: &Path) -> Result<PathBuf, Error> {
        match self.get_file_impl(path).await {
            Ok(file_contents) => {
                if self.verbose {
                    eprintln!("Successfully obtained {path:?} from the symbol cache.");
                }
                Ok(file_contents)
            }
            Err(e) => {
                if self.verbose {
                    eprintln!("Encountered an error when trying to obtain {path:?} from the symbol cache: {e:?}");
                }
                Err(e)
            }
        }
    }

    /// This is the implementation of `get_file`.
    async fn get_file_impl(&self, rel_path_uncompressed: &Path) -> Result<PathBuf, Error> {
        let rel_path_compressed = create_compressed_path(rel_path_uncompressed)?;

        // The cache paths frome `cache*` entries, which apply to all subsequent
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
                        if let Some(cache_dir) =
                            cache_path.try_to_path(self.default_downstream_store.as_deref())
                        {
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

                    // Download the symbol file from the URL(s) in this entry. If found, also persist
                    // the file to the previous cache paths.
                    for url in urls {
                        if let Some(found_path) = self
                            .check_url(
                                url,
                                &parent_cache_paths,
                                rel_path_uncompressed,
                                &rel_path_compressed,
                            )
                            .await?
                        {
                            return Ok(found_path);
                        }
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

    /// Return whether a file is found at `path`, and perform some logging if `self.verbose` is `true`.
    async fn check_file_exists(&self, path: &Path) -> bool {
        match tokio::fs::metadata(path).await {
            Ok(meta) if meta.is_file() => {
                if self.verbose {
                    eprintln!("Checking if {} exists... yes", path.to_string_lossy());
                }
                true
            }
            _ => {
                if self.verbose {
                    eprintln!("Checking if {} exists... no", path.to_string_lossy());
                }
                false
            }
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

    /// Attempt to download a file from the given server. This tries both the compressed and
    /// the non-compressed file. If successful, the file is stored in all the cache directories.
    /// On success, the bottom cache always has the uncompressed file, and the other cache
    /// directories have whichever file was downloaded from the server.
    ///
    /// The return value is either an mmap view into the uncompressed file in the bottom-most
    /// cache, or, if no cache directories were given, a `Vec` of the uncompressed file bytes.
    ///
    /// Arguments:
    ///
    ///  - `url` is the base URL, to which the relative paths will be appended.
    ///  - `parent_cache_paths` is the list of cache directories, starting with the bottom-most cache.
    ///  - `rel_path_uncompressed` is the relative path to the uncompressed file.
    ///  - `rel_path_compressed` is the relative path to the compressed file.
    async fn check_url(
        &self,
        url: &str,
        parent_caches: &[CachePath],
        rel_path_uncompressed: &Path,
        rel_path_compressed: &Path,
    ) -> Result<Option<PathBuf>, Error> {
        let full_candidate_url = url_join(url, rel_path_uncompressed.components());
        let full_candidate_url_compr = url_join(url, rel_path_compressed.components());
        let (download_dest_cache, remaining_caches) = parent_caches
            .split_last()
            .unwrap_or((&CachePath::DefaultDownstreamStore, &[]));
        let (dest_path, is_compressed) = match self
            .download_file_to_cache(
                &full_candidate_url_compr,
                rel_path_compressed,
                download_dest_cache,
            )
            .await
        {
            Ok(dest_path) => (dest_path, true),
            Err(_) => match self
                .download_file_to_cache(
                    &full_candidate_url,
                    rel_path_uncompressed,
                    download_dest_cache,
                )
                .await
            {
                Ok(dest_path) => (dest_path, false),
                Err(_) => return Ok(None),
            },
        };

        // We have a file!
        let uncompressed_dest_path = if is_compressed {
            if let Some((_remaining_bottom_cache, remaining_mid_level_caches)) =
                remaining_caches.split_first()
            {
                // Save the compressed file to the mid-level caches.
                self.copy_file_to_caches(
                    rel_path_compressed,
                    &dest_path,
                    remaining_mid_level_caches,
                )
                .await;
            }
            // Extract the file into the bottom cache.
            let bottom_cache = parent_caches
                .first()
                .unwrap_or(&CachePath::DefaultDownstreamStore);
            self.extract_to_file_in_cache(&dest_path, rel_path_uncompressed, bottom_cache)
                .await?
        } else {
            // The file is not compressed. Just copy to the other caches.
            self.copy_file_to_caches(rel_path_uncompressed, &dest_path, remaining_caches)
                .await;
            dest_path
        };
        Ok(Some(uncompressed_dest_path))
    }

    /// Copy the file at `abs_path` to the cache directories given by `caches`, using
    /// `rel_path` to create the correct destination path for each cache.
    async fn copy_file_to_caches(&self, rel_path: &Path, abs_path: &Path, caches: &[CachePath]) {
        for cache_path in caches {
            if let Some(cache_dir) =
                cache_path.try_to_path(self.default_downstream_store.as_deref())
            {
                if let Ok(dest_path) = self
                    .make_dest_path_and_ensure_parent_dirs(rel_path, cache_dir)
                    .await
                {
                    let _ = tokio::fs::copy(&abs_path, &dest_path).await;
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
    ) -> Result<PathBuf, Error> {
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
        let cache_path = cache_path
            .try_to_path(self.default_downstream_store.as_deref())
            .ok_or(Error::NoDefaultDownstreamStore)?;
        let dest_path = self
            .make_dest_path_and_ensure_parent_dirs(rel_path, cache_path)
            .await?;
        let compressed_input_path = compressed_input_path.to_owned();
        let verbose = self.verbose;

        tokio::spawn(async move {
            let file = std::fs::File::open(&compressed_input_path)?;
            let buf_read = BufReader::new(file);

            let mut cabinet = cab::Cabinet::new(buf_read)?;
            let file_name_in_cab = {
                // Only pick the first file we encounter. That's the PDB.
                let folder = cabinet.folder_entries().next().unwrap();
                let file = folder.file_entries().next().unwrap();
                file.name().to_string()
            };
            if verbose {
                eprintln!("Extracting {file_name_in_cab:?} from cab file {compressed_input_path:?} to file {dest_path:?}...");
            }
            let mut reader = cabinet.read_file(&file_name_in_cab)?;
            let mut dest_file = std::fs::File::create(&dest_path)?;
            std::io::copy(&mut reader, &mut dest_file)?;
            Ok(dest_path)
        }).await?
    }

    /// Download the file at `url` into memory.
    async fn download_file_to_cache(
        &self,
        url: &str,
        rel_path: &Path,
        cache: &CachePath,
    ) -> Result<PathBuf, Error> {
        let cache_path = cache
            .try_to_path(self.default_downstream_store.as_deref())
            .ok_or(Error::NoDefaultDownstreamStore)?;
        if self.verbose {
            eprintln!("Checking URL {url}...");
        }
        let response = reqwest::get(url).await?.error_for_status()?;

        // We have a response with a success error code.
        let dest_path = self
            .make_dest_path_and_ensure_parent_dirs(rel_path, cache_path)
            .await?;
        if self.verbose {
            eprintln!("Downloading file from {url} to {dest_path:?}...");
        }

        let mut stream = response.bytes_stream();

        let file = tokio::fs::File::create(&dest_path).await?;
        let mut writer = tokio::io::BufWriter::new(file);
        use futures_util::StreamExt;
        while let Some(item) = stream.next().await {
            let item = item?;
            let mut item_slice = item.as_ref();
            tokio::io::copy(&mut item_slice, &mut writer).await?;
        }
        writer.flush().await?;
        Ok(dest_path)
    }
}

/// Convert a relative `Path` into a URL by appending the components to the
/// given base URL.
fn url_join(base_url: &str, components: std::path::Components) -> String {
    format!(
        "{}/{}",
        base_url,
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
