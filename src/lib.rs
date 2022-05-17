//! # symsrv
//!
//! This crate lets you download and cache pdb files from symbol servers,
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
//! use symsrv::{get_symbol_path_from_environment, SymbolCache};
//!
//! # fn use_pdb_bytes(b: &[u8]) {}
//! #
//! # async fn wrapper() -> Result<(), symsrv::Error> {
//! // Parse the _NT_SYMBOL_PATH environment variable.
//! let symbol_path =
//!     get_symbol_path_from_environment("srv**https://msdl.microsoft.com/download/symbols");
//!
//! // Create a symbol cache which follows the _NT_SYMBOL_PATH recipe.
//! let symbol_cache = SymbolCache::new(symbol_path, false);
//!
//! // Download and cache a PDB file.
//! let relative_path: PathBuf =
//!     ["dcomp.pdb", "648B8DD0780A4E22FA7FA89B84633C231", "dcomp.pdb"].iter().collect();
//! let file_contents = symbol_cache.get_pdb(&relative_path).await?;
//!
//! // Use the PDB file contents.
//! use_pdb_bytes(&file_contents[..]);
//! # Ok(())
//! # }
//! ```

use std::ffi::OsStr;
use std::io::Cursor;
use std::path::{Path, PathBuf};

/// A re-export of the `bytes` crate, because this crate uses the type `Bytes`
/// in its public API.
pub use bytes;

/// A re-export of the `memmap2` crate, because this crate uses the type `Mmap`
/// in its public API.
pub use memmap2;

use bytes::Bytes;

/// This is how the symbol file contents are returned. If there's an uncompressed file
/// in the store, then we return an Mmap of that uncompressed file. If there is no
/// local file or the local file is compressed, then we load or uncompress the file
/// into memory and return a `Bytes` wrapper of that memory.
///
/// This type can be coerced to a [u8] slice with `&file_contents[..]`.
pub enum FileContents {
    /// A mapped file.
    Mmap(memmap2::Mmap),
    /// Bytes in memory.
    Bytes(Bytes),
}

impl std::ops::Deref for FileContents {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            FileContents::Mmap(mmap) => mmap,
            FileContents::Bytes(bytes) => bytes,
        }
    }
}

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
        cache_paths: Vec<PathBuf>,
        /// Symbol server URLs. Can serve compressed or uncompressed files. Not used as a cache target.
        /// These are checked last.
        urls: Vec<String>,
    },
    /// A path where symbols can be found but which is not used as a cache target.
    /// Created for entries which are just a path.
    LocalOrShare(PathBuf),
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
    dirs::home_dir().map(|home_dir| home_dir.join("sym"))
}

/// Reads the `_NT_SYMBOL_PATH` environment variable and parses it.
/// The parsed path entries use ~/sym as the default downstream store.
pub fn get_symbol_path_from_environment(fallback_if_unset: &str) -> Vec<NtSymbolPathEntry> {
    let default_downstream_store = get_default_downstream_store();
    if let Ok(symbol_path) = std::env::var("_NT_SYMBOL_PATH") {
        parse_nt_symbol_path(&symbol_path, default_downstream_store.as_deref())
    } else {
        parse_nt_symbol_path(fallback_if_unset, default_downstream_store.as_deref())
    }
}

/// Parse the value of the `_NT_SYMBOL_PATH` variable. The format of this variable
/// is a semicolon-separated list of entries, where each entry is an asterisk-separated
/// hierarchy of symbol locations which can be either directories or server URLs.
pub fn parse_nt_symbol_path(
    symbol_path: &str,
    default_downstream_store: Option<&Path>,
) -> Vec<NtSymbolPathEntry> {
    fn chain<'a>(
        dll_name: &str,
        parts: impl Iterator<Item = &'a str>,
        default_downstream_store: Option<&Path>,
    ) -> NtSymbolPathEntry {
        let mut cache_paths: Vec<PathBuf> = Vec::new();
        let mut urls: Vec<String> = Vec::new();
        for part in parts {
            if part.is_empty() {
                if let Some(default_downstream_store) = default_downstream_store {
                    cache_paths.push(default_downstream_store.into());
                }
            } else if part.starts_with("http://") || part.starts_with("https://") {
                urls.push(part.into());
            } else {
                cache_paths.push(part.into());
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
                "srv" => Some(chain("symsrv.dll", parts, default_downstream_store)),
                "symsrv" => parts
                    .next()
                    .map(|dll_name| chain(dll_name, parts, default_downstream_store)),
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
    #[error("The PDB was not found in the SymbolCache.")]
    NotFound,
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
}

impl SymbolCache {
    /// Create a new `SymbolCache`. If `verbose` is set to `true`, log messages
    /// will be printed to stderr.
    pub fn new(symbol_path: Vec<NtSymbolPathEntry>, verbose: bool) -> Self {
        Self {
            symbol_path,
            verbose,
        }
    }

    /// This is the primary entry point to fetch symbols. It takes a relative
    /// `path` of the form `name.pdb\HEX\name.pdb`, and then looks up the
    /// file according to the recipe of this `SymbolCache`. That means it searches
    /// cache directories, downloads symbols as needed, and uncompresses files
    /// as needed.
    pub async fn get_pdb(&self, path: &Path) -> Result<FileContents, Error> {
        match self.get_pdb_impl(path).await {
            Ok(file_contents) => {
                if self.verbose {
                    eprintln!("Successfully obtained {:?} from the symbol cache.", path);
                }
                Ok(file_contents)
            }
            Err(e) => {
                if self.verbose {
                    eprintln!("Encountered an error when trying to obtain {:?} from the symbol cache: {:?}", path, e);
                }
                Err(e)
            }
        }
    }

    /// `path` should be a path of the form firefox.pdb\HEX\firefox.pdb
    async fn get_pdb_impl(&self, rel_path_uncompressed: &Path) -> Result<FileContents, Error> {
        assert!(rel_path_uncompressed.extension() == Some(OsStr::new("pdb")));
        let mut rel_path_compressed = rel_path_uncompressed.to_owned();
        rel_path_compressed.set_extension("pd_");

        // The cache paths frome `cache*` entries, which apply to all subsequent
        // entries.
        let mut persisted_cache_paths: Vec<PathBuf> = Vec::new();

        // Iterate all entries in the symbol path, checking them for matches one by one.
        for entry in &self.symbol_path {
            match entry {
                NtSymbolPathEntry::Cache(cache_path) => {
                    if persisted_cache_paths.contains(cache_path) {
                        continue;
                    }

                    // Add this path to `persisted_cache_paths` so that any matches in the
                    // upcoming entries can be persisted to this cache.
                    persisted_cache_paths.push(cache_path.clone());

                    // Check if the symbol file is present in this cache. If found, also persist
                    // it to the previous cache paths.
                    let (_, parent_cache_paths) = persisted_cache_paths.split_last().unwrap();
                    if let Some(file_contents) = self
                        .check_directory(
                            cache_path,
                            parent_cache_paths,
                            rel_path_uncompressed,
                            &rel_path_compressed,
                        )
                        .await?
                    {
                        return Ok(file_contents);
                    };
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
                        if let Some(file_contents) = self
                            .check_directory(
                                cache_path,
                                parent_cache_paths,
                                rel_path_uncompressed,
                                &rel_path_compressed,
                            )
                            .await?
                        {
                            return Ok(file_contents);
                        };
                    }

                    // Download the symbol file from the URL(s) in this entry. If found, also persist
                    // the file to the previous cache paths.
                    for url in urls {
                        if let Some(file_contents) = self
                            .check_url(
                                url,
                                &parent_cache_paths,
                                rel_path_uncompressed,
                                &rel_path_compressed,
                            )
                            .await?
                        {
                            return Ok(file_contents);
                        }
                    }
                }
                NtSymbolPathEntry::LocalOrShare(dir_path) => {
                    if persisted_cache_paths.contains(dir_path) {
                        continue;
                    }

                    // Check if the symbol file is present at this path. If found, also persist
                    // it to the previous cache paths.
                    if let Some(file_contents) = self
                        .check_directory(
                            dir_path,
                            &persisted_cache_paths,
                            rel_path_uncompressed,
                            &rel_path_compressed,
                        )
                        .await?
                    {
                        return Ok(file_contents);
                    };
                }
            }
        }
        Err(Error::NotFound)
    }

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

    async fn check_directory(
        &self,
        dir: &Path,
        parent_cache_paths: &[PathBuf],
        rel_path_uncompressed: &Path,
        rel_path_compressed: &Path,
    ) -> Result<Option<FileContents>, Error> {
        let full_candidate_path = dir.join(rel_path_uncompressed);
        let full_candidate_path_compr = dir.join(&rel_path_compressed);

        let (abs_path, is_compressed) = if self.check_file_exists(&full_candidate_path).await {
            (full_candidate_path, false)
        } else if self.check_file_exists(&full_candidate_path_compr).await {
            (full_candidate_path_compr, true)
        } else {
            return Ok(None);
        };

        // We found a file. Yay!

        let uncompressed_path = if is_compressed {
            let file = tokio::fs::File::open(&abs_path).await?;
            let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
            if let Some((bottom_most_cache, mid_level_caches)) = parent_cache_paths.split_first() {
                // We have at least one cache, and the file is compressed.
                // Copy the compressed file to the mid-level caches, and uncompress the file
                // into the bottom-most cache.
                self.copy_file_to_caches(rel_path_compressed, &abs_path, mid_level_caches)
                    .await;
                self.extract_to_file_in_cache(&mmap[..], rel_path_uncompressed, bottom_most_cache)
                    .await?
            } else {
                // We have no cache. Extract it into memory.
                let vec = self.extract_into_memory(&mmap[..])?;
                return Ok(Some(FileContents::Bytes(Bytes::from(vec))));
            }
        } else {
            abs_path
        };

        let file = tokio::fs::File::open(&uncompressed_path).await?;
        Ok(Some(FileContents::Mmap(unsafe {
            memmap2::MmapOptions::new().map(&file)?
        })))
    }

    async fn check_url(
        &self,
        url: &str,
        parent_cache_paths: &[PathBuf],
        rel_path_uncompressed: &Path,
        rel_path_compressed: &Path,
    ) -> Result<Option<FileContents>, Error> {
        let full_candidate_url = url_join(url, rel_path_uncompressed.components());
        let full_candidate_url_compr = url_join(url, rel_path_compressed.components());
        let (bytes, is_compressed) = match self.get_bytes_from_url(&full_candidate_url_compr).await
        {
            Some(bytes) => (bytes, true),
            None => match self.get_bytes_from_url(&full_candidate_url).await {
                Some(bytes) => (bytes, false),
                None => return Ok(None),
            },
        };

        // We have a file!
        let file_contents = if is_compressed {
            if let Some((bottom_most_cache, mid_level_caches)) = parent_cache_paths.split_first() {
                // We have at least one cache, and the file is compressed.
                // Save the compressed file to the mid-level caches, and uncompress the file
                // into the bottom-most cache.
                if let Some((one_mid_level_cache, other_mid_level_caches)) =
                    mid_level_caches.split_first()
                {
                    if let Ok(abs_compressed_path) = self
                        .save_file_to_cache(&bytes[..], rel_path_compressed, one_mid_level_cache)
                        .await
                    {
                        let _ = self
                            .copy_file_to_caches(
                                rel_path_compressed,
                                &abs_compressed_path,
                                other_mid_level_caches,
                            )
                            .await;
                    }
                }
                let uncompressed_path = self
                    .extract_to_file_in_cache(&bytes[..], rel_path_uncompressed, bottom_most_cache)
                    .await?;
                let file = tokio::fs::File::open(&uncompressed_path).await?;
                FileContents::Mmap(unsafe { memmap2::MmapOptions::new().map(&file)? })
            } else {
                // We have no cache. Extract the bytes into memory.
                let vec = self.extract_into_memory(&bytes[..])?;
                FileContents::Bytes(Bytes::from(vec))
            }
        } else {
            // The file is not compressed. Just store.
            if let Some((bottom_most_cache, mid_level_caches)) = parent_cache_paths.split_first() {
                // We have at least one cache, and the file is NOT compressed.
                // Save the file to the bottom-most cache, and copy it into the mid-level caches.
                if let Ok(abs_compressed_path) = self
                    .save_file_to_cache(&bytes[..], rel_path_uncompressed, bottom_most_cache)
                    .await
                {
                    let _ = self
                        .copy_file_to_caches(
                            rel_path_uncompressed,
                            &abs_compressed_path,
                            mid_level_caches,
                        )
                        .await;
                }
            } else {
                // No caching. Don't do anything.
            }
            FileContents::Bytes(bytes)
        };
        Ok(Some(file_contents))
    }

    async fn copy_file_to_caches(&self, rel_path: &Path, abs_path: &Path, caches: &[PathBuf]) {
        for cache_path in caches {
            if let Ok(dest_path) = self
                .make_dest_path_and_ensure_parent_dirs(rel_path, cache_path)
                .await
            {
                let _ = tokio::fs::copy(&abs_path, &dest_path).await;
            }
        }
    }

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

    async fn save_file_to_cache(
        &self,
        bytes: &[u8],
        rel_path: &Path,
        cache_path: &Path,
    ) -> Result<PathBuf, Error> {
        let dest_path = self
            .make_dest_path_and_ensure_parent_dirs(rel_path, cache_path)
            .await?;

        let mut cursor = Cursor::new(bytes);
        if self.verbose {
            eprintln!("Saving bytes to {:?}.", dest_path);
        }
        let mut file = tokio::fs::File::create(&dest_path).await?;
        tokio::io::copy(&mut cursor, &mut file).await?;
        Ok(dest_path)
    }

    async fn extract_to_file_in_cache(
        &self,
        bytes: &[u8],
        rel_path: &Path,
        cache_path: &Path,
    ) -> Result<PathBuf, Error> {
        let extracted_bytes = self.extract_into_memory(bytes)?;
        self.save_file_to_cache(&extracted_bytes, rel_path, cache_path)
            .await
    }

    fn extract_into_memory(&self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let cursor = Cursor::new(bytes);
        let mut cabinet = cab::Cabinet::new(cursor)?;
        let file_name_in_cab = {
            // Only pick the first file we encounter. That's the PDB.
            let folder = cabinet.folder_entries().next().unwrap();
            let file = folder.file_entries().next().unwrap();
            file.name().to_string()
        };
        if self.verbose {
            eprintln!("Extracting {:?} into memory...", file_name_in_cab);
        }
        let mut reader = cabinet.read_file(&file_name_in_cab)?;
        let mut vec = Vec::new();
        std::io::copy(&mut reader, &mut vec)?;
        Ok(vec)
    }

    async fn get_bytes_from_url(&self, url: &str) -> Option<Bytes> {
        if self.verbose {
            eprintln!("Downloading {}...", url);
        }
        let response = reqwest::get(url).await.ok()?.error_for_status().ok()?;
        response.bytes().await.ok()
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
