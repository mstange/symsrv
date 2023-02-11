use std::path::{Path, PathBuf};

use symsrv::{NtSymbolPathEntry, SymbolCache};
use tempfile::tempdir;

fn fixtures_dir() -> PathBuf {
    let symsrv_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    symsrv_dir.join("tests").join("fixtures")
}

struct TestCacheDir {
    dir: tempfile::TempDir,
}

impl TestCacheDir {
    pub fn prepare(prepopulated_files: &[&str]) -> std::io::Result<Self> {
        let dir = tempdir()?;

        // Populate the cache.
        let fixtures_dir = fixtures_dir();
        for rel_path in prepopulated_files {
            let mut src_path = fixtures_dir.to_owned();
            src_path.push(rel_path);
            let mut dest_path = dir.path().to_owned();
            dest_path.push(rel_path);
            std::fs::create_dir_all(dest_path.parent().unwrap())?;
            std::fs::copy(src_path, dest_path)?;
        }

        Ok(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn path_for_file(&self, rel_path: &Path) -> PathBuf {
        let mut file_path = self.path().to_owned();
        file_path.push(rel_path);
        file_path
    }

    pub fn contains_file(&self, rel_path: &Path) -> bool {
        matches!(self.path_for_file(rel_path).metadata(), Ok(meta) if meta.is_file())
    }
}

#[tokio::test]
async fn test_nothing_available() {
    let cache1 = TestCacheDir::prepare(&[]).unwrap();
    let symbol_cache = SymbolCache::new(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.path().to_owned()],
            urls: vec![],
        }],
        false,
    );
    let res = symbol_cache
        .get_file(Path::new(
            "dummy.pdb/6E3C51F71CC1F0F64C4C44205044422E1/dummy.pdb",
        ))
        .await;
    assert!(
        matches!(res, Err(symsrv::Error::NotFound)),
        "Should not find a symbol file in an empty cache"
    );
}

#[tokio::test]
async fn test_simple_available() {
    let cache1 =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"]).unwrap();
    let symbol_cache = SymbolCache::new(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.path().to_owned()],
            urls: vec![],
        }],
        false,
    );
    let res = symbol_cache
        .get_file(Path::new(
            "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe",
        ))
        .await;
    assert!(
        matches!(res, Ok(_contents) if _contents.len() > 0),
        "Should find a symbol file in a pre-populated cache"
    );
}

#[tokio::test]
async fn test_simple_compressed() {
    // The cache starts out with the compressed .ex_ file.
    let cache1 =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"]).unwrap();
    let symbol_cache = SymbolCache::new(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.path().to_owned()],
            urls: vec![],
        }],
        false,
    );
    let res = symbol_cache
        .get_file(Path::new(
            "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe",
        ))
        .await;
    assert!(
        matches!(res, Ok(_)),
        "Should find an uncompressed symbol file in a cache with the compressed file"
    );
    assert!(
        !cache1.contains_file(Path::new(
            "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"
        )),
        "The uncompressed file should be NOT stored in the cache which the file was found in."
    );
    // TODO: The Microsoft docs say that in this case, the uncompressed file should be stored
    // in the "default downstream store". We don't currently do that.
    //
    // > Note: If you are accessing symbols from an HTTP or HTTPS site, or if the symbol store
    // > uses compressed files, a downstream store is always used. If no downstream store is
    // > specified, one will be created in the sym subdirectory of the home directory.
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use
}

#[tokio::test]
async fn test_propagate_compressed() {
    // The cache starts out with the compressed .ex_ file.
    let cache1 = TestCacheDir::prepare(&[]).unwrap();
    let cache2 =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"]).unwrap();
    let symbol_cache = SymbolCache::new(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.path().to_owned(), cache2.path().to_owned()],
            urls: vec![],
        }],
        false,
    );
    let res = symbol_cache
        .get_file(Path::new(
            "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe",
        ))
        .await;
    assert!(
        matches!(res, Ok(_)),
        "Should find an uncompressed symbol file in a cache with the compressed file"
    );

    assert!(
        cache1.contains_file(Path::new(
            "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"
        )),
        "The uncompressed file should be stored in the parent cache."
    );
}

// Tests to add:
//  - Tests which download from a server
//  - Tests for `NtSymbolPathEntry::Cache`: make sure things are propagated into that cache for
//    files found in caches following that entry but not preceding it.
