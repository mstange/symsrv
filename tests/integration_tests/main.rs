use std::collections::HashMap;
use std::future::{poll_fn, Future};
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use http::StatusCode;
use symsrv::{CachePath, DownloadError, NtSymbolPathEntry, SymsrvDownloader, SymsrvObserver};
use tempfile::tempdir;
use tokio::pin;

fn fixtures_dir() -> PathBuf {
    let symsrv_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    symsrv_dir.join("tests").join("fixtures")
}

fn path_to_fixture(rel_path: impl AsRef<Path>) -> PathBuf {
    let mut path = fixtures_dir();
    path.push(rel_path);
    path
}

fn file_matches_fixture(test_path: &Path, fixture_rel_path: impl AsRef<Path>) -> bool {
    let test_file_bytes = std::fs::read(test_path).unwrap();
    let ref_file_bytes = std::fs::read(path_to_fixture(fixture_rel_path)).unwrap();
    test_file_bytes == ref_file_bytes
}

fn make_symbol_cache(
    symbol_path: Vec<NtSymbolPathEntry>,
    default_downstream_store: Option<&Path>,
) -> (SymsrvDownloader, Arc<TestObserver>) {
    let observer = Arc::new(TestObserver::default());
    let mut downloader = SymsrvDownloader::new(symbol_path);
    downloader.set_default_downstream_store(default_downstream_store);
    downloader.set_observer(Some(observer.clone()));
    (downloader, observer)
}

struct TestCacheDir {
    dir: tempfile::TempDir,
}

impl TestCacheDir {
    pub fn prepare(prepopulated_files: &[&str]) -> std::io::Result<Self> {
        let dir = tempdir()?;
        let cache = Self { dir };

        // Populate the cache.
        for rel_path in prepopulated_files {
            let src_path = path_to_fixture(rel_path);
            let dest_path = cache.path_for_file(rel_path);
            std::fs::create_dir_all(dest_path.parent().unwrap())?;
            std::fs::copy(src_path, dest_path)?;
        }

        Ok(cache)
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn cache_path(&self) -> CachePath {
        CachePath::Path(self.path().into())
    }

    pub fn path_for_file(&self, rel_path: impl AsRef<Path>) -> PathBuf {
        let mut file_path = self.path().to_owned();
        file_path.push(rel_path);
        file_path
    }

    pub fn contains_file(&self, rel_path: impl AsRef<Path>) -> bool {
        matches!(self.path_for_file(rel_path).metadata(), Ok(meta) if meta.is_file())
    }
}

struct TestSymbolServer {
    server: Box<dyn DerefMut<Target = mockito::Server>>,
    #[allow(unused)]
    mocks: Vec<mockito::Mock>,
}

impl TestSymbolServer {
    pub async fn prepare(prepopulated_files: &[&str]) -> Self {
        let mut server = Box::new(mockito::Server::new_async().await);
        let mut mocks = Vec::new();

        // GET requests to unknown URLs should receive a 404 response.
        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .expect_at_least(0)
            .create_async()
            .await;
        mocks.push(mock);

        // Populate the server.
        for rel_path in prepopulated_files {
            let mock = server
                .mock("GET", format!("/{rel_path}").as_str())
                .with_body_from_file(path_to_fixture(rel_path))
                .create_async()
                .await;
            mocks.push(mock);
        }

        Self { server, mocks }
    }

    pub fn add_mock_which_sends_a_chunk_and_then_cancels(
        &mut self,
        rel_path: &str,
        cutoff_size: usize,
    ) {
        let body = std::fs::read(path_to_fixture(rel_path)).unwrap();
        let mock = self
            .server
            .mock("GET", format!("/{rel_path}").as_str())
            .with_chunked_body(move |w| {
                let partial_body = &body[..cutoff_size];
                w.write_all(partial_body).unwrap();
                Err(std::io::Error::new(std::io::ErrorKind::Other, "canceled"))
            })
            .create();
        self.mocks.push(mock);
    }

    pub fn add_mock_with_slow_chunked_response(&mut self, rel_path: &str, chunk_size: usize) {
        let body = std::fs::read(path_to_fixture(rel_path)).unwrap();
        let mock = self
            .server
            .mock("GET", format!("/{rel_path}").as_str())
            .with_chunked_body(move |w| {
                for chunk in body.chunks(chunk_size) {
                    w.write_all(chunk).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Ok(())
            })
            .create();
        self.mocks.push(mock);
    }

    pub fn url(&self) -> String {
        self.server.url()
    }

    pub async fn expect_no_fetch_from(&mut self, rel_path: &str) {
        let mock = self
            .server
            .mock("GET", format!("/{rel_path}").as_str())
            .expect(0)
            .create_async()
            .await;
        self.mocks.push(mock);
    }

    pub async fn assert(&self) {
        for mock in &self.mocks {
            mock.assert_async().await;
        }
    }
}

#[tokio::test]
async fn test_nothing_available() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();
    let cache1 = TestCacheDir::prepare(&[]).unwrap();
    let (symbol_cache, observer) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("dummy.pdb", "6E3C51F71CC1F0F64C4C44205044422E1")
        .await;
    assert!(
        matches!(res, Err(symsrv::Error::NotFound)),
        "Should not find a symbol file in an empty cache"
    );
    let observer = observer.get_inner();
    assert_eq!(
        observer.failed_downloads.len(),
        0,
        "Should not have any failed downloads"
    );
    assert_eq!(
        observer.missed_files.len(),
        2,
        "Should have two missed files"
    );
    assert_eq!(
        observer.missed_files[0],
        cache1.path_for_file("dummy.pdb/6E3C51F71CC1F0F64C4C44205044422E1/dummy.pdb"),
        "Should have missed the uncompressed file"
    );
    assert_eq!(
        observer.missed_files[1],
        cache1.path_for_file("dummy.pdb/6E3C51F71CC1F0F64C4C44205044422E1/dummy.pd_"),
        "Should have missed the compressed file"
    );
}

#[tokio::test]
async fn test_simple_available() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();
    let cache1 =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"]).unwrap();
    let (symbol_cache, observer) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        res.is_ok(),
        "Should find a symbol file in a pre-populated cache"
    );
    let path = res.unwrap();
    assert!(
        file_matches_fixture(&path, "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "Should find a symbol file in a pre-populated cache"
    );

    let observer = observer.get_inner();
    assert_eq!(
        observer.failed_downloads.len(),
        0,
        "Should not have any failed downloads"
    );
    assert_eq!(
        observer.missed_files.len(),
        0,
        "Should not have any missed files"
    );
    assert_eq!(
        observer.created_files.len(),
        0,
        "Should not have created any files"
    );
    assert_eq!(
        observer.accessed_files.len(),
        1,
        "Should have accessed one file"
    );
    assert_eq!(
        observer.accessed_files[0], path,
        "Should have accessed the expected file"
    );
}

#[tokio::test]
async fn test_simple_available_no_download() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();
    let cache1 =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"]).unwrap();
    let (symbol_cache, _) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file_no_download("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        res.is_ok(),
        "Should find a symbol file in a pre-populated cache"
    );
    let path = res.unwrap();
    assert!(
        file_matches_fixture(&path, "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "Should find a symbol file in a pre-populated cache"
    );
}

#[tokio::test]
async fn test_simple_compressed() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();

    // The cache starts out with the compressed .ex_ file.
    let cache1 =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"]).unwrap();
    let (symbol_cache, observer) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        res.is_ok(),
        "Should find an uncompressed symbol file in a cache with the compressed file"
    );
    assert!(
        !cache1.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The uncompressed file should be NOT stored in the cache which the file was found in."
    );
    // The Microsoft docs say that in this case, the uncompressed file should be stored
    // in the "default downstream store".
    //
    // > Note: If you are accessing symbols from an HTTP or HTTPS site, or if the symbol store
    // > uses compressed files, a downstream store is always used. If no downstream store is
    // > specified, one will be created in the sym subdirectory of the home directory.
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use
    assert!(
        default_downstream.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The uncompressed file should be stored in the default downstream store."
    );

    let observer = observer.get_inner();
    assert_eq!(
        observer.failed_downloads.len(),
        0,
        "Should not have any failed downloads"
    );
    assert_eq!(
        observer.missed_files.len(),
        1,
        "Should have one missed file: the uncompressed file"
    );
    assert_eq!(
        observer.created_files.len(),
        1,
        "Should have created one file"
    );
    assert_eq!(
        observer.created_files[0].0,
        default_downstream
            .path()
            .join("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "Should have created the uncompressed file"
    );
    assert_eq!(
        observer.accessed_files.len(),
        1,
        "Should have accessed one file: the compressed file"
    );
    assert_eq!(
        observer.accessed_files[0],
        cache1.path_for_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"),
        "Should have accessed the compressed file"
    );
}

#[tokio::test]
async fn test_propagate_compressed() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();

    // The cache starts out with the compressed .ex_ file.
    let cache1 = TestCacheDir::prepare(&[]).unwrap();
    let cache2 =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"]).unwrap();
    let (symbol_cache, _) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path(), cache2.cache_path()],
            urls: vec![],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        matches!(res, Ok(path) if file_matches_fixture(&path, "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe")),
        "Should find an uncompressed symbol file in a cache with the compressed file"
    );

    assert!(
        cache1.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The uncompressed file should be stored in the parent cache."
    );
}

#[tokio::test]
async fn test_simple_server() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();

    // The cache starts out empty.
    let cache1 = TestCacheDir::prepare(&[]).unwrap();

    // The server has a single, uncompressed, file.
    let server1 =
        TestSymbolServer::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"]).await;

    let (symbol_cache, _) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![server1.url()],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        res.is_ok(),
        "Should find an uncompressed symbol file by downloading the uncompressed file"
    );
    assert!(
        cache1.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The uncompressed file should be stored in the cache."
    );
}

#[tokio::test]
async fn test_simple_server_no_download() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();

    // The cache starts out empty.
    let cache1 = TestCacheDir::prepare(&[]).unwrap();

    // The server has a single, uncompressed, file.
    let server1 =
        TestSymbolServer::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"]).await;

    let (symbol_cache, _) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![server1.url()],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file_no_download("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        matches!(res, Err(symsrv::Error::NotFound)),
        "Should not have obtained the file from the server because it wasn't in the cache and we were using get_file_no_download"
    );
    assert!(
        !cache1.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The file should not be in the cache."
    );
}

// A test where the response from the server is partial and then the connection is aborted.
#[tokio::test]
async fn test_aborted_response() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();

    // The cache starts out empty.
    let cache1 = TestCacheDir::prepare(&[]).unwrap();

    // The server has a single, uncompressed, file.
    let mut server1 = TestSymbolServer::prepare(&[]).await;
    server1.add_mock_which_sends_a_chunk_and_then_cancels(
        "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe",
        5678,
    );

    let (symbol_cache, observer) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![server1.url()],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        res.is_err(),
        "The response is aborted, so the result should be an error."
    );
    assert!(
        !cache1.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The partial file should not be stored in the cache."
    );

    let observer = observer.get_inner();
    assert_eq!(
        observer.failed_downloads.len(),
        2,
        "Should have two failed downloads"
    );
    // The requests run in parallel, so we don't know which error will be reported first.
    assert!(
        observer.failed_downloads.iter().any(|(url, err)| url
            == &(server1.url() + "/ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe")
            && matches!(err, DownloadError::ErrorDuringDownloading(_))),
        "Should have failed to download the uncompressed file with the appropriate error"
    );
    assert!(
        observer.failed_downloads.iter().any(|(url, err)| url
            == &(server1.url() + "/ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_")
            && matches!(err, DownloadError::StatusError(StatusCode::NOT_FOUND))),
        "Should have failed to download the compressed file with the appropriate error"
    );
}

// A test where the response from the server is partial and then the connection is aborted.
#[tokio::test]
async fn test_dropped_future() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();

    // The cache starts out empty.
    let cache1 = TestCacheDir::prepare(&[]).unwrap();

    // The server has a single, uncompressed, file.
    let mut server1 = TestSymbolServer::prepare(&[]).await;
    server1.add_mock_with_slow_chunked_response(
        "ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe",
        1000,
    );

    let (symbol_cache, observer) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![server1.url()],
        }],
        Some(default_downstream.path()),
    );

    {
        let get_file_future = symbol_cache.get_file("ShowSSEConfig.exe", "63E6C7F78000");
        pin!(get_file_future);

        let observer_copy = observer.clone();
        poll_fn(move |cx: &mut Context<'_>| {
            if observer_copy.get_inner().pending_downloads.is_empty() {
                // Keep polling the future until a download has started.
                let result = get_file_future.as_mut().poll(cx);
                result.map(|_| ())
            } else {
                // Once the download has started, complete this future so that
                // the `await` below completes before the download is done.
                Poll::Ready(())
            }
        })
        .await;
    }

    // Now res_future has been dropped, and the download should not have completed.
    // The observer should have been notified about the fact that the download didn't complete.
    // This test is fairly racy; there may have been two requests, one for the compressed file
    // and one for the uncompressed file, and we don't know which one will be current when the
    // future is dropped.
    let observer = observer.get_inner();
    assert_ne!(
        observer.canceled_downloads.len(),
        0,
        "Should at least one canceled download"
    );
}

#[tokio::test]
async fn test_dont_use_server_if_cache_has_it() {
    // The file is already in the default downstream store.
    let default_downstream =
        TestCacheDir::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"]).unwrap();

    let mut server1 = TestSymbolServer::prepare(&[]).await;
    server1
        .expect_no_fetch_from("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe")
        .await;

    let (symbol_cache, _) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![CachePath::DefaultDownstreamStore],
            urls: vec![server1.url()],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        res.is_ok(),
        "Should find an uncompressed symbol file by downloading the uncompressed file"
    );
    server1.assert().await;
}

#[tokio::test]
async fn test_server_with_cab_compression() {
    let default_downstream = TestCacheDir::prepare(&[]).unwrap();

    // The cache starts out empty.
    let cache1 = TestCacheDir::prepare(&[]).unwrap();

    // The server has a single, uncompressed, file.
    let server1 =
        TestSymbolServer::prepare(&["ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"]).await;

    let (symbol_cache, _) = make_symbol_cache(
        vec![NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths: vec![cache1.cache_path()],
            urls: vec![server1.url()],
        }],
        Some(default_downstream.path()),
    );
    let res = symbol_cache
        .get_file("ShowSSEConfig.exe", "63E6C7F78000")
        .await;
    assert!(
        res.is_ok(),
        "Should find an uncompressed symbol file by downloading the uncompressed file"
    );
    assert!(
        cache1.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"),
        "The compressed file should be stored in the cache."
    );
    assert!(
        cache1.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The uncompressed file should be stored in the cache."
    );
    assert!(
        !default_downstream.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.ex_"),
        "The uncompressed file should NOT be stored in the default downstream store."
    );
    assert!(
        !default_downstream.contains_file("ShowSSEConfig.exe/63E6C7F78000/ShowSSEConfig.exe"),
        "The uncompressed file should NOT be stored in the default downstream store."
    );
}

// Tests to add:
//  - Tests with multiple servers, falling back on 404 and other error responses
//  - Tests for `NtSymbolPathEntry::Cache`: make sure things are propagated into that cache for
//    files found in caches following that entry but not preceding it.
//  - A test which checks that, if you have [(cache1, server1), (cache2, server2)], and cache1
//    does not have the file but cache2 does, we get the file from server1 and not from cache2.
//  - A test which does the same as the previous test, but with get_file_no_download, and gets
//    the file from cache2.

#[derive(Debug, Default)]
struct TestObserverInner {
    pending_downloads: HashMap<u64, String>,
    completed_downloads: Vec<String>,
    failed_downloads: Vec<(String, DownloadError)>,
    canceled_downloads: Vec<String>,
    missed_files: Vec<PathBuf>,
    created_files: Vec<(PathBuf, u64)>,
    accessed_files: Vec<PathBuf>,
}

impl TestObserverInner {
    fn on_new_download_before_connect(&mut self, download_id: u64, url: &str) {
        self.pending_downloads.insert(download_id, url.to_owned());
    }

    fn on_download_failed(&mut self, download_id: u64, error: DownloadError) {
        let url = self.pending_downloads.remove(&download_id).unwrap();
        self.failed_downloads.push((url, error));
    }

    fn on_download_canceled(&mut self, download_id: u64) {
        let url = self.pending_downloads.remove(&download_id).unwrap();
        self.canceled_downloads.push(url);
    }

    fn on_download_completed(
        &mut self,
        download_id: u64,
        _uncompressed_size_in_bytes: u64,
        _time_until_headers: std::time::Duration,
        _time_until_completed: std::time::Duration,
    ) {
        let url = self.pending_downloads.remove(&download_id).unwrap();
        self.completed_downloads.push(url);
    }

    fn on_file_missed(&mut self, path: &Path) {
        self.missed_files.push(path.to_owned());
    }

    fn on_file_created(&mut self, path: &Path, size_in_bytes: u64) {
        self.created_files.push((path.to_owned(), size_in_bytes));
    }

    fn on_file_accessed(&mut self, path: &Path) {
        self.accessed_files.push(path.to_owned());
    }
}

#[derive(Debug, Default)]
struct TestObserver {
    inner: Mutex<TestObserverInner>,
}

impl TestObserver {
    fn get_inner(&self) -> MutexGuard<'_, TestObserverInner> {
        self.inner.lock().unwrap()
    }
}

impl SymsrvObserver for TestObserver {
    fn on_new_download_before_connect(&self, download_id: u64, url: &str) {
        self.get_inner()
            .on_new_download_before_connect(download_id, url);
    }

    fn on_download_failed(&self, download_id: u64, error: DownloadError) {
        self.get_inner().on_download_failed(download_id, error);
    }

    fn on_download_canceled(&self, download_id: u64) {
        self.get_inner().on_download_canceled(download_id);
    }

    fn on_download_started(&self, _download_id: u64) {}

    fn on_download_progress(
        &self,
        _download_id: u64,
        _bytes_so_far: u64,
        _total_bytes: Option<u64>,
    ) {
    }

    fn on_download_completed(
        &self,
        download_id: u64,
        uncompressed_size_in_bytes: u64,
        time_until_headers: std::time::Duration,
        time_until_completed: std::time::Duration,
    ) {
        self.get_inner().on_download_completed(
            download_id,
            uncompressed_size_in_bytes,
            time_until_headers,
            time_until_completed,
        );
    }

    fn on_file_missed(&self, path: &Path) {
        self.get_inner().on_file_missed(path);
    }

    fn on_file_created(&self, path: &Path, size_in_bytes: u64) {
        self.get_inner().on_file_created(path, size_in_bytes);
    }

    fn on_file_accessed(&self, path: &Path) {
        self.get_inner().on_file_accessed(path);
    }
}
