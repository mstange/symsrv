use clap::Parser;
use indicatif::{DecimalBytes, MultiProgress, ProgressBar};
use symsrv::{
    get_default_downstream_store, parse_nt_symbol_path, CachePath, DownloadError,
    NtSymbolPathEntry, SymsrvDownloader, SymsrvObserver,
};

use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Parser)]
#[clap(
    version,
    about = "Fetch a symbol file.",
    long_about = "
Fetch a single symbol file from a symbol server, or find it in a local cache directory.
Prints the local path to the file to stdout.

Supports symbol servers which serve files with cab compression; the local file will be
decompressed if necessary, and the printed path always refers to a decompressed file.",
    override_usage = r#"symfetch [OPTIONS] <name> <hash>

Examples:
    symfetch --server "https://msdl.microsoft.com/download/symbols/" --cache ~/sym winmine.exe 3B7D847520000
    symfetch --server "https://msdl.microsoft.com/download/symbols/" --cache ~/sym combase.pdb 071849A7C75FD246A3367704EE1CA85B1
    symfetch --server "https://renderdoc.org/symbols" --cache ~/sym renderdoc.pdb 6D1DFFC4DC524537962CCABC000820641
    symfetch --symbol-path "srv**https://renderdoc.org/symbols" renderdoc.pdb 6D1DFFC4DC524537962CCABC000820641
    _NT_SYMBOL_PATH="srv**https://msdl.microsoft.com/download/symbols/*https://chromium-browser-symsrv.commondatastorage.googleapis.com/" symfetch --use-env-symbol-path chrome.dll.pdb 93B17FC546DE07D14C4C44205044422E1"#
)]
struct Args {
    /// The server URL to use for downloading symbol files. Can be specified multiple times.
    #[clap(long)]
    server: Vec<String>,

    /// The local cache directory to use for storing files that are downloaded from servers specified via --server.
    #[clap(long)]
    cache: Option<PathBuf>,

    /// If set, nothing is printed to stderr (no progress bars and no status messages).
    #[clap(long)]
    quiet: bool,

    /// Respect the _NT_SYMBOL_PATH environment variable.
    #[clap(long, short = 'e')]
    use_env_symbol_path: bool,

    /// The "symbol path" in the format used by the _NT_SYMBOL_PATH environment variable.
    /// See https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use
    #[clap(long)]
    symbol_path: Option<String>,

    /// The local cache directory which should be used if no other cache directories are specified in the symbol path.
    #[clap(long)]
    default_downstream_store: Option<PathBuf>,

    /// The file name of the symbol file to fetch.
    name: String,

    /// The hash / "ID" of the symbol file, e.g. B2A2B092E45739B84C4C44205044422E1 or 61015E74442b000.
    ///
    /// For PDBs this is `<GUID><age>`, with `<GUID>` in uppercase and `<age>` in lowercase hex.
    /// For binaries this is `<TIMESTAMP><imageSize>`, with `<TIMESTAMP>` printed as eight uppercase
    /// hex digits (with leading zeros added as needed) and `<imageSize>` in lowercase hex
    //  digits with as many digits as needed.
    hash: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = Args::parse();

    let mut parsed_nt_symbol_path = Vec::new();
    let nt_symbol_path = if args.use_env_symbol_path {
        std::env::var("_NT_SYMBOL_PATH").ok()
    } else {
        args.symbol_path
    };
    if let Some(nt_symbol_path) = nt_symbol_path {
        parsed_nt_symbol_path.extend(parse_nt_symbol_path(&nt_symbol_path));
    }

    if !args.server.is_empty() {
        let mut cache_paths = Vec::new();
        if let Some(cache) = args.cache {
            cache_paths.push(CachePath::Path(cache));
        }
        let urls = args.server;
        parsed_nt_symbol_path.push(NtSymbolPathEntry::Chain {
            dll: "symsrv.dll".into(),
            cache_paths,
            urls,
        });
    }

    let observer = Arc::new(SymFetchObserver::new());

    let symbol_cache = SymsrvDownloader::new(
        parsed_nt_symbol_path,
        args.default_downstream_store
            .or(get_default_downstream_store())
            .as_deref(),
        Some(observer),
    );

    let path: PathBuf = [args.name.clone(), args.hash, args.name].iter().collect();
    let path = symbol_cache.get_file(&path).await?;
    println!("{}", path.to_string_lossy());
    Ok(())
}

struct SymFetchObserver {
    inner: Mutex<SymFetchObserverInner>,
}

impl SymFetchObserver {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SymFetchObserverInner::new()),
        }
    }

    fn get_inner(&self) -> MutexGuard<SymFetchObserverInner> {
        self.inner.lock().unwrap()
    }
}

impl SymsrvObserver for SymFetchObserver {
    fn on_new_download_before_connect(&self, download_id: u64, url: &str) {
        self.get_inner()
            .on_new_download_before_connect(download_id, url);
    }

    fn on_download_failed(&self, download_id: u64, error: DownloadError) {
        self.get_inner().on_download_failed(download_id, error);
    }

    fn on_download_started(&self, download_id: u64) {
        self.get_inner().on_download_started(download_id);
    }

    fn on_download_progress(&self, download_id: u64, bytes_so_far: u64, total_bytes: Option<u64>) {
        self.get_inner()
            .on_download_progress(download_id, bytes_so_far, total_bytes);
    }

    fn on_download_completed(
        &self,
        download_id: u64,
        uncompressed_size_in_bytes: u64,
        _time_until_headers: std::time::Duration,
        _time_until_completed: std::time::Duration,
    ) {
        self.get_inner()
            .on_download_completed(download_id, uncompressed_size_in_bytes);
    }

    fn on_file_missed(&self, _path: &Path) {}

    fn on_file_created(&self, _path: &Path, _size_in_bytes: u64) {}

    fn on_file_accessed(&self, _path: &Path) {}
}

struct SymFetchObserverInner {
    multi_progress: MultiProgress,
    requests: HashMap<u64, RequestData>,
}

impl SymFetchObserverInner {
    pub fn new() -> Self {
        Self {
            multi_progress: MultiProgress::new(),
            requests: HashMap::new(),
        }
    }

    fn on_new_download_before_connect(&mut self, download_id: u64, url: &str) {
        let progress_bar = self.multi_progress.add(ProgressBar::new_spinner());
        progress_bar.set_style(style::spinner());
        progress_bar.set_message(format!("Connecting to {url}..."));
        self.requests.insert(
            download_id,
            RequestData {
                progress_bar,
                url: url.to_owned(),
                is_determinate: false,
            },
        );
    }

    fn on_download_failed(&mut self, download_id: u64, error: DownloadError) {
        let request = self.requests.remove(&download_id).unwrap();
        request.progress_bar.finish_and_clear();
        self.multi_progress.remove(&request.progress_bar);
        let url = request.url;
        self.multi_progress
            .println(format!("Request to {url} failed: {error}"))
            .unwrap();
    }

    fn message_for_url(url: &str) -> String {
        format!("Downloading from {url}...")
    }

    fn on_download_started(&mut self, download_id: u64) {
        let request = self.requests.get_mut(&download_id).unwrap();
        let message = Self::message_for_url(&request.url);
        request.progress_bar.set_message(message);
    }

    fn on_download_progress(
        &mut self,
        download_id: u64,
        bytes_so_far: u64,
        total_bytes: Option<u64>,
    ) {
        let request = self.requests.get_mut(&download_id).unwrap();
        match (request.is_determinate, total_bytes) {
            (false, Some(total_bytes)) => {
                let progress_bar = self.multi_progress.insert_after(
                    &request.progress_bar,
                    ProgressBar::new(total_bytes).with_elapsed(request.progress_bar.elapsed()),
                );
                self.multi_progress.remove(&request.progress_bar);
                progress_bar.set_style(style::bar());
                progress_bar.set_message(Self::message_for_url(&request.url));
                request.progress_bar = progress_bar;
                request.is_determinate = true;
            }
            (true, None) => {
                let progress_bar = self.multi_progress.insert_after(
                    &request.progress_bar,
                    ProgressBar::new_spinner().with_elapsed(request.progress_bar.elapsed()),
                );
                self.multi_progress.remove(&request.progress_bar);
                progress_bar.set_style(style::spinner());
                progress_bar.set_message(Self::message_for_url(&request.url));
                request.progress_bar = progress_bar;
                request.is_determinate = false;
            }
            _ => {}
        }
        request.progress_bar.set_position(bytes_so_far);
    }

    fn on_download_completed(&mut self, download_id: u64, uncompressed_size_in_bytes: u64) {
        let request = self.requests.remove(&download_id).unwrap();
        request.progress_bar.finish();
        self.multi_progress.remove(&request.progress_bar);
        let url = request.url;
        self.multi_progress
            .println(format!(
                "Successfully downloaded {} from {url}.",
                DecimalBytes(uncompressed_size_in_bytes)
            ))
            .unwrap();
    }
}

struct RequestData {
    progress_bar: ProgressBar,
    url: String,
    is_determinate: bool,
}

mod style {
    use indicatif::ProgressStyle;

    pub fn bar() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template(
                "[{elapsed_precise}] {bar:.cyan/blue} {decimal_bytes:>12}/{decimal_total_bytes:12} {wide_msg}",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  ")
    }

    pub fn spinner() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {spinner} {bytes_per_sec:>10} {wide_msg}")
            .unwrap()
    }
}
