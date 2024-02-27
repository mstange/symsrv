[![crates.io page](https://img.shields.io/crates/v/symsrv.svg)](https://crates.io/crates/symsrv)
[![docs.rs page](https://docs.rs/symsrv/badge.svg)](https://docs.rs/symsrv/)

# symsrv

This crate lets you download and cache symbol files from symbol servers,
according to the rules from the `_NT_SYMBOL_PATH` environment variable.

It exposes an async API. Internally it uses `reqwest` and `tokio`.

The downloaded symbols are stored on the file system. No automatic expiration
or eviction is performed. If you want to enforce a cache size limit or expire
old files, you can observe cache file creations and accesses with the
[`SymsrvObserver`] trait, and then write your own implementation for automatic
file cleanup.

## Microsoft Documentation

 - [Advanced SymSrv Use](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use)

## Example

```rust
use symsrv::{SymsrvDownloader};

// Parse the _NT_SYMBOL_PATH environment variable.
let symbol_path_env = symsrv::get_symbol_path_from_environment();
let symbol_path =
  symbol_path_env.as_deref().unwrap_or("srv**https://msdl.microsoft.com/download/symbols");
let parsed_symbol_path = symsrv::parse_nt_symbol_path(symbol_path);

// Create a downloader which follows the _NT_SYMBOL_PATH recipe.
let mut downloader = SymsrvDownloader::new(parsed_symbol_path);
downloader.set_default_downstream_store(symsrv::get_home_sym_dir());

// Download and cache a PDB file.
let local_path = downloader.get_file("dcomp.pdb", "648B8DD0780A4E22FA7FA89B84633C231").await?;

// Use the PDB file.
open_pdb_at_path(&local_path);
```

## Command line tool `symfetch`

This repository also contains a small example program called `symfetch`.
You can install it as follows:

```
cargo install --examples symsrv
```

Run it with `symfetch <filename> <hash>` - see `symfetch --help` for details.

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
