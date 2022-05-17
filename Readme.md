# symsrv

This crate lets you download and cache pdb files from symbol servers, according to the rules from the `_NT_SYMBOL_PATH` environment variable.

It exposes an async API and uses `reqwest` and `tokio::fs`.

The downloaded symbols are stored and never evicted.

## Microsoft Documentation

 - [Advanced SymSrv Use](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/advanced-symsrv-use)

## Example

```rust
use std::path::PathBuf;
use symsrv::{get_symbol_path_from_environment, SymbolCache};

// Parse the _NT_SYMBOL_PATH environment variable.
let symbol_path =
    get_symbol_path_from_environment("srv**https://msdl.microsoft.com/download/symbols");

// Create a symbol cache which follows the _NT_SYMBOL_PATH recipe.
let symbol_cache = SymbolCache::new(symbol_path, false);

// Download and cache a PDB file.
let relative_path: PathBuf =
    ["dcomp.pdb", "648B8DD0780A4E22FA7FA89B84633C231", "dcomp.pdb"].iter().collect();
let file_contents = symbol_cache.get_pdb(&relative_path).await?;

// Use the PDB file contents.
use_pdb_bytes(&file_contents[..]);
```

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
