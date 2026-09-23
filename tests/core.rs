//! Integration tests for `src/core/`. One submodule per source module.
//!
//! Submodules carry explicit `#[path]` attributes because a test crate root
//! resolves `mod` declarations against `tests/`, not `tests/core/`.

#[path = "common.rs"]
mod common;

#[path = "core/context.rs"]
mod context;

#[path = "core/scan.rs"]
mod scan;

#[path = "core/utils.rs"]
mod utils;
