//! Tool download, verification, and integration with external CCDC utilities.

/// Curated list of tools available for download.
pub mod catalog;
/// Download, SHA256 verification, and binary installation.
pub mod downloader;
/// Wrapper around the `nftbuild` firewall generator.
pub mod nftbuild;
