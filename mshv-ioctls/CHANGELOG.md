# Changelog
## [Unreleased]

### Added

### Changed

### Deprecated

### Fixed

# v0.3.2

### Added
- [[178]](https://github.com/rust-vmm/mshv/pull/178) mshv-bindings: implement send for svm_ghcb_base

### Changed

### Deprecated

### Fixed

- [[179]](https://github.com/rust-vmm/mshv/pull/179) Fix UB with Tree Borrows aliasing model in test suite
- [[177]](https://github.com/rust-vmm/mshv/pull/177) build(deps): update thiserror requirement from 1.0 to 2.0

# v0.3.1

## Added

- [[#163]](https://github.com/rust-vmm/mshv/pull/163) get_gpa_access_state: avoid returning dangling reference
- [[#161]](https://github.com/rust-vmm/mshv/pull/161) Add definitions to handle GHCB page
- [[#160]](https://github.com/rust-vmm/mshv/pull/160) mshv-ioctls: test case to validate map VP state page

### Changed

- [[#175]](https://github.com/rust-vmm/mshv/pull/175) Cargo.toml: Update metadata description to comply with cargo publish standards
- [[#169]](https://github.com/rust-vmm/mshv/pull/169) Cargo.toml: Update Cargo toml with metadata
- [[#168]](https://github.com/rust-vmm/mshv/pull/168) Bump zerocopy crate to the lastest version
- [[#157]](https://github.com/rust-vmm/mshv/pull/157) Update to Rust 2021 edition, and fix a warning.

# v0.1.0

First release of the mshv-ioctls crate.
