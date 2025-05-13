# Changelog
## [Unreleased]

### Added

### Changed

### Deprecated

### Fixed

## [v0.5.1]

### Added
* [[218 ]] (https://github.com/rust-vmm/mshv/pull/218) save and restore interrupt vectors
* [[219 ]] (https://github.com/rust-vmm/mshv/pull/219) use new hvcall_ versions for ioctls

### Fixed
* [[220 ]] https://github.com/rust-vmm/mshv/pull/220 Fix ARM64 guest default processor feature set

## [v0.5.0]

### Changed
* [[206]] (https://github.com/rust-vmm/mshv/pull/206) mshv-ioctls: Don't initialize partition after creation

## [v0.4.0]

### Added
* [[207]] (https://github.com/rust-vmm/mshv/pull/207) hvcall ioctls

### Changed
* [[209]] (https://github.com/rust-vmm/mshv/pull/209) filter MSRs before returing to VMM
* [[208]] https://github.com/rust-vmm/mshv/pull/208) property value is 64 bits
* [[204]] https://github.com/rust-vmm/mshv/pull/204 Rework Create Partition IOCTL

## [v0.3.5]

### Added
* [[197]](https://github.com/rust-vmm/mshv/pull/197) mshv-ioctls: Implement get/set reg for aarch64

### Changed
* [[200]](https://github.com/rust-vmm/mshv/pull/200) Validate VP register page before using it

## [v0.3.4]

### Added
* [[191]](https://github.com/rust-vmm/mshv/pull/191) Use VP register page to get/set Special and extended registers  

## [v0.3.3]

### Added
* [[184]](https://github.com/rust-vmm/mshv/pull/184) mshv-ioctl: Add an interface to retrieve host partition property
* [[186]](https://github.com/rust-vmm/mshv/pull/186) Add support for StandardRegisters on ARM64
* [[187]](https://github.com/rust-vmm/mshv/pull/187) Validate Cargo.toml and commit messages
* [[188]](https://github.com/rust-vmm/mshv/pull/188) Add new interfaces required for ARM64 guest.
* [[189]](https://github.com/rust-vmm/mshv/pull/189) Add @praveen-pk as the codeowner

### Changed
* [[183]](https://github.com/rust-vmm/mshv/pull/183) Update get/set Standard Registers to use VP register page

### Deprecated

### Fixed
* [[185]](https://github.com/rust-vmm/mshv/pull/185) Make tests conditionally compile for x86
* [[181]](https://github.com/rust-vmm/mshv/pull/181) mshv-bindings: Fix rust clippy warnings

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
