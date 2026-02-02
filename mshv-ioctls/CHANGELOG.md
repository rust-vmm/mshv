# Changelog
## [Unreleased]

### Added

### Changed

### Deprecated

### Fixed

## [v0.6.7]

###

* [[300]](https://github.com/rust-vmm/mshv/pull/300) Enable all host supported processor features for guests

## [v0.6.6]

### Changed
* [[290]](https://github.com/rust-vmm/mshv/pull/290) mshv-ioctls: use passthrough hvcall to get host partition props
* [[292]](https://github.com/rust-vmm/mshv/pull/292) Add more CPU features supported by the Microsoft Hypervisor
* [[296]](https://github.com/rust-vmm/mshv/pull/296) mshv-ioctls: enable more CPU features for arm64
* [[299]](https://github.com/rust-vmm/mshv/pull/299) mshv: Modify intermediate control registers to support nested hypervisor

## [v0.6.5]

### Changed
* [[283]](https://github.com/rust-vmm/mshv/pull/283) mshv-ioctls: rename variables for proc & xsave features
* [[287]](https://github.com/rust-vmm/mshv/pull/287) mshv-ioctls: turn on default CPU features

## [v0.6.4]

### Changed
* [[279]](https://github.com/rust-vmm/mshv/pull/279) mshv-ioctls: expose two APIs

## [v0.6.3]

###
* No changes

## [v0.6.2]

### Changed
* [[262]](https://github.com/rust-vmm/mshv/pull/262) make create feature functions public

## [v0.6.1]

### Changed
* [[254]](https://github.com/rust-vmm/mshv/pull/254) Enable RDRAND support for x86 guests
* [[253]](https://github.com/rust-vmm/mshv/pull/253) Enable PMU for arm64 guests

### Fixed
* [[251]](https://github.com/rust-vmm/mshv/pull/251) Munmap register page

## [v0.6.0]

### Added
* [[244]](https://github.com/rust-vmm/mshv/pull/244) add function to query vmm capabilities

### Fixed
* [[241]](https://github.com/rust-vmm/mshv/pull/241) Fixes for arm64 guests

## [v0.5.2]

### Fixed
* [[224]](https://github.com/rust-vmm/mshv/pull/224) Add vm.initialize() to tests
* [[231]](https://github.com/rust-vmm/mshv/pull/231) Fix a bug in translate gva hypercall
* [[234]](https://github.com/rust-vmm/mshv/pull/234) Fix ioctl invocations
* [[232]](https://github.com/rust-vmm/mshv/pull/232) Move test_get_msr_index_list() to vm.rs, fix issues

## [v0.5.1]

### Added
* [[218]](https://github.com/rust-vmm/mshv/pull/218) save and restore interrupt vectors
* [[219]](https://github.com/rust-vmm/mshv/pull/219) use new hvcall_ versions for ioctls

### Fixed
* [[220]](https://github.com/rust-vmm/mshv/pull/220) Fix ARM64 guest default processor feature set

## [v0.5.0]

### Changed
* [[206]](https://github.com/rust-vmm/mshv/pull/206) mshv-ioctls: Don't initialize partition after creation

## [v0.4.0]

### Added
* [[207]](https://github.com/rust-vmm/mshv/pull/207) hvcall ioctls

### Changed
* [[209]](https://github.com/rust-vmm/mshv/pull/209) filter MSRs before returing to VMM
* [[208]](https://github.com/rust-vmm/mshv/pull/208) property value is 64 bits
* [[204]](https://github.com/rust-vmm/mshv/pull/204) Rework Create Partition IOCTL

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
