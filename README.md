# mshv

Microsoft Hypervisor wrappers. This repository provides two crates which are
mshv-bindings and mshv-ioctls. These crates will provide the APIs and
definitions to create a VMM on Microsoft Hypervisor along with other rust-vmm
crates.

## Supported Platforms

The mshv-{ioctls, bindings} can be used on x86_64 only.

## Build

```shell
cargo build
```

## Running the tests

Test (/dev/mshv requires root):
```shell
sudo -E ~/.cargo/bin/cargo test
```
