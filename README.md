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

## Release Process

Versioning follows [semver](https://semver.org/). As mshv is currently pre-1.0, minor version increments indicate both new features and breaking changes.

Generally follow the guidelines [here](https://github.com/rust-vmm/community/blob/main/docs/crate_release.md)

`mshv-ioctls` and `mshv-bindings` version numbers stay in sync; they are identical.

1. Update each Cargo.toml and add the relevant changes in each CHANGELOG.md
2. Create PR for the release with the changes from (1)
3. Once the PR is merged, create and push tags for the release:
```
    $ ./scripts/tag_release.py --crate mshv-ioctls
    Created tag: mshv-ioctls-v0.6.0
    $ ./scripts/tag_release.py --crate mshv-bindings
    Created tag: mshv-bindings-v0.6.0
```
4. Check the tags look okay, and push them
```
    git show mshv-ioctls-v0.6.0
    git show mshv-bindings-v0.6.0
    git push --tags
```
5. Create a release on github
6. Create a release on crates.io
7. Bump the mshv version in upstream [vfio](https://github.com/rust-vmm/vfio)
8. Bump the mshv version in upstream [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)