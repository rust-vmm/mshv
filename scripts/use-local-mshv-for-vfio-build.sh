#! /bin/sh

sed -i 's/mshv-ioctls = { git = "https:\/\/github.com\/rust-vmm\/mshv", branch = "main", optional  = true }*/mshv-ioctls = { path = \"..\/..\/..\/mshv\/mshv-ioctls\", optional  = true }/g' ./crates/vfio-ioctls/Cargo.toml
sed -i 's/mshv-bindings = { git = "https:\/\/github.com\/rust-vmm\/mshv", branch = "main", features = \["with-serde", "fam-wrappers"\], optional  = true }*/mshv-bindings = { path = "..\/..\/..\/mshv\/mshv-bindings", features = ["with-serde", "fam-wrappers"], optional  = true }/g' ./crates/vfio-ioctls/Cargo.toml


