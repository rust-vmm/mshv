#! /bin/sh

line=$(grep -n '\[dev-dependencies\]' Cargo.toml | tail -n1 | cut -f1 -d:)

sed -i "$line i [patch.\"https://github.com/rust-vmm/mshv\"]\n" ./Cargo.toml
line=$((line+1))
sed -i "$line i mshv-bindings = { path = \"../mshv/mshv-bindings\" }" ./Cargo.toml

line=$((line+1))
sed -i "$line i mshv-ioctls = { path = \"../mshv/mshv-ioctls\" }" ./Cargo.toml


