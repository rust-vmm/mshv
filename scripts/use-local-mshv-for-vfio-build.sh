#! /bin/sh

filename=./vfio-ioctls/Cargo.toml
replace_crate() {
    line=$(grep -n "$1 = { version =" $filename | tail -n1 | cut -f1 -d:)
    if [ -z $line ]; then
            echo "$1 not found in the Cargo.toml file"
            exit 1
    fi
    sed -i "$line i $1 = { path = \"..\/..\/mshv\/$1\" $2" $filename
    line=$((line+1))
    sed -i "${line}d" $filename
}

replace_crate mshv-ioctls ', optional  = true }'
replace_crate mshv-bindings ', features = ['


# Below is a temporary workaround to fix ongoing pipeline issues.
# This should be removed once
# https://github.com/cloud-hypervisor/cloud-hypervisor/pull/7123 is merged.
# Summary: vfio crate picked up newer versions of dependencies, which conflict
#     with the versions within cloud-hypervisor. This script downgrades the
#     dependencies used by vfio to the versions used by cloud-hypervisor.

sed -e 's/^kvm-bindings.*$/kvm-bindings = { version = "0.10.0", optional = true }/g' -i $filename
sed -e 's/^kvm-ioctls.*$/kvm-ioctls = { version = "0.19.1", optional = true }/g' -i $filename

vfio_cargo="./Cargo.toml"
sed -e 's/^vmm-sys-util.*$/vmm-sys-util = "0.12.1"/g' -i $vfio_cargo
