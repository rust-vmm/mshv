#! /bin/sh

replace_crate() {
        filename=./Cargo.toml
        line=$(grep -n "$1 = " $filename | tail -n1 | cut -f1 -d:)
        if [ -z $line ]; then
                echo " $1 not found in the Cargo.toml file"
                exit 1
        fi
        sed -i "$line i $1 = { path = \"../$2\" }" $filename
        line=$((line+1))
        sed -i "${line}d" $filename
};

replace_crate mshv-bindings mshv/mshv-bindings
replace_crate mshv-ioctls mshv/mshv-ioctls 
replace_crate vfio-bindings vfio/crates/vfio-bindings
replace_crate vfio-ioctls vfio/crates/vfio-ioctls
replace_crate vfio_user vfio-user
