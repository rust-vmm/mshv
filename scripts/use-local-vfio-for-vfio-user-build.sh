#! /bin/sh

filename=./Cargo.toml

line=$(grep -n "vfio-bindings = { git =" $filename | tail -n1 | cut -f1 -d:)
if [ -z $line ]; then
        echo "vfio-bindings not found in the Cargo.toml file"
        exit 1
fi
sed -i "$line i vfio-bindings = { path = \"../vfio/vfio-bindings\" }" $filename
line=$((line+1))
sed -i "${line}d" $filename
