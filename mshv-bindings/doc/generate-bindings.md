# Generate Bindings

## Install Dependencies

```shell
$ cargo install bindgen
$ sudo apt install llvm-dev libclang-dev clang llvm
```

## Export kernel headers to userspace

First we must generate the uapi headers if it hasn't already been done.
This installs headers to `INSTALL\_DIR/include`.
You can put them anywhere however.

```shell
INSTALL_DIR=/usr      # /usr/include is where they are normally installed
KERN_SOURCE_ROOT=<>   # Directory where the kernel sources are present
pushd $KERN_SOURCE_ROOT
sudo make headers_install ARCH=x86 INSTALL_HDR_PATH=${INSTALL_DIR}
popd
```

## Hacks

- mshv.h includes hyperv-tlfs.h already, but we need to modify some things in hyperv-tlfs.h, so we concatenate them for simplicity.
- In userspace, the compiler defines bool in stdbool.h. We just manually add the typedef here.
- Bindgen doesn't support nested or function-like macros, so we need to manually replace BIT().
- We remove the redundant includes of hyperv-tlfs.h

```shell
echo "typedef _Bool bool;" | \
cat - ${INSTALL_DIR}/include/asm/hyperv-tlfs.h ${INSTALL_DIR}/include/asm-generic/hyperv-tlfs.h ${INSTALL_DIR}/include/linux/mshv.h | \
sed -r 's/BIT\(([0-9]+)\)/(1 << \1)/g' | \
sed -r '/hyperv-tlfs.h/d' \
> hacked_mshv.h
```

## Generate bindings

Generate the bindings with the following command:

```shell
bindgen --no-doc-comments --with-derive-default --no-derive-debug --rustified-enum hv_register_name \
	hacked_mshv.h -- -I ${INSTALL_DIR}/include > bindings.rs
```

Copy the bindings.rs to mshv-bindings/src/
