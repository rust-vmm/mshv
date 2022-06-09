#!/usr/bin/env python3

import argparse
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from shutil import rmtree, which


def check_installed(cmd):
    return which(cmd) is not None


def install_kernel_headers(kernel_src_path):
    kernel_hdr_path = tempfile.mkdtemp(prefix="linux")
    logging.debug(f"Installing kernel headers at {kernel_hdr_path}")
    subprocess.run(
        [
            "make",
            "headers_install",
            "ARCH=x86",
            f"INSTALL_HDR_PATH={kernel_hdr_path}",
            "-C",
            kernel_src_path,
        ],
        capture_output=True,
        check=True,
    )
    return kernel_hdr_path


def generate_unified_mshv_headers(kernel_hdr_path):
    logging.debug("Start generating unified header file")
    mshv_header_files = [
        f"{kernel_hdr_path}/include/asm/hyperv-tlfs.h",
        f"{kernel_hdr_path}/include/asm-generic/hyperv-tlfs.h",
        f"{kernel_hdr_path}/include/linux/mshv.h",
    ]

    with open(f"{kernel_hdr_path}/combined_mshv.h", "w") as fp:
        fp.write("typedef _Bool bool;\n")
        for header in mshv_header_files:
            data = ""

            with open(header, "r") as f:
                data = f.read()
                data = re.sub(r"BIT\(([0-9]+)\)", "(1 << \\1)", data, flags=re.M)
                data = re.sub(r".*hyperv\-tlfs.h.*", "", data, flags=re.M)

            fp.write(data)

    logging.debug("Done generating unified header file")


def run_bindgen(kernel_hdr_path, output_dir, bindgen_debug):
    logging.debug("Running bindgen")
    derive_debug = "--no-derive-debug"

    if bindgen_debug:
        derive_debug = "--with-derive-debug"

    cmd = f"""
    bindgen --no-doc-comments --with-derive-default {derive_debug} --rustified-enum hv_register_name \
    {kernel_hdr_path}/combined_mshv.h -- -I {kernel_hdr_path}/include > {output_dir}/bindings.rs
    """
    subprocess.check_call(cmd, shell=True)
    logging.debug("Cleaning up installed header files")
    rmtree(kernel_hdr_path)


def main(args):
    bindgen = check_installed("bindgen")
    if not bindgen:
        logging.error("Please install bindgen utility.")
        return -1

    make = check_installed("make")
    if not make:
        logging.error("Please install make.")
        return -1

    kernel_hdr_path = install_kernel_headers(args.kernel_src_path)
    generate_unified_mshv_headers(kernel_hdr_path)
    run_bindgen(kernel_hdr_path, args.output, args.bindgen_debug)

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate Rust bindings from HyperV headers files from Linux Kernel"
    )

    parser.add_argument(
        "--kernel",
        "-k",
        type=str,
        dest="kernel_src_path",
        required=True,
        help="Linux kernel source path",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        dest="output",
        default="mshv-bindings/src",
        help="Directory to store bindgen.rs",
    )

    parser.add_argument("--bingen-debug", dest="bindgen_debug", action="store_true")

    parser.add_argument(
        "--no-bindgen-debug", dest="bindgen_debug", action="store_false"
    )

    parser.set_defaults(bindgen_debug=False)

    parser.add_argument(
        "--log-level",
        "-l",
        dest="log_level",
        choices=["info", "debug", "error"],
        default="info",
        help="Log level for logging (default: %(default)s)",
    )

    log_level = {"info": logging.INFO, "debug": logging.DEBUG, "error": logging.ERROR}

    args = parser.parse_args()
    logging.getLogger().setLevel(log_level.get(args.log_level, logging.INFO))

    if not Path(args.kernel_src_path).is_dir():
        logging.error("Invalid kernel path:", args.kernel_src_path)
        sys.exit(-1)

    res = main(args)
    sys.exit(res)
