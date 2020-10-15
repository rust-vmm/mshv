// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
#![allow(unused_variables, unused_mut)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(target_arch = "x86_64")]

extern crate mshv_bindings;
pub mod ioctls;
pub use ioctls::vcpu::VcpuFd;
pub use ioctls::vm::VmFd;
#[macro_use]
pub mod mshv_ioctls;
extern crate libc;
#[macro_use]
extern crate vmm_sys_util;
