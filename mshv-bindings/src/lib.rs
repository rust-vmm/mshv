// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(target_arch = "x86_64")]

#[macro_use]
#[cfg(all(
    feature = "fam-wrappers",
    any(target_arch = "x86", target_arch = "x86_64")
))]
extern crate vmm_sys_util;

pub mod bindings;
pub use bindings::*;
pub mod regs;
pub use regs::*;

#[cfg(feature = "with-serde")]
extern crate serde;

#[cfg(feature = "with-serde")]
extern crate serde_derive;
pub mod hvdef;
pub use hvdef::*;
mod unmarshal;
pub use unmarshal::*;

#[cfg(feature = "fam-wrappers")]
mod fam_wrappers;

#[cfg(feature = "fam-wrappers")]
pub use fam_wrappers::*;
