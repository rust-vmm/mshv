// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(target_arch = "x86_64")]
#![allow(
    clippy::too_many_arguments,
    clippy::missing_safety_doc,
    clippy::upper_case_acronyms
)]
#![allow(unknown_lints)]
//TODO Remove later
#![allow(clippy::useless_transmute)]
//TODO Remove later
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(deref_nullptr)]
#![allow(unaligned_references)]
#![allow(clippy::wrong_self_convention)]

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

#[cfg(feature = "with-serde")]
mod serializers;

#[cfg(feature = "with-serde")]
pub use serializers::*;
