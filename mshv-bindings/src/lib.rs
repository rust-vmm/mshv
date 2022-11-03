// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

#[macro_use]
#[cfg(feature = "fam-wrappers")]
extern crate vmm_sys_util;

#[allow(
    clippy::too_many_arguments,
    clippy::missing_safety_doc,
    clippy::useless_transmute,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
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
