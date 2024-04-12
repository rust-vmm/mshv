// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

#[cfg(target_arch = "x86_64")]
#[macro_use]
#[cfg(feature = "fam-wrappers")]
extern crate vmm_sys_util;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

pub mod hvdef;
pub use hvdef::*;
