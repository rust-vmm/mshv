// Copyright © 2025, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

#[cfg(feature = "with-serde")]
use serde_derive::{Deserialize, Serialize};
use zerocopy::{FromBytes, IntoBytes};

/*
* Note: Only add fields to the end of this struct otherwise it will
* break the get/set_reg function in the Vcpu trait.
*/
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, IntoBytes, FromBytes)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct StandardRegisters {
    pub gpr: [u64; 29usize], // 29 General Purpose registers
    pub fp: u64,             // Frame Pointer
    pub lr: u64,             // Link register
    pub sp: u64,             // Stack Pointer
    pub pc: u64,             // Program Counter
    pub pstate: u64,         // Program Status register
    pub sp_el1: u64,         // Stack Pointer for EL1
    pub elr_el1: u64,        // Exception Link register for EL1
    pub fpsr: u64,           // Floating point status register
    pub fpcr: u64,           // Floating point control register
}
