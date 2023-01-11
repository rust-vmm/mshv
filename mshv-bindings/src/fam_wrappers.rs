// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use vmm_sys_util::fam::{FamStruct, FamStructWrapper};

use crate::regs::*;
use crate::bindings::{mshv_modify_gpa_host_access, mshv_import_isolated_pages};

pub const MAX_MSR_ENTRIES: usize = 256;

generate_fam_struct_impl!(msrs, msr_entry, entries, u32, nmsrs, MAX_MSR_ENTRIES);

pub type Msrs = FamStructWrapper<msrs>;

pub type CpuId = FamStructWrapper<hv_cpuid>;

pub const HV_MAX_CPUID_ENTRIES: usize = 256;
// Implement the FamStruct trait for hv_cpuid.
generate_fam_struct_impl!(
    hv_cpuid,
    hv_cpuid_entry,
    entries,
    u32,
    nent,
    HV_MAX_CPUID_ENTRIES
);

generate_fam_struct_impl!(msr_list, u32, indices, u32, nmsrs, MAX_MSR_ENTRIES);

pub type MsrList = FamStructWrapper<msr_list>;

pub const HV_MAX_GPA_LIST_SIZE: usize = 512;

generate_fam_struct_impl!(mshv_modify_gpa_host_access, u64, gpa_list, u64, gpa_list_size, HV_MAX_GPA_LIST_SIZE);

pub type GpaHostAccess = FamStructWrapper<mshv_modify_gpa_host_access>;

pub const HV_MAX_ISOLATED_PAGES: usize = 1024;

generate_fam_struct_impl!(mshv_import_isolated_pages, u64, page_number, u64, num_pages, HV_MAX_ISOLATED_PAGES);

pub type IsolatedPages = FamStructWrapper<mshv_import_isolated_pages>;