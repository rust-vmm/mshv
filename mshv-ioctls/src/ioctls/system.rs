// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::ioctls::vm::{new_vmfd, VmFd};
use crate::ioctls::Result;
use crate::mshv_ioctls::*;
use libc::{open, O_CLOEXEC, O_NONBLOCK};
use mshv_bindings::*;
use std::fs::File;
use std::os::raw::c_char;
use std::os::unix::io::{FromRawFd, RawFd};
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::ioctl_with_ref;

/// Wrapper over MSHV system ioctls.
pub struct Mshv {
    hv: File,
}

impl Mshv {
    /// Opens `/dev/mshv` and returns a `Mshv` object on success.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Self> {
        // Open `/dev/mshv` using `O_CLOEXEC` flag.
        let fd = Self::open_with_cloexec(true)?;
        // Safe because we verify that ret is valid and we own the fd.
        let ret = unsafe { Self::new_with_fd_number(fd) };
        Ok(ret)
    }
    /// Creates a new Mshv object assuming `fd` represents an existing open file descriptor
    /// associated with `/dev/mshv`.
    ///
    /// # Safety
    ///
    /// This function is unsafe as the primitives currently returned have the contract that
    /// they are the sole owner of the file descriptor they are wrapping. Usage of this function
    /// could accidentally allow violating this contract which can cause memory unsafety in code
    /// that relies on it being true.
    ///
    /// The caller of this method must make sure the fd is valid and nothing else uses it.
    pub unsafe fn new_with_fd_number(fd: RawFd) -> Self {
        Mshv {
            hv: File::from_raw_fd(fd),
        }
    }

    /// Opens `/dev/mshv` and returns the fd number on success.
    pub fn open_with_cloexec(close_on_exec: bool) -> Result<RawFd> {
        let open_flags = O_NONBLOCK | if close_on_exec { O_CLOEXEC } else { 0 };
        // Safe because we give a constant nul-terminated string and verify the result.
        let ret = unsafe { open("/dev/mshv\0".as_ptr() as *const c_char, open_flags) };
        if ret < 0 {
            Err(errno::Error::last())
        } else {
            Ok(ret)
        }
    }
    /// Creates a VM fd using the MSHV fd.
    pub fn create_vm(&self) -> Result<VmFd> {
        // Safe because we know `self.hv` is a real MSHV fd as this module is the only one that
        // creates mshv objects.
        let creation_flags: u64 = HV_PARTITION_CREATION_FLAG_LAPIC_ENABLED as u64;
        let mut pr = mshv_create_partition {
            partition_creation_properties: hv_partition_creation_properties {
                disabled_processor_features: hv_partition_processor_features { as_uint64: [0; 2] },
                disabled_processor_xsave_features: hv_partition_processor_xsave_features {
                    as_uint64: 0_u64,
                },
            },
            synthetic_processor_features: hv_partition_synthetic_processor_features {
                as_uint64: [0; 1],
            },
            flags: creation_flags,
        };
        /* TODO pass in arg for this */
        unsafe {
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_hypervisor_present(1);
            pr.synthetic_processor_features.__bindgen_anon_1.set_hv1(1);
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_partition_reference_counter(1);
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_synic_regs(1);
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_synthetic_timer_regs(1);
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_partition_reference_tsc(1);
            /* Need this for linux on CH, as there's no PIT or HPET */
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_frequency_regs(1);
            /* Linux I'm using appears to require vp assist page... */
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_intr_ctrl_regs(1);
            /* According to Hv#1 spec, these must be set also, but they aren't in KVM? */
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_vp_index(1);
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_hypercall_regs(1);
            /* Windows requires this */
            pr.synthetic_processor_features
                .__bindgen_anon_1
                .set_access_guest_idle_reg(1);
        }

        let ret = unsafe { ioctl_with_ref(&self.hv, MSHV_CREATE_PARTITION(), &pr) };
        if ret >= 0 {
            // Safe because we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            Ok(new_vmfd(vm_file))
        } else {
            Err(errno::Error::last())
        }
    }
    /// Check if MSHV API is stable
    pub fn check_stable(&self) -> Result<bool> {
        // Safe because we know `self.hv` is a real MSHV fd as this module is the only one that
        // creates mshv objects.
        let cap: u32 = MSHV_CAP_CORE_API_STABLE;
        let ret = unsafe { ioctl_with_ref(&self.hv, MSHV_CHECK_EXTENSION(), &cap) };
        match ret {
            0 => Ok(false),
            r if r > 0 => Ok(true),
            _ => Err(errno::Error::last()),
        }
    }
    /// X86 specific call to get list of supported MSRS
    pub fn get_msr_index_list(&self) -> Result<MsrList> {
        /* return all the MSRs we currently support */
        Ok(MsrList::from_entries(&[
            IA32_MSR_TSC,
            IA32_MSR_EFER,
            IA32_MSR_KERNEL_GS_BASE,
            IA32_MSR_APIC_BASE,
            IA32_MSR_PAT,
            IA32_MSR_SYSENTER_CS,
            IA32_MSR_SYSENTER_ESP,
            IA32_MSR_SYSENTER_EIP,
            IA32_MSR_STAR,
            IA32_MSR_LSTAR,
            IA32_MSR_CSTAR,
            IA32_MSR_SFMASK,
            IA32_MSR_MTRR_DEF_TYPE,
            IA32_MSR_MTRR_PHYSBASE0,
            IA32_MSR_MTRR_PHYSMASK0,
            IA32_MSR_MTRR_PHYSBASE1,
            IA32_MSR_MTRR_PHYSMASK1,
            IA32_MSR_MTRR_PHYSBASE2,
            IA32_MSR_MTRR_PHYSMASK2,
            IA32_MSR_MTRR_PHYSBASE3,
            IA32_MSR_MTRR_PHYSMASK3,
            IA32_MSR_MTRR_PHYSBASE4,
            IA32_MSR_MTRR_PHYSMASK4,
            IA32_MSR_MTRR_PHYSBASE5,
            IA32_MSR_MTRR_PHYSMASK5,
            IA32_MSR_MTRR_PHYSBASE6,
            IA32_MSR_MTRR_PHYSMASK6,
            IA32_MSR_MTRR_PHYSBASE7,
            IA32_MSR_MTRR_PHYSMASK7,
            IA32_MSR_MTRR_FIX64K_00000,
            IA32_MSR_MTRR_FIX16K_80000,
            IA32_MSR_MTRR_FIX16K_a0000,
            IA32_MSR_MTRR_FIX4K_c0000,
            IA32_MSR_MTRR_FIX4K_c8000,
            IA32_MSR_MTRR_FIX4K_d0000,
            IA32_MSR_MTRR_FIX4K_d8000,
            IA32_MSR_MTRR_FIX4K_e0000,
            IA32_MSR_MTRR_FIX4K_e8000,
            IA32_MSR_MTRR_FIX4K_f0000,
            IA32_MSR_MTRR_FIX4K_f8000,
            IA32_MSR_TSC_AUX,
            IA32_MSR_BNDCFGS,
            IA32_MSR_DEBUG_CTL,
            IA32_MSR_SPEC_CTRL,
            //IA32_MSR_TSC_ADJUST, // Current hypervisor version does not allow to get this MSR, need to check later
        ])
        .unwrap())
    }
}
#[allow(dead_code)]
#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    #[ignore]
    fn test_create_vm() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm();
        assert!(vm.is_ok());
    }
    #[test]
    #[ignore]
    fn test_get_msr_index_list() {
        let hv = Mshv::new().unwrap();
        let msr_list = hv.get_msr_index_list().unwrap();
        assert!(msr_list.as_fam_struct_ref().nmsrs == 44);

        let mut found = false;
        for index in msr_list.as_slice() {
            if *index == IA32_MSR_SYSENTER_CS {
                found = true;
                break;
            }
        }
        assert!(found);

        /* Test all MSRs in the list individually and determine which can be get/set */
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut num_errors = 0;
        for idx in hv.get_msr_index_list().unwrap().as_slice().iter() {
            let mut get_set_msrs = Msrs::from_entries(&[msr_entry {
                index: *idx,
                ..Default::default()
            }])
            .unwrap();
            vcpu.get_msrs(&mut get_set_msrs).unwrap_or_else(|_| {
                println!("Error getting MSR: 0x{:x}", *idx);
                num_errors += 1;
                0
            });
            vcpu.set_msrs(&get_set_msrs).unwrap_or_else(|_| {
                println!("Error setting MSR: 0x{:x}", *idx);
                num_errors += 1;
                0
            });
        }
        assert!(num_errors == 0);
    }
}
