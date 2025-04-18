// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::ioctls::vm::{new_vmfd, VmFd, VmType};
use crate::ioctls::Result;
use crate::mshv_ioctls::*;
use crate::*;
use libc::{open, O_CLOEXEC, O_NONBLOCK};
use mshv_bindings::*;
use std::fs::File;
use std::os::raw::c_char;
use std::os::unix::io::{FromRawFd, RawFd};
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::ioctl_with_ref;

/// Wrapper over MSHV system ioctls.
#[derive(Debug)]
pub struct Mshv {
    hv: File,
}

impl Mshv {
    /// Opens `/dev/mshv` and returns a `Mshv` object on success.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Self> {
        // Open `/dev/mshv` using `O_CLOEXEC` flag.
        let fd = Self::open_with_cloexec(true)?;
        // SAFETY: we verify that ret is valid and we own the fd.
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
        // SAFETY: we give a constant null-terminated string and verify the result.
        let ret = unsafe { open(c"/dev/mshv".as_ptr() as *const c_char, open_flags) };
        if ret < 0 {
            Err(errno::Error::last().into())
        } else {
            Ok(ret)
        }
    }

    /// Creates a VM fd using the MSHV fd and prepared mshv partition.
    pub fn create_vm_with_args(&self, args: &mshv_create_partition) -> Result<VmFd> {
        // SAFETY: IOCTL call with the correct types.
        let ret = unsafe { ioctl_with_ref(&self.hv, MSHV_CREATE_PARTITION(), args) };
        if ret >= 0 {
            // SAFETY: we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            Ok(new_vmfd(vm_file))
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Retrieve the host partition property given a property code.
    pub fn get_host_partition_property(&self, property_code: u64) -> Result<i32> {
        // SAFETY: IOCTL call with the correct types.
        let ret =
            unsafe { ioctl_with_ref(&self.hv, MSHV_GET_HOST_PARTITION_PROPERTY(), &property_code) };
        if ret >= 0 {
            Ok(ret)
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Helper function to creates a VM fd using the MSHV fd with provided configuration.
    pub fn create_vm_with_type(&self, vm_type: VmType) -> Result<VmFd> {
        let mut features: hv_partition_synthetic_processor_features = Default::default();
        unsafe {
            let feature_bits = &mut features.__bindgen_anon_1;
            feature_bits.set_hypervisor_present(1);
            feature_bits.set_hv1(1);
            feature_bits.set_access_partition_reference_counter(1);
            feature_bits.set_access_synic_regs(1);
            feature_bits.set_access_synthetic_timer_regs(1);
            feature_bits.set_access_partition_reference_tsc(1);
            feature_bits.set_access_frequency_regs(1);
            feature_bits.set_access_intr_ctrl_regs(1);
            feature_bits.set_access_vp_index(1);
            feature_bits.set_access_hypercall_regs(1);
            #[cfg(not(target_arch = "aarch64"))]
            feature_bits.set_access_guest_idle_reg(1);
            feature_bits.set_tb_flush_hypercalls(1);
            feature_bits.set_synthetic_cluster_ipi(1);
            feature_bits.set_direct_synthetic_timers(1);
        }
        let pt_flags: u64 = set_bits!(
            u64,
            MSHV_PT_BIT_LAPIC,
            MSHV_PT_BIT_X2APIC,
            MSHV_PT_BIT_GPA_SUPER_PAGES
        );
        let mut pt_isolation: u64 = MSHV_PT_ISOLATION_NONE as u64;

        if vm_type == VmType::Snp {
            pt_isolation = MSHV_PT_ISOLATION_SNP as u64;
        }

        let create_args = mshv_create_partition {
            pt_flags,
            pt_isolation,
        };

        let vm = self.create_vm_with_args(&create_args)?;

        // This is an 'early' property that must be set between creation and initialization
        vm.hvcall_set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
            unsafe { features.as_uint64[0] },
        )?;

        vm.initialize()?;

        Ok(vm)
    }

    /// Creates a VM fd using the MSHV fd.
    pub fn create_vm(&self) -> Result<VmFd> {
        self.create_vm_with_type(VmType::Normal)
    }

    #[cfg(target_arch = "x86_64")]
    /// X86 specific call to get list of supported MSRs
    pub fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        let mut msrs: Vec<u32> = Vec::new();
        msrs.extend_from_slice(MSRS_COMMON);
        msrs.extend_from_slice(MSRS_CET_SS);
        msrs.extend_from_slice(MSRS_SYNIC);
        msrs.extend_from_slice(MSRS_OTHER);
        Ok(msrs)
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
    fn test_get_host_ipa_limit() {
        let hv = Mshv::new().unwrap();
        let host_ipa_limit = hv.get_host_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_PHYSICAL_ADDRESS_WIDTH as u64,
        );
        assert!(host_ipa_limit.is_ok());
    }

    #[test]
    #[ignore]
    fn test_create_vm_with_default_config() {
        let pr: mshv_create_partition = Default::default();
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm_with_args(&pr);
        assert!(vm.is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_get_msr_index_list() {
        let hv = Mshv::new().unwrap();
        let msr_list = hv.get_msr_index_list().unwrap();
        assert!(msr_list.len() == 73);

        let mut found = false;
        for index in msr_list {
            if index == IA32_MSR_SYSENTER_CS {
                found = true;
                break;
            }
        }
        assert!(found);

        /* Test all MSRs in the list individually and determine which can be get/set */
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut num_errors = 0;
        for idx in hv.get_msr_index_list().unwrap() {
            let mut get_set_msrs = Msrs::from_entries(&[msr_entry {
                index: idx,
                ..Default::default()
            }])
            .unwrap();
            vcpu.get_msrs(&mut get_set_msrs).unwrap_or_else(|_| {
                println!("Error getting MSR: 0x{:x}", idx);
                num_errors += 1;
                0
            });
            vcpu.set_msrs(&get_set_msrs).unwrap_or_else(|_| {
                println!("Error setting MSR: 0x{:x}", idx);
                num_errors += 1;
                0
            });
        }
        assert!(num_errors == 0);
    }
}
