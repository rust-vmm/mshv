// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::ioctls::vm::{new_vmfd, VmFd, VmType};
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
#[derive(Debug)]
pub struct Mshv {
    hv: File,
}

/// Builder for MSHV Partition
#[derive(Default)]
pub struct MshvPartitionBuilder {
    mshv_partition: mshv_create_partition,
}

#[derive(Debug)]
///
pub enum SyntheticProcessorFeature {
    /// Report a hypervisor is present.
    HypervisorPresent,
    /// Report support for Hv1.
    Hv1,
    /// Access to HV_X64_MSR_TIME_REF_COUNT.Corresponds to access_partition_reference_counter privilege.
    AccessPartitionReferenceCounter,
    /// Access to SINT-related registers (HV_X64_MSR_SCONTROL through HV_X64_MSR_EOM and HV_X64_MSR_SINT0 through HV_X64_MSR_SINT15). Corresponds to access_synic_regs privilege.
    AccessSynicRegs,
    /// Access to synthetic timers and associated MSRs (HV_X64_MSR_STIMER0_CONFIG through HV_X64_MSR_STIMER3_COUNT).Corresponds to access_synthetic_timer_regs privilege.
    AccessSyntheticTimerRegs,
    /// Access to the reference TSC. Corresponds to access_partition_reference_tsc privilege.
    AccessPartitionReferenceTsc,
    /// Partition has access to frequency regs. corresponds to access_frequency_regs privilege.
    AccessFrequencyRegs,
    /// Access to APIC MSRs (HV_X64_MSR_EOI, HV_X64_MSR_ICR and HV_X64_MSR_TPR) as well as the VP assist page. Corresponds to access_intr_ctrl_regs privilege.
    AccessIntrCtrlRegs,
    /// VP index can be queried. corresponds to access_vp_index privilege.
    AccessVpIndex,
    /// Access to registers associated with hypercalls (HV_X64_MSR_GUEST_OS_ID and HV_X64_MSR_HYPERCALL).Corresponds to access_hypercall_msrs privilege.
    AccessHypercallRegs,
    /// Partition has access to the guest idle reg. Corresponds to access_guest_idle_reg privilege.
    AccessGuestIdleReg,
    ///  HvCallFlushVirtualAddressSpace / HvCallFlushVirtualAddressList are supported.
    TbFlushHypercalls,
    /// HvCallSendSyntheticClusterIpi is supported.
    SyntheticClusterIpi,
}

impl MshvPartitionBuilder {
    /// Creates a new MshvPartitionBuilder
    pub fn new() -> MshvPartitionBuilder {
        MshvPartitionBuilder {
            mshv_partition: mshv_create_partition {
                partition_creation_properties: hv_partition_creation_properties {
                    disabled_processor_features: hv_partition_processor_features {
                        as_uint64: [0; 2],
                    },
                    disabled_processor_xsave_features: hv_partition_processor_xsave_features {
                        as_uint64: 0_u64,
                    },
                },
                synthetic_processor_features: hv_partition_synthetic_processor_features {
                    as_uint64: [0; 1],
                },
                isolation_properties: hv_partition_isolation_properties { as_uint64: 0_u64 },
                flags: 0_u64,
            },
        }
    }

    /// Updates partition flags
    pub fn set_partiton_creation_flag(mut self, flag: u64) -> MshvPartitionBuilder {
        self.mshv_partition.flags |= flag;
        self
    }

    /// Set isolation type
    pub fn set_isolation_type(mut self, val: u64) -> MshvPartitionBuilder {
        // SAFETY: Setting a bunch of bitfields. Functions and unions are generated by bindgen
        // so we have to use unsafe here. We trust bindgen to generate the correct accessors.
        unsafe {
            self.mshv_partition
                .isolation_properties
                .__bindgen_anon_1
                .set_isolation_type(val);
        }
        self
    }

    /// Set shared GPA boundary page number
    pub fn set_shared_gpa_boundary_page_number(mut self, val: u64) -> MshvPartitionBuilder {
        // SAFETY: Setting a bunch of bitfields. Functions and unions are generated by bindgen
        // so we have to use unsafe here. We trust bindgen to generate the correct accessors.
        unsafe {
            self.mshv_partition
                .isolation_properties
                .__bindgen_anon_1
                .set_shared_gpa_boundary_page_number(val);
        }
        self
    }

    /// Sets a synthetic_processor_feature for the partition
    pub fn set_synthetic_processor_feature(
        mut self,
        feature: SyntheticProcessorFeature,
    ) -> MshvPartitionBuilder {
        // SAFETY: Setting a bunch of bitfields. Functions and unions are generated by bindgen
        // so we have to use unsafe here. We trust bindgen to generate the correct accessors.
        match feature {
            SyntheticProcessorFeature::HypervisorPresent => unsafe {
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_hypervisor_present(1);
            },
            SyntheticProcessorFeature::Hv1 => unsafe {
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_hv1(1);
            },
            SyntheticProcessorFeature::AccessPartitionReferenceCounter => unsafe {
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_partition_reference_counter(1);
            },
            SyntheticProcessorFeature::AccessSynicRegs => unsafe {
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_synic_regs(1);
            },
            SyntheticProcessorFeature::AccessSyntheticTimerRegs => unsafe {
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_synthetic_timer_regs(1);
            },
            SyntheticProcessorFeature::AccessPartitionReferenceTsc => unsafe {
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_partition_reference_tsc(1);
            },
            SyntheticProcessorFeature::AccessFrequencyRegs => unsafe {
                /* Need this for linux on CH, as there's no PIT or HPET */
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_frequency_regs(1);
            },
            SyntheticProcessorFeature::AccessIntrCtrlRegs => unsafe {
                /* Linux I'm using appears to require vp assist page... */
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_intr_ctrl_regs(1);
            },
            SyntheticProcessorFeature::AccessVpIndex => unsafe {
                /* According to Hv#1 spec, these must be set also, but they aren't in KVM? */
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_vp_index(1);
            },
            SyntheticProcessorFeature::AccessHypercallRegs => unsafe {
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_hypercall_regs(1);
            },
            SyntheticProcessorFeature::AccessGuestIdleReg => unsafe {
                /* Windows requires this */
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_access_guest_idle_reg(1);
            },
            SyntheticProcessorFeature::TbFlushHypercalls => unsafe {
                /* Enable TLB flush hypercalls */
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_tb_flush_hypercalls(1);
            },
            SyntheticProcessorFeature::SyntheticClusterIpi => unsafe {
                /* Enable synthetic cluster ipi */
                self.mshv_partition
                    .synthetic_processor_features
                    .__bindgen_anon_1
                    .set_synthetic_cluster_ipi(1);
            },
        }
        self
    }
    /// Builds the partition
    pub fn build(&self) -> mshv_create_partition {
        self.mshv_partition
    }
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
        let ret = unsafe { open("/dev/mshv\0".as_ptr() as *const c_char, open_flags) };
        if ret < 0 {
            Err(errno::Error::last())
        } else {
            Ok(ret)
        }
    }

    /// Creates a VM fd using the MSHV fd and prepared mshv partition.
    pub fn create_vm_with_config(&self, pr: &mshv_create_partition) -> Result<VmFd> {
        // SAFETY: IOCTL call with the correct types.
        let ret = unsafe { ioctl_with_ref(&self.hv, MSHV_CREATE_PARTITION(), pr) };
        if ret >= 0 {
            // SAFETY: we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            Ok(new_vmfd(vm_file))
        } else {
            Err(errno::Error::last())
        }
    }

    /// Helper function to creates a VM fd using the MSHV fd with provided configuration.
    pub fn create_vm_with_type(&self, vm_type: VmType) -> Result<VmFd> {
        let mut mshv_builder = MshvPartitionBuilder::new()
            .set_partiton_creation_flag(HV_PARTITION_CREATION_FLAG_LAPIC_ENABLED as u64)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::HypervisorPresent)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::Hv1)
            .set_synthetic_processor_feature(
                SyntheticProcessorFeature::AccessPartitionReferenceCounter,
            )
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessSynicRegs)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessSyntheticTimerRegs)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessPartitionReferenceTsc)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessFrequencyRegs)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessIntrCtrlRegs)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessVpIndex)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessHypercallRegs)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::AccessGuestIdleReg)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::TbFlushHypercalls)
            .set_synthetic_processor_feature(SyntheticProcessorFeature::SyntheticClusterIpi);

        if vm_type == VmType::Snp {
            mshv_builder = mshv_builder
                .set_partiton_creation_flag(HV_PARTITION_CREATION_FLAG_X2APIC_CAPABLE as u64)
                .set_isolation_type(HV_PARTITION_ISOLATION_TYPE_SNP as u64)
                .set_shared_gpa_boundary_page_number(0_u64);
        }

        let partition_config = mshv_builder.build();
        self.create_vm_with_config(&partition_config)
    }

    /// Creates a VM fd using the MSHV fd.
    pub fn create_vm(&self) -> Result<VmFd> {
        self.create_vm_with_type(VmType::Normal)
    }

    /// Check if MSHV API is stable
    pub fn check_stable(&self) -> Result<bool> {
        // Safe because we know `self.hv` is a real MSHV fd as this module is the only one that
        // creates mshv objects.
        let cap: u32 = MSHV_CAP_CORE_API_STABLE;
        // SAFETY: IOCTL call with the correct types.
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
            IA32_MSR_MTRR_FIX16K_A0000,
            IA32_MSR_MTRR_FIX4K_C0000,
            IA32_MSR_MTRR_FIX4K_C8000,
            IA32_MSR_MTRR_FIX4K_D0000,
            IA32_MSR_MTRR_FIX4K_D8000,
            IA32_MSR_MTRR_FIX4K_E0000,
            IA32_MSR_MTRR_FIX4K_E8000,
            IA32_MSR_MTRR_FIX4K_F0000,
            IA32_MSR_MTRR_FIX4K_F8000,
            IA32_MSR_TSC_AUX,
            /*
                IA32_MSR_BNDCFGS MSR can be accessed if any of the following features enabled
                HV_X64_PROCESSOR_FEATURE0_IBRS
                HV_X64_PROCESSOR_FEATURE0_STIBP
                HV_X64_PROCESSOR_FEATURE0_MDD
                HV_X64_PROCESSOR_FEATURE1_PSFD
            */
            //IA32_MSR_BNDCFGS,
            IA32_MSR_DEBUG_CTL,
            /*
                MPX support needed for this MSR
                Currently feature is not enabled
            */
            //IA32_MSR_SPEC_CTRL,
            //IA32_MSR_TSC_ADJUST, // Current hypervisor version does not allow to get this MSR, need to check later
            HV_X64_MSR_GUEST_OS_ID,
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
    fn test_create_vm_with_default_config() {
        let pr: mshv_create_partition = Default::default();
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm_with_config(&pr);
        assert!(vm.is_ok());
    }
    #[test]
    #[ignore]
    fn test_get_msr_index_list() {
        let hv = Mshv::new().unwrap();
        let msr_list = hv.get_msr_index_list().unwrap();
        assert!(msr_list.as_fam_struct_ref().nmsrs == 45);

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
