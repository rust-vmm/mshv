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
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

/// Helper function to populate synthetic features for the partition to create
pub fn make_default_synthetic_features_mask() -> u64 {
    let mut features: hv_partition_synthetic_processor_features = Default::default();
    // SAFETY: access union fields
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
        #[cfg(not(target_arch = "aarch64"))]
        feature_bits.set_tb_flush_hypercalls(1);
        feature_bits.set_synthetic_cluster_ipi(1);
        feature_bits.set_direct_synthetic_timers(1);
        feature_bits.set_access_vp_regs(1);
    }

    // SAFETY: access union fields
    unsafe { features.as_uint64[0] }
}

/// Helper function to make partition creation argument
pub fn make_default_partition_create_arg(vm_type: VmType) -> mshv_create_partition_v2 {
    let pt_flags: u64 = set_bits!(
        u64,
        MSHV_PT_BIT_LAPIC,
        MSHV_PT_BIT_X2APIC,
        MSHV_PT_BIT_GPA_SUPER_PAGES,
        MSHV_PT_BIT_CPU_AND_XSAVE_FEATURES
    );
    let mut pt_isolation: u64 = MSHV_PT_ISOLATION_NONE as u64;

    if vm_type == VmType::Snp {
        pt_isolation = MSHV_PT_ISOLATION_SNP as u64;
    }

    let mut create_args = mshv_create_partition_v2 {
        pt_flags,
        pt_isolation,
        pt_num_cpu_fbanks: MSHV_NUM_CPU_FEATURES_BANKS as u16,
        ..Default::default()
    };

    let mut proc_features = hv_partition_processor_features::default();
    let mut xsave_features = hv_partition_processor_xsave_features::default();
    for i in 0..MSHV_NUM_CPU_FEATURES_BANKS {
        // SAFETY: access union fields
        unsafe {
            proc_features.as_uint64[i as usize] = 0xFFFFFFFFFFFFFFFF;
        }
    }
    xsave_features.as_uint64 = 0xFFFFFFFFFFFFFFFF;

    #[cfg(target_arch = "x86_64")]
    // SAFETY: access union fields
    unsafe {
        // Enable default XSave features that are known to be supported
        xsave_features.__bindgen_anon_1.set_avx_support(0u64);
        xsave_features.__bindgen_anon_1.set_xsave_comp_support(0u64);
        xsave_features
            .__bindgen_anon_1
            .set_xsave_supervisor_support(0u64);
        xsave_features.__bindgen_anon_1.set_xsave_support(0u64);
        xsave_features.__bindgen_anon_1.set_xsaveopt_support(0u64);
        create_args.pt_disabled_xsave = xsave_features.as_uint64;

        // Enable default processor features that are known to be supported
        proc_features.__bindgen_anon_1.set_adx_support(0u64);
        proc_features.__bindgen_anon_1.set_aes_support(0u64);
        proc_features.__bindgen_anon_1.set_altmovcr8_support(0u64);
        proc_features.__bindgen_anon_1.set_amd3dnow_support(0u64);
        proc_features.__bindgen_anon_1.set_bhi_dis_support(0u64);
        proc_features.__bindgen_anon_1.set_bhi_no_support(0u64);
        proc_features.__bindgen_anon_1.set_bmi1_support(0u64);
        proc_features.__bindgen_anon_1.set_bmi2_support(0u64);
        proc_features.__bindgen_anon_1.set_btc_no_support(0u64);
        proc_features.__bindgen_anon_1.set_cet_ibt_support(0u64);
        proc_features.__bindgen_anon_1.set_cet_ss_support(0u64);
        proc_features.__bindgen_anon_1.set_clflushopt_support(0u64);
        proc_features.__bindgen_anon_1.set_cmpxchg16b_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_dep_x87_fpu_save_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_enhanced_fast_string_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_extended_amd3dnow_support(0u64);
        proc_features.__bindgen_anon_1.set_f16c_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_fast_short_rep_mov_support(0u64);
        proc_features.__bindgen_anon_1.set_fb_clear_support(0u64);
        proc_features.__bindgen_anon_1.set_fma4_support(0u64);
        proc_features.__bindgen_anon_1.set_gds_no_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_hle_support_deprecated(0u64);
        proc_features.__bindgen_anon_1.set_hle_support(0u64);
        proc_features.__bindgen_anon_1.set_ibpb_support(0u64);
        proc_features.__bindgen_anon_1.set_ibrs_all_support(0u64);
        proc_features.__bindgen_anon_1.set_ibrs_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_intel_prefetch_support(0u64);
        proc_features.__bindgen_anon_1.set_invpcid_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_l1dcache_flush_support(0u64);
        proc_features.__bindgen_anon_1.set_lahf_sahf_support(0u64);
        proc_features.__bindgen_anon_1.set_lzcnt_support(0u64);
        proc_features.__bindgen_anon_1.set_mb_clear_support(0u64);
        proc_features.__bindgen_anon_1.set_mbec_support(0u64);
        proc_features.__bindgen_anon_1.set_mbs_no_support(0u64);
        proc_features.__bindgen_anon_1.set_mdd_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_mis_align_sse_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_mitigation_ctrl_support(0u64);
        proc_features.__bindgen_anon_1.set_mmx_ext_support(0u64);
        proc_features.__bindgen_anon_1.set_movbe_support(0u64);
        proc_features.__bindgen_anon_1.set_npiep1_support(0u64);
        proc_features.__bindgen_anon_1.set_page_1gb_support(0u64);
        proc_features.__bindgen_anon_1.set_pclmulqdq_support(0u64);
        proc_features.__bindgen_anon_1.set_pcid_support(0u64);
        proc_features.__bindgen_anon_1.set_pop_cnt_support(0u64);
        proc_features.__bindgen_anon_1.set_psfd_support(0u64);
        proc_features.__bindgen_anon_1.set_rd_pid_support(0u64);
        proc_features.__bindgen_anon_1.set_rd_rand_support(0u64);
        proc_features.__bindgen_anon_1.set_rd_rand_support(0u64);
        proc_features.__bindgen_anon_1.set_rd_seed_support(0u64);
        proc_features.__bindgen_anon_1.set_rd_wr_fs_gs_support(0u64);
        proc_features.__bindgen_anon_1.set_rdcl_no_support(0u64);
        proc_features.__bindgen_anon_1.set_rdpru_support(0u64);
        proc_features.__bindgen_anon_1.set_rdtscp_support(0u64);
        proc_features.__bindgen_anon_1.set_rfds_clear_support(0u64);
        proc_features.__bindgen_anon_1.set_rfds_no_support(0u64);
        proc_features.__bindgen_anon_1.set_rsb_a_no_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_rtm_support_deprecated(0u64);
        proc_features.__bindgen_anon_1.set_rtm_support(0u64);
        proc_features.__bindgen_anon_1.set_skip_l1df_support(0u64);
        proc_features.__bindgen_anon_1.set_smap_support(0u64);
        proc_features.__bindgen_anon_1.set_smep_support(0u64);
        proc_features.__bindgen_anon_1.set_ssb_no_support(0u64);
        proc_features.__bindgen_anon_1.set_sse3_support(0u64);
        proc_features.__bindgen_anon_1.set_sse4_1_support(0u64);
        proc_features.__bindgen_anon_1.set_sse4_2_support(0u64);
        proc_features.__bindgen_anon_1.set_sse4a_support(0u64);
        proc_features.__bindgen_anon_1.set_ssse3_support(0u64);
        proc_features.__bindgen_anon_1.set_stibp_support(0u64);
        proc_features.__bindgen_anon_1.set_taa_no_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_tsc_invariant_support(0u64);
        proc_features.__bindgen_anon_1.set_tsx_ctrl_support(0u64);
        proc_features.__bindgen_anon_1.set_umip_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_unrestricted_guest_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_virt_spec_ctrl_support(0u64);
        proc_features
            .__bindgen_anon_1
            .set_vmx_exception_inject_support(0u64);
        proc_features.__bindgen_anon_1.set_xop_support(0u64);
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: access union fields
    unsafe {
        // This must always be enabled for ARM64 guests.
        proc_features.__bindgen_anon_1.set_gic_v3v4(0u64);

        proc_features.__bindgen_anon_1.set_fp(0);
        proc_features.__bindgen_anon_1.set_fp_hp(0);
        proc_features.__bindgen_anon_1.set_adv_simd(0);
        proc_features.__bindgen_anon_1.set_adv_simd_hp(0);

        proc_features.__bindgen_anon_1.set_pmu_v3(0);
    }

    // SAFETY: access union fields
    unsafe {
        for i in 0..MSHV_NUM_CPU_FEATURES_BANKS {
            create_args.pt_cpu_fbanks[i as usize] = proc_features.as_uint64[i as usize];
        }
    }

    create_args
}

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
    pub fn create_vm_with_args(&self, args: &mshv_create_partition_v2) -> Result<VmFd> {
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
    pub fn get_host_partition_property(&self, property_code: u32) -> Result<u64> {
        let mut property = mshv_partition_property {
            property_code: property_code as u64,
            ..Default::default()
        };
        // SAFETY: IOCTL call with the correct types.
        let ret = unsafe {
            ioctl_with_mut_ref(&self.hv, MSHV_GET_HOST_PARTITION_PROPERTY(), &mut property)
        };
        if ret == 0 {
            Ok(property.property_value)
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Helper function to creates a VM fd using the MSHV fd with provided configuration.
    pub fn create_vm_with_type(&self, vm_type: VmType) -> Result<VmFd> {
        let create_args = make_default_partition_create_arg(vm_type);

        let vm = self.create_vm_with_args(&create_args)?;

        // This is an 'early' property that must be set between creation and initialization
        vm.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
            make_default_synthetic_features_mask(),
        )?;

        Ok(vm)
    }

    /// Creates a VM fd using the MSHV fd.
    pub fn create_vm(&self) -> Result<VmFd> {
        self.create_vm_with_type(VmType::Normal)
    }

    /// Execute a hypercall targeting the host partition (self).
    fn hvcall(&self, args: &mut mshv_root_hvcall) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_mut_ref(&self.hv, MSHV_ROOT_HVCALL(), args) };
        if ret == 0 {
            Ok(())
        } else {
            Err(MshvError::from_hvcall(errno::Error::last(), *args))
        }
    }

    fn get_host_partition_property_ex(
        &self,
        property_code: u32,
    ) -> Result<Box<hv_partition_property_ex>> {
        let mut input = hv_input_get_partition_property_ex {
            property_code,
            ..Default::default() // NOTE: Kernel will populate partition_id field
        };

        input.__bindgen_anon_1.arg = 0;

        let mut output = Box::new(hv_partition_property_ex::default());

        let mut args = make_args!(HVCALL_GET_PARTITION_PROPERTY_EX, input, *output);

        self.hvcall(&mut args).map(|_| output)
    }

    /// Get VMM capabilities
    pub fn get_vmm_caps(&self) -> Result<hv_partition_property_vmm_capabilities> {
        match self.get_host_partition_property_ex(
            hv_partition_property_code_HV_PARTITION_PROPERTY_VMM_CAPABILITIES,
        ) {
            Ok(output) => {
                // SAFETY: accessing union fields
                let vmm_caps = unsafe { output.vmm_capabilities };
                Ok(vmm_caps)
            }
            Err(MshvError::Hypercall {
                status: Some(HvError::AccessDenied),
                ..
            }) => {
                // If the hypercall fails with AccessDenied, it means the
                // VMM capabilities query is not supported on this MSHV version.
                // As per the hypervisor team, we should treat this case as if
                // none of the capabilities are set. So, return a zeroed out struct.
                Ok(hv_partition_property_vmm_capabilities::default())
            }
            Err(e) => Err(e),
        }
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
            hv_partition_property_code_HV_PARTITION_PROPERTY_PHYSICAL_ADDRESS_WIDTH,
        );
        assert!(host_ipa_limit.is_ok());
    }

    #[test]
    #[ignore]
    fn test_create_vm_with_default_config() {
        let pr: mshv_create_partition_v2 = make_default_partition_create_arg(VmType::Normal);
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm_with_args(&pr);
        assert!(vm.is_ok());
    }

    #[test]
    fn test_vmm_caps() {
        let hv = Mshv::new().unwrap();
        let vmm_caps = hv.get_vmm_caps();
        assert!(vmm_caps.is_ok());
    }
}
