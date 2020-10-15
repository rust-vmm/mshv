// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::ioctls::vcpu::{new_vcpu, VcpuFd};
use crate::ioctls::Result;
use crate::mshv_ioctls::*;
use mshv_bindings::*;
use std::fs::File;

use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

/// Wrapper over Mshv VM ioctls.
pub struct VmFd {
    vm: File,
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

impl VmFd {
    ///
    /// Install intercept to enable some VM exits like MSR, CPUId etc
    ///
    pub fn install_intercept(&self, install_intercept_args: mshv_install_intercept) -> Result<()> {
        #[allow(clippy::cast_lossless)]
        let ret =
            unsafe { ioctl_with_ref(self, MSHV_INSTALL_INTERCEPT(), &install_intercept_args) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
    ///
    /// Creates/modifies a guest physical memory.
    ///
    pub fn map_user_memory(&self, user_memory_region: mshv_user_mem_region) -> Result<()> {
        #[allow(clippy::cast_lossless)]
        let ret = unsafe { ioctl_with_ref(self, MSHV_MAP_GUEST_MEMORY(), &user_memory_region) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
    ///
    /// Unmap a guest physical memory.
    ///
    pub fn umap_user_memory(&self, user_memory_region: mshv_user_mem_region) -> Result<()> {
        #[allow(clippy::cast_lossless)]
        let ret = unsafe { ioctl_with_ref(self, MSHV_UNMAP_GUEST_MEMORY(), &user_memory_region) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
    ///
    /// Creates a new MSHV vCPU file descriptor
    ///
    pub fn create_vcpu(&self, id: u8) -> Result<VcpuFd> {
        let vp_arg = mshv_create_vp {
            vp_index: id as __u32,
        };
        // Safe because we know that vm is a VM fd and we verify the return result.
        #[allow(clippy::cast_lossless)]
        let vcpu_fd = unsafe { ioctl_with_ref(&self.vm, MSHV_CREATE_VP(), &vp_arg) };
        if vcpu_fd < 0 {
            return Err(errno::Error::last());
        }

        // Wrap the vCPU now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        Ok(new_vcpu(vcpu))
    }
    ///
    /// Inject an interrupt into the guest..
    ///
    pub fn request_virtual_interrupt(
        &self,
        interrupt_type: hv_interrupt_type,
        apic_id: u64,
        vector: u32,
        level_triggered: bool,
        logical_destination_mode: bool,
        long_mode: bool,
    ) -> Result<()> {
        let mut control_flags: u32 = 0;
        if level_triggered {
            control_flags |= 0x1;
        }
        if logical_destination_mode {
            control_flags |= 0x2;
        }
        if long_mode {
            control_flags |= 1 << 30;
        }

        let interrupt_arg = mshv_assert_interrupt {
            control: hv_interrupt_control {
                as_uint64: interrupt_type as u64 | ((control_flags as u64) << 32),
            },
            dest_addr: apic_id,
            vector: vector,
        };
        #[allow(clippy::cast_lossless)]
        let ret = unsafe { ioctl_with_ref(&self.vm, MSHV_ASSERT_INTERRUPT(), &interrupt_arg) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
    ///
    /// Get property of the VM partition: For example , CPU Frequency, Size of the Xsave state and more.
    /// For more of the codes, please see the hv_partition_property_code type definitions in the bindings.rs
    ///
    pub fn get_partition_property(&self, code: u32) -> Result<u64> {
        let mut property: mshv_partition_property = mshv_partition_property::default();
        property.property_code = code;
        #[allow(clippy::cast_lossless)]
        let ret =
            unsafe { ioctl_with_mut_ref(&self.vm, HV_GET_PARTITION_PROPERTY(), &mut property) };
        if ret == 0 {
            Ok(property.property_value)
        } else {
            Err(errno::Error::last())
        }
    }
    ///
    /// Sets a partion property
    ///
    pub fn set_partition_property(&self, code: u32, value: u64) -> Result<()> {
        let property: mshv_partition_property = mshv_partition_property {
            property_code: code,
            property_value: value,
        };
        #[allow(clippy::cast_lossless)]
        let ret = unsafe { ioctl_with_ref(&self.vm, HV_SET_PARTITION_PROPERTY(), &property) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
}
/// Helper function to create a new `VmFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `create_vm` from `Mshv`. The function cannot be part of the `VmFd` implementation because
/// then it would be exported with the public `VmFd` interface.
pub fn new_vmfd(vm: File) -> VmFd {
    VmFd { vm }
}
