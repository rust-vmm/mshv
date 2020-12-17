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
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

/// Structure for injecting interurpt
/// This struct is passed to request_virtual_interrupt function as an argument
/// Member variable
///     interrupt_type: Type of the interrupt
///     apic_id: Advanced Programmable Interrupt Controller Identification Number
///     Vector: APIC Vector (entry of Interrupt Vector Table i.e IVT)
///     level_triggered: True means level triggered, false means edge triggered
///     logical_destination_mode: lTrue means the APIC ID is logical, false means physical
///     long_mode: True means CPU is in long mode
///
pub struct InterruptRequest {
    pub interrupt_type: hv_interrupt_type,
    pub apic_id: u64,
    pub vector: u32,
    pub level_triggered: bool,
    pub logical_destination_mode: bool,
    pub long_mode: bool,
}
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
    pub fn request_virtual_interrupt(&self, request: &InterruptRequest) -> Result<()> {
        let mut control_flags: u32 = 0;
        if request.level_triggered {
            control_flags |= 0x1;
        }
        if request.logical_destination_mode {
            control_flags |= 0x2;
        }
        if request.long_mode {
            control_flags |= 1 << 30;
        }

        let interrupt_arg = mshv_assert_interrupt {
            control: hv_interrupt_control {
                as_uint64: request.interrupt_type as u64 | ((control_flags as u64) << 32),
            },
            dest_addr: request.apic_id,
            vector: request.vector,
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
    /// irqfd: Passes in an eventfd which is to be used for injecting
    /// interrupts from userland.
    ///
    fn irqfd(
        &self,
        fd: RawFd,
        gsi: u32,
        request: Option<&InterruptRequest>,
        flags: u32,
    ) -> Result<()> {
        let mut irqfd_arg = mshv_irqfd {
            fd: fd as i32,
            flags,
            resamplefd: 0,
            gsi,
            vector: 0,
            apic_id: 0,
            interrupt_type: 0,
            level_triggered: 0,
            logical_dest_mode: 0,
            ..Default::default()
        };

        if let Some(r) = request {
            irqfd_arg.vector = r.vector;
            irqfd_arg.apic_id = r.apic_id;
            irqfd_arg.interrupt_type = r.interrupt_type as u32;
            irqfd_arg.level_triggered = if r.level_triggered { 1 } else { 0 };
            irqfd_arg.logical_dest_mode = if r.logical_destination_mode { 1 } else { 0 };
        }

        #[allow(clippy::cast_lossless)]
        let ret = unsafe { ioctl_with_ref(&self.vm, MSHV_IRQFD(), &irqfd_arg) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` to be signaled.
    /// * `gsi` - IRQ to be triggered.
    /// * `req` - Interrupt Request
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// # use crate::mshv_ioctls::*;
    /// # use mshv_bindings::*;
    /// let hv = Mshv::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let req = InterruptRequest {
    ///     interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_FIXED,
    ///     apic_id: 0,
    ///     vector: 0,
    ///     level_triggered: false,
    ///     logical_destination_mode: false,
    ///     long_mode: false,
    /// };
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm.register_irqfd(&evtfd, 0, &req).unwrap();
    /// ```
    ///
    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32, request: &InterruptRequest) -> Result<()> {
        self.irqfd(fd.as_raw_fd(), gsi, Some(&request), 0)
    }
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` to be signaled.
    /// * `gsi` - IRQ to be triggered.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// # use crate::mshv_ioctls::*;
    /// # use mshv_bindings::*;
    /// let hv = Mshv::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let req = InterruptRequest {
    ///     interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_FIXED,
    ///     apic_id: 0,
    ///     vector: 0,
    ///     level_triggered: false,
    ///     logical_destination_mode: false,
    ///     long_mode: false,
    /// };
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm.register_irqfd(&evtfd, 0, &req).unwrap();
    /// vm.unregister_irqfd(&evtfd, 0).unwrap();
    /// ```
    ///
    pub fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.irqfd(fd.as_raw_fd(), gsi, None, MSHV_IRQFD_FLAG_DEASSIGN)
    }

    ///
    /// Get property of the VM partition: For example , CPU Frequency, Size of the Xsave state and more.
    /// For more of the codes, please see the hv_partition_property_code type definitions in the bindings.rs
    ///
    pub fn get_partition_property(&self, code: u32) -> Result<u64> {
        let mut property = mshv_partition_property {
            property_code: code,
            ..Default::default()
        };
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
#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::ioctls::system::Mshv;

    #[test]
    fn test_user_memory() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        let mem = mshv_user_mem_region {
            flags: HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | HV_MAP_GPA_EXECUTABLE,
            guest_pfn: 0x1,
            size: 0x1000,
            userspace_addr: addr as u64,
        };

        vm.map_user_memory(mem).unwrap();

        vm.umap_user_memory(mem).unwrap();
    }
    #[test]
    fn test_create_vcpu() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0);
        assert!(vcpu.is_ok());
    }
    #[test]
    fn test_assert_virtual_interrupt() {
        /* TODO better test with some code */
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let state: LapicState = LapicState::default();
        let vp_state: mshv_vp_state = mshv_vp_state::from(state);
        vcpu.get_vp_state_ioctl(&vp_state).unwrap();
        let lapic: hv_local_interrupt_controller_state = unsafe { *(vp_state.buf.lapic) };
        let cfg = InterruptRequest {
            interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_EXTINT,
            apic_id: lapic.apic_id as u64,
            vector: 0,
            level_triggered: false,
            logical_destination_mode: false,
            long_mode: false,
        };
        vm.request_virtual_interrupt(&cfg).unwrap();
    }
    #[test]
    fn test_install_intercept() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let intercept_args = mshv_install_intercept {
            access_type_mask: HV_INTERCEPT_ACCESS_MASK_EXECUTE,
            intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_X64_CPUID,
            intercept_parameter: hv_intercept_parameters { cpuid_index: 0x100 },
        };
        vm.install_intercept(intercept_args).unwrap();
    }
    #[test]
    fn test_get_set_property() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();

        let mut val = vm
            .get_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_MAX_XSAVE_DATA_SIZE,
            )
            .unwrap();
        println!("Max xsave data size: {} bytes", val);
        val = vm
            .get_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_PROCESSOR_XSAVE_FEATURES,
            )
            .unwrap();
        println!("Xsave feature: {}", val);
        val = vm
            .get_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_PROCESSOR_CLOCK_FREQUENCY,
            )
            .unwrap();
        println!("Processor frequency: {}", val);
        vm.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_PRIVILEGE_FLAGS,
            0,
        )
        .unwrap();
    }
    #[test]
    fn test_irqfd() {
        use libc::EFD_NONBLOCK;
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let req = InterruptRequest {
            interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_EXTINT,
            apic_id: 0,
            vector: 0,
            level_triggered: false,
            logical_destination_mode: false,
            long_mode: false,
        };
        let efd = EventFd::new(EFD_NONBLOCK).unwrap();
        vm.register_irqfd(&efd, 0, &req).unwrap();
        vm.unregister_irqfd(&efd, 0).unwrap();
    }
}
