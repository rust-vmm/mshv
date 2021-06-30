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

/// An address either in programmable I/O space or in memory mapped I/O space.
///
/// The `IoEventAddress` is used for specifying the type when registering an event
/// in [register_ioevent](struct.VmFd.html#method.register_ioevent).
///
#[derive(Eq, PartialEq, Hash, Clone, Debug, Copy)]
pub enum IoEventAddress {
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
    Mmio(u64),
}

/// Helper structure for disabling datamatch.
///
/// The structure can be used as a parameter to
/// [`register_ioevent`](struct.VmFd.html#method.register_ioevent)
/// to disable filtering of events based on the datamatch flag.
///
pub struct NoDatamatch;

impl From<NoDatamatch> for u64 {
    fn from(s: NoDatamatch) -> u64 {
        0
    }
}

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
    pub fn unmap_user_memory(&self, user_memory_region: mshv_user_mem_region) -> Result<()> {
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
    fn irqfd(&self, fd: RawFd, gsi: u32, flags: u32) -> Result<()> {
        let mut irqfd_arg = mshv_irqfd {
            fd: fd as i32,
            flags,
            resamplefd: 0,
            gsi,
        };

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
    /// ```no_run
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// # use crate::mshv_ioctls::*;
    /// # use mshv_bindings::*;
    /// let hv = Mshv::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm.register_irqfd(&evtfd, 30).unwrap();
    /// ```
    ///
    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.irqfd(fd.as_raw_fd(), gsi, 0)
    }
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` to be signaled.
    /// * `gsi` - IRQ to be triggered.
    ///
    /// # Example
    /// ```no_run
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// # use crate::mshv_ioctls::*;
    /// # use mshv_bindings::*;
    /// let hv = Mshv::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm.register_irqfd(&evtfd, 30).unwrap();
    /// vm.unregister_irqfd(&evtfd, 30).unwrap();
    /// ```
    ///
    pub fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.irqfd(fd.as_raw_fd(), gsi, MSHV_IRQFD_FLAG_DEASSIGN)
    }

    /// Sets the MSI routing table entries, overwriting any previously set
    /// entries, as per the `MSHV_SET_MSI_ROUTING` ioctl.
    ///
    /// Returns an io::Error when the table could not be updated.
    ///
    /// # Arguments
    ///
    /// * mshv_msi_routing - MSI routing configuration.
    ///
    /// # Example
    /// ```no_run
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// # use crate::mshv_ioctls::*;
    /// # use mshv_bindings::*;
    /// let hv = Mshv::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    ///
    /// let msi_routing = mshv_msi_routing::default();
    /// vm.set_msi_routing(&msi_routing).unwrap();
    /// ```
    ///
    pub fn set_msi_routing(&self, msi_routing: &mshv_msi_routing) -> Result<()> {
        // Safe because we allocated the structure and we know the kernel
        // will read exactly the size of the structure.
        let ret = unsafe { ioctl_with_ref(self, MSHV_SET_MSI_ROUTING(), msi_routing) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }

    ///
    /// ioeventfd: Passes in an eventfd which the kernel would signal when
    /// an mmio region is written into.
    ///
    fn ioeventfd<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
        mut flags: u32,
    ) -> Result<()> {
        let mut mmio_addr: u64;

        //
        // mshv doesn't support PIO ioeventfds now.
        //
        mmio_addr = match addr {
            IoEventAddress::Pio(_) => {
                return Err(errno::Error::new(libc::ENOTSUP));
            }
            IoEventAddress::Mmio(ref m) => *m,
        };

        if std::mem::size_of::<T>() > 0 {
            flags |= 1 << mshv_ioeventfd_flag_nr_datamatch
        }

        let ioeventfd = mshv_ioeventfd {
            datamatch: datamatch.into(),
            len: std::mem::size_of::<T>() as u32,
            addr: mmio_addr,
            fd: fd.as_raw_fd(),
            flags,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, MSHV_IOEVENTFD(), &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }
    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` which will be signaled. When signaling, the usual `vmexit` to userspace
    ///           is prevented.
    /// * `addr` - Address being written to.
    /// * `datamatch` - Limits signaling `fd` to only the cases where the value being written is
    ///                 equal to this parameter. The size of `datamatch` is important and it must
    ///                 match the expected size of the guest's write.
    ///
    /// # Example
    /// ```no_run
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// # use crate::mshv_ioctls::*;
    /// # use mshv_bindings::*;
    /// let hv = Mshv::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm.register_ioevent(&evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
    ///   .unwrap();
    /// ```
    ///
    pub fn register_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        self.ioeventfd(fd, addr, datamatch, 0)
    }
    /// Unregisters an event from a certain address it has been previously registered to.
    ///
    /// # Arguments
    ///
    /// * `fd` - FD which will be unregistered.
    /// * `addr` - Address being written to.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it relies on RawFd.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// # use crate::mshv_ioctls::*;
    /// # use mshv_bindings::*;
    /// let hv = Mshv::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm.register_ioevent(&evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
    ///   .unwrap();
    /// vm.unregister_ioevent(&evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
    ///   .unwrap();
    /// ```
    ///
    pub fn unregister_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        self.ioeventfd(fd, addr, datamatch, 1 << mshv_ioeventfd_flag_nr_deassign)
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
    ///
    /// Enable dirty page tracking by hypervisor
    /// Flags:
    ///         bit 1: Enabled
    ///         bit 2: Granularity
    ///
    pub fn enable_dirty_page_tracking(&self) -> Result<()> {
        let flag: u64 = 0x1;
        self.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_GPA_PAGE_ACCESS_TRACKING,
            flag,
        )
    }
    ///
    /// Disable dirty page tracking by hypervisor
    /// Prerequisite: It is required to set the dirty bits if cleared
    /// previously, otherwise this hypercall will be failed.
    /// Flags:
    ///         bit 1: Enabled
    ///         bit 2: Granularity
    ///
    pub fn disable_dirty_page_tracking(&self) -> Result<()> {
        let flag: u64 = 0x0;
        self.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_GPA_PAGE_ACCESS_TRACKING,
            flag,
        )
    }
    ///
    /// Get page access state
    /// The data provides each page's access state whether it is dirty or accessed
    /// Prerequisite: Need to enable page_acess_tracking
    /// Flags:
    ///         bit 1: ClearAccessed
    ///         bit 2: SetAccessed
    ///         bit 3: ClearDirty
    ///         bit 4: SetDirty
    ///         Number of bits reserved: 60
    ///
    pub fn get_gpa_access_state(
        &self,
        base_pfn: u64,
        nr_pfns: u32,
        flags: u64,
    ) -> Result<mshv_get_gpa_pages_access_state> {
        let mut states: Vec<hv_gpa_page_access_state> =
            vec![hv_gpa_page_access_state { as_uint8: 0 }; nr_pfns as usize];
        let mut gpa_pages_access_state: mshv_get_gpa_pages_access_state =
            mshv_get_gpa_pages_access_state {
                count: nr_pfns as u32,
                hv_gpa_page_number: base_pfn,
                flags,
                states: states.as_mut_ptr(),
            };

        let ret = unsafe {
            ioctl_with_mut_ref(
                self,
                MSHV_GET_GPA_ACCESS_STATES(),
                &mut gpa_pages_access_state,
            )
        };
        if ret == 0 {
            Ok(gpa_pages_access_state)
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
    #[ignore]
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

        vm.unmap_user_memory(mem).unwrap();
    }
    #[test]
    #[ignore]
    fn test_create_vcpu() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0);
        assert!(vcpu.is_ok());
    }
    #[test]
    #[ignore]
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
    #[ignore]
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
    #[ignore]
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
    #[ignore]
    fn test_irqfd() {
        use libc::EFD_NONBLOCK;
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let efd = EventFd::new(EFD_NONBLOCK).unwrap();
        vm.register_irqfd(&efd, 30).unwrap();
        vm.unregister_irqfd(&efd, 30).unwrap();
    }
    #[test]
    #[ignore]
    fn test_ioeventfd() {
        let efd = EventFd::new(0).unwrap();
        let addr = IoEventAddress::Mmio(0xe7e85004);
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        vm.register_ioevent(&efd, &addr, NoDatamatch).unwrap();
        vm.unregister_ioevent(&efd, &addr, NoDatamatch).unwrap();
    }
    #[test]
    #[ignore]
    fn test_set_msi_routing() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let msi_routing = mshv_msi_routing::default();
        assert!(vm.set_msi_routing(&msi_routing).is_ok());
    }
}
