// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::ioctls::device::{new_device, DeviceFd};
use crate::ioctls::vcpu::{new_vcpu, VcpuFd};
use crate::ioctls::{MshvError, Result};
use crate::mshv_ioctls::*;
use crate::set_bits;
use mshv_bindings::*;

use std::cmp;
use std::convert::TryFrom;
use std::fs::File;

use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::{ioctl, ioctl_with_mut_ref, ioctl_with_ref};

/// Batch size for processing page access states
const PAGE_ACCESS_STATES_BATCH_SIZE: u32 = 0x10000;

/// An address either in programmable I/O space or in memory mapped I/O space.
///
/// The `IoEventAddress` is used for specifying the type when registering an event
/// in [register_ioevent](struct.VmFd.html#method.register_ioevent).
#[derive(Eq, PartialEq, Hash, Clone, Debug, Copy)]
pub enum IoEventAddress {
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
    Mmio(u64),
}

/// VMType represents the type of VM.
#[derive(Eq, PartialEq, Hash, Clone, Debug, Copy)]
pub enum VmType {
    /// Normal VM with no support for confidential computing
    Normal,
    /// AMD's SEV-SNP
    Snp,
}

impl TryFrom<u64> for VmType {
    type Error = ();

    fn try_from(v: u64) -> std::result::Result<Self, Self::Error> {
        match v {
            x if x == VmType::Normal as u64 => Ok(VmType::Normal),
            x if x == VmType::Snp as u64 => Ok(VmType::Snp),
            _ => Err(()),
        }
    }
}

/// Helper structure for disabling datamatch.
///
/// The structure can be used as a parameter to
/// [`register_ioevent`](struct.VmFd.html#method.register_ioevent)
/// to disable filtering of events based on the datamatch flag.
#[derive(Debug)]
pub struct NoDatamatch;

impl From<NoDatamatch> for u64 {
    fn from(_s: NoDatamatch) -> u64 {
        0
    }
}

/// Structure for injecting interurpt
///
/// This struct is passed to request_virtual_interrupt function as an argument
#[derive(Debug)]
pub struct InterruptRequest {
    /// Type of interrupt
    pub interrupt_type: hv_interrupt_type,
    /// Advanced Programmable Interrupt Controller Identification Number
    pub apic_id: u64,
    /// APIC Vector (entry of Interrupt Vector Table i.e IVT)
    pub vector: u32,
    /// True means level triggered, false means edge triggered
    pub level_triggered: bool,
    /// True means the APIC ID is logical, false means physical
    pub logical_destination_mode: bool,
    /// True means CPU is in long mode
    pub long_mode: bool,
}

/// Wrapper over Mshv VM ioctls.
#[derive(Debug)]
pub struct VmFd {
    vm: File,
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

impl VmFd {
    /// Initialize the partition after creation
    pub fn initialize(&self) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl(self, MSHV_INITIALIZE_PARTITION()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }
    /// Install intercept to enable some VM exits like MSR, CPUId etc
    pub fn install_intercept(&self, install_intercept_args: mshv_install_intercept) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret =
            unsafe { ioctl_with_ref(self, MSHV_INSTALL_INTERCEPT(), &install_intercept_args) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Modify host visibility for a range of GPA
    pub fn modify_gpa_host_access(
        &self,
        gpa_host_access_args: &mshv_modify_gpa_host_access,
    ) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret =
            unsafe { ioctl_with_ref(self, MSHV_MODIFY_GPA_HOST_ACCESS(), gpa_host_access_args) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Import the isolated pages
    pub fn import_isolated_pages(
        &self,
        isolate_page_list: &mshv_import_isolated_pages,
    ) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_IMPORT_ISOLATED_PAGES(), isolate_page_list) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Mark completion of importing the isoalted pages
    pub fn complete_isolated_import(&self, data: &mshv_complete_isolated_import) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_COMPLETE_ISOLATED_IMPORT(), data) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Issue PSP request from guest side
    pub fn psp_issue_guest_request(&self, data: &mshv_issue_psp_guest_request) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_ISSUE_PSP_GUEST_REQUEST(), data) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Create AP threads for SEV-SNP guest
    pub fn sev_snp_ap_create(&self, data: &mshv_sev_snp_ap_create) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_SEV_SNP_AP_CREATE(), data) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Creates/modifies a guest physical memory.
    pub fn map_user_memory(&self, user_memory_region: mshv_user_mem_region) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_MAP_GUEST_MEMORY(), &user_memory_region) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Unmap a guest physical memory.
    pub fn unmap_user_memory(&self, user_memory_region: mshv_user_mem_region) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_UNMAP_GUEST_MEMORY(), &user_memory_region) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Creates a new MSHV vCPU file descriptor
    pub fn create_vcpu(&self, id: u8) -> Result<VcpuFd> {
        let vp_arg = mshv_create_vp {
            vp_index: id as __u32,
        };
        // SAFETY: IOCTL with correct types
        let vcpu_fd = unsafe { ioctl_with_ref(&self.vm, MSHV_CREATE_VP(), &vp_arg) };
        if vcpu_fd < 0 {
            return Err(errno::Error::last().into());
        }

        // Wrap the vCPU now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        // SAFETY: we're sure vcpu_fd is valid.
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        Ok(new_vcpu(id as u32, vcpu))
    }

    /// Inject an interrupt into the guest..
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
            ..Default::default()
        };
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(&self.vm, MSHV_ASSERT_INTERRUPT(), &interrupt_arg) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    ///
    /// signal_event_direct: Send a sint signal event to the vp.
    pub fn signal_event_direct(&self, vp: u32, sint: u8, flag: u16) -> Result<bool> {
        let mut event_info = mshv_signal_event_direct {
            vp,
            vtl: 0,
            sint,
            flag,
            ..Default::default()
        };

        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_SIGNAL_EVENT_DIRECT(), &mut event_info) };
        if ret == 0 {
            Ok(event_info.newly_signaled != 0)
        } else {
            Err(errno::Error::last().into())
        }
    }

    ///
    /// post_message_direct: Post a message to the vp using a given sint.
    pub fn post_message_direct(&self, vp: u32, sint: u8, msg: &[u8]) -> Result<()> {
        let message_info = mshv_post_message_direct {
            vp,
            vtl: 0,
            sint,
            length: u16::try_from(msg.len()).expect("failed to convert message length"),
            message: msg.as_ptr(),
        };

        let ret = unsafe { ioctl_with_ref(self, MSHV_POST_MESSAGE_DIRECT(), &message_info) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    ///
    /// register_deliverabilty_notifications: Register for a notification when
    /// hypervisor is ready to process more post_message_direct(s).
    pub fn register_deliverabilty_notifications(&self, vp: u32, flag: u64) -> Result<()> {
        let notifications_info = mshv_register_deliverabilty_notifications {
            vp,
            flag,
            ..Default::default()
        };
        let ret = unsafe {
            ioctl_with_ref(
                self,
                MSHV_REGISTER_DELIVERABILITY_NOTIFICATIONS(),
                &notifications_info,
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// irqfd: Passes in an eventfd which is to be used for injecting
    /// interrupts from userland.
    fn irqfd(&self, fd: RawFd, resamplefd: RawFd, gsi: u32, flags: u32) -> Result<()> {
        let irqfd_arg = mshv_user_irqfd {
            fd,
            flags,
            resamplefd,
            gsi,
        };

        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(&self.vm, MSHV_IRQFD(), &irqfd_arg) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
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
    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.irqfd(fd.as_raw_fd(), 0, gsi, 0)
    }

    /// Registers an event that will, when signaled, assert the `gsi` IRQ.
    /// If the irqchip is resampled by the guest, the IRQ is de-asserted,
    /// and `resamplefd` is notified.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` to be signaled.
    /// * `resamplefd` - `Eventfd` to be notified on resample.
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
    /// let resamplefd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm.register_irqfd_with_resample(&evtfd, &resamplefd, 30)
    ///     .unwrap();
    /// ```
    pub fn register_irqfd_with_resample(
        &self,
        fd: &EventFd,
        resamplefd: &EventFd,
        gsi: u32,
    ) -> Result<()> {
        self.irqfd(
            fd.as_raw_fd(),
            resamplefd.as_raw_fd(),
            gsi,
            set_bits!(u32, MSHV_IRQFD_BIT_RESAMPLE),
        )
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
    pub fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.irqfd(
            fd.as_raw_fd(),
            0,
            gsi,
            set_bits!(u32, MSHV_IRQFD_BIT_DEASSIGN),
        )
    }

    /// Sets the MSI routing table entries, overwriting any previously set
    /// entries, as per the `MSHV_SET_MSI_ROUTING` ioctl.
    ///
    /// Returns an io::Error when the table could not be updated.
    ///
    /// # Arguments
    ///
    /// * msi_routing - MSI routing configuration.
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
    /// let msi_routing = mshv_user_irq_table::default();
    /// vm.set_msi_routing(&msi_routing).unwrap();
    /// ```
    pub fn set_msi_routing(&self, msi_routing: &mshv_user_irq_table) -> Result<()> {
        // SAFETY: we allocated the structure and we know the kernel
        // will read exactly the size of the structure.
        let ret = unsafe { ioctl_with_ref(self, MSHV_SET_MSI_ROUTING(), msi_routing) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// ioeventfd: Passes in an eventfd which the kernel would signal when
    /// an mmio region is written into.
    fn ioeventfd<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
        mut flags: u32,
    ) -> Result<()> {
        //
        // mshv doesn't support PIO ioeventfds now.
        //
        let mmio_addr = match addr {
            IoEventAddress::Pio(_) => {
                return Err(libc::ENOTSUP.into());
            }
            IoEventAddress::Mmio(ref m) => *m,
        };

        if std::mem::size_of::<T>() > 0 {
            flags |= set_bits!(u32, MSHV_IOEVENTFD_BIT_DATAMATCH);
        }

        let ioeventfd = mshv_user_ioeventfd {
            datamatch: datamatch.into(),
            len: std::mem::size_of::<T>() as u32,
            addr: mmio_addr,
            fd: fd.as_raw_fd(),
            flags,
            ..Default::default()
        };
        // SAFETY: we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, MSHV_IOEVENTFD(), &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
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
    ///     .unwrap();
    /// ```
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
    ///     .unwrap();
    /// vm.unregister_ioevent(&evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
    ///     .unwrap();
    /// ```
    pub fn unregister_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        self.ioeventfd(
            fd,
            addr,
            datamatch,
            set_bits!(u32, MSHV_IOEVENTFD_BIT_DEASSIGN),
        )
    }

    /// Get property of the VM partition: For example , CPU Frequency, Size of the Xsave state and more.
    /// For more of the codes, please see the hv_partition_property_code type definitions in the bindings.rs
    pub fn get_partition_property(&self, code: u32) -> Result<u64> {
        let mut property = mshv_partition_property {
            property_code: code,
            ..Default::default()
        };
        // SAFETY: IOCTL with correct types
        let ret =
            unsafe { ioctl_with_mut_ref(&self.vm, MSHV_GET_PARTITION_PROPERTY(), &mut property) };
        if ret == 0 {
            Ok(property.property_value)
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Sets a partion property
    pub fn set_partition_property(&self, code: u32, value: u64) -> Result<()> {
        let property: mshv_partition_property = mshv_partition_property {
            property_code: code,
            property_value: value,
        };
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(&self.vm, MSHV_SET_PARTITION_PROPERTY(), &property) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Generic hvcall version of set_partition_property
    pub fn hvcall_set_partition_property(&self, code: u32, value: u64) -> Result<()> {
        let input = hv_input_set_partition_property {
            property_code: code,
            property_value: value,
            ..Default::default() // NOTE: kernel will populate partition_id field
        };
        let mut args = make_args!(HVCALL_SET_PARTITION_PROPERTY, input);
        self.hvcall(&mut args)
    }

    /// Enable dirty page tracking by hypervisor
    /// Flags:
    ///         bit 1: Enabled
    ///         bit 2: Granularity
    pub fn enable_dirty_page_tracking(&self) -> Result<()> {
        let flag: u64 = 0x1;
        self.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_GPA_PAGE_ACCESS_TRACKING,
            flag,
        )
    }

    /// Disable dirty page tracking by hypervisor
    /// Prerequisite: It is required to set the dirty bits if cleared
    /// previously, otherwise this hypercall will be failed.
    /// Flags:
    ///         bit 1: Enabled
    ///         bit 2: Granularity
    pub fn disable_dirty_page_tracking(&self) -> Result<()> {
        let flag: u64 = 0x0;
        self.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_GPA_PAGE_ACCESS_TRACKING,
            flag,
        )
    }

    /// Get page access state
    /// The data provides each page's access state whether it is dirty or accessed
    /// Prerequisite: Need to enable page_acess_tracking
    /// Flags:
    ///         bit 1: ClearAccessed
    ///         bit 2: SetAccessed
    ///         bit 3: ClearDirty
    ///         bit 4: SetDirty
    ///         Number of bits reserved: 60
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
                count: nr_pfns,
                hv_gpa_page_number: base_pfn,
                flags,
                states: states.as_mut_ptr(),
            };

        // SAFETY: IOCTL with correct types
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
            Err(errno::Error::last().into())
        }
    }

    /// Gets the bitmap of pages dirtied since the last call of this function
    ///
    /// Flags:
    ///         bit 1: ClearAccessed
    ///         bit 2: SetAccessed
    ///         bit 3: ClearDirty
    ///         bit 4: SetDirty
    ///         Number of bits reserved: 60
    pub fn get_dirty_log(&self, base_pfn: u64, memory_size: usize, flags: u64) -> Result<Vec<u64>> {
        // Compute the length of the bitmap needed for all dirty pages in one memory slot.
        // One memory page is `page_size` bytes and `KVM_GET_DIRTY_LOG` returns one dirty bit for
        // each page.
        // SAFETY: FFI call to libc
        let page_size = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
            -1 => return Err(errno::Error::last().into()),
            ps => ps as usize,
        };

        // For ease of access we are saving the bitmap in a u64 vector. We are using ceil to
        // make sure we count all dirty pages even when `memory_size` is not a multiple of
        // `page_size * 64`.
        let div_ceil = |dividend, divisor| (dividend + divisor - 1) / divisor;
        let bitmap_size = div_ceil(memory_size, page_size * 64);
        let mut bitmap = vec![0u64; bitmap_size];

        let mut processed: usize = 0;
        let mut mask;
        let mut state: u8;
        let mut current_size;
        let mut remaining = (memory_size / page_size) as u32;
        let mut bit_index = 0;
        let mut bitmap_index = 0;

        while remaining != 0 {
            current_size = cmp::min(PAGE_ACCESS_STATES_BATCH_SIZE, remaining);
            let page_states =
                self.get_gpa_access_state(base_pfn + processed as u64, current_size, flags)?;
            // SAFETY: we're sure states and count meet the requirements for from_raw_parts
            let slices: &[hv_gpa_page_access_state] = unsafe {
                std::slice::from_raw_parts(page_states.states, page_states.count as usize)
            };
            for item in slices.iter() {
                let bits = &mut bitmap[bitmap_index];
                mask = 1 << bit_index;
                // SAFETY: access union field
                state = unsafe { item.__bindgen_anon_1.dirty() };
                if state == 1 {
                    *bits |= mask;
                }
                processed += 1;
                bitmap_index = processed / 64;
                bit_index = processed % 64;
            }
            remaining -= page_states.count;
        }
        Ok(bitmap)
    }

    /// Create an in-kernel device
    ///
    /// See the documentation for `MSHV_CREATE_DEVICE`.
    pub fn create_device(&self, device: &mut mshv_create_device) -> Result<DeviceFd> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_CREATE_DEVICE(), device) };
        if ret == 0 {
            // SAFETY: fd is valid
            Ok(new_device(unsafe { File::from_raw_fd(device.fd as i32) }))
        } else {
            Err(errno::Error::last().into())
        }
    }

    /// Execute a hypercall for this partition
    pub fn hvcall(&self, args: &mut mshv_root_hvcall) -> Result<()> {
        // SAFETY: IOCTL with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_ROOT_HVCALL(), args) };
        if ret == 0 {
            Ok(())
        } else {
            Err(MshvError::from_hvcall(errno::Error::last(), *args))
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
    use libc::c_void;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::ioctls::system::Mshv;
    use crate::ioctls::MshvError;
    use std::mem;

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

        vm.unmap_user_memory(mem).unwrap();
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
        let state = vcpu.get_lapic().unwrap();
        let buffer = Buffer::try_from(&state).unwrap();
        let hv_state = unsafe { &*(buffer.buf as *const hv_local_interrupt_controller_state) };
        let cfg = InterruptRequest {
            interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_EXTINT,
            apic_id: hv_state.apic_id as u64,
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
        assert!(vm.install_intercept(intercept_args).is_ok());
    }

    #[test]
    fn test_get_property() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();

        let mut val = vm
            .get_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_MAX_XSAVE_DATA_SIZE,
            )
            .unwrap();
        println!("Max xsave data size: {val} bytes");
        val = vm
            .get_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_PROCESSOR_XSAVE_FEATURES,
            )
            .unwrap();
        println!("Xsave feature: {val}");
        val = vm
            .get_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_PROCESSOR_CLOCK_FREQUENCY,
            )
            .unwrap();
        println!("Processor frequency: {val}");
        vm.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION,
            hv_unimplemented_msr_action_HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO as u64,
        )
        .unwrap();
        val = vm
            .get_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION,
            )
            .unwrap();
        assert!(
            val == hv_unimplemented_msr_action_HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO
                .into()
        );
    }

    #[test]
    fn test_set_property() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();

        let code = hv_partition_property_code_HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION;
        let ignore =
            hv_unimplemented_msr_action_HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO as u64;
        let fault = hv_unimplemented_msr_action_HV_UNIMPLEMENTED_MSR_ACTION_FAULT as u64;

        vm.set_partition_property(code, ignore).unwrap();
        let ignore_ret = vm.get_partition_property(code).unwrap();
        assert!(ignore_ret == ignore);

        vm.set_partition_property(code, fault).unwrap();
        let fault_ret = vm.get_partition_property(code).unwrap();
        assert!(fault_ret == fault);

        // Test the same with hvcall_ equivalent
        vm.hvcall_set_partition_property(code, ignore).unwrap();
        let ignore_ret = vm.get_partition_property(code).unwrap();
        assert!(ignore_ret == ignore);

        vm.hvcall_set_partition_property(code, fault).unwrap();
        let fault_ret = vm.get_partition_property(code).unwrap();
        assert!(fault_ret == fault);
    }

    #[test]
    fn test_set_partition_property_invalid() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let code = hv_partition_property_code_HV_PARTITION_PROPERTY_PRIVILEGE_FLAGS;

        // old IOCTL
        let res_0 = vm.set_partition_property(code, 0);
        assert!(res_0.is_err());

        // generic hvcall
        let res_1 = vm.hvcall_set_partition_property(code, 0);
        let mshv_err_check = MshvError::Hypercall {
            code: HVCALL_SET_PARTITION_PROPERTY as u16,
            status_raw: HV_STATUS_INVALID_PARTITION_STATE as u16,
            status: Some(HvError::InvalidPartitionState),
        };
        assert!(res_1.err().unwrap() == mshv_err_check);
    }

    #[test]
    fn test_irqfd() {
        use libc::EFD_NONBLOCK;
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let efd = EventFd::new(EFD_NONBLOCK).unwrap();
        vm.register_irqfd(&efd, 30).unwrap();
        vm.unregister_irqfd(&efd, 30).unwrap();
    }

    #[test]
    fn test_ioeventfd() {
        let efd = EventFd::new(0).unwrap();
        let addr = IoEventAddress::Mmio(0xe7e85004);
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        vm.register_ioevent(&efd, &addr, NoDatamatch).unwrap();
        vm.unregister_ioevent(&efd, &addr, NoDatamatch).unwrap();
    }

    #[test]
    fn test_set_msi_routing() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let msi_routing = mshv_user_irq_table::default();
        assert!(vm.set_msi_routing(&msi_routing).is_ok());
    }

    #[test]
    fn test_get_gpa_access_states() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        // Try to allocate 32 MB memory
        let mem_size = 32 * 1024 * 1024;
        let load_addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        } as *mut u8;
        let mem_region = mshv_user_mem_region {
            flags: HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | HV_MAP_GPA_EXECUTABLE,
            guest_pfn: 0x0_u64,
            size: mem_size as u64,
            userspace_addr: load_addr as u64,
        };
        // TODO need more real time testing: validating data,
        // number of bits returned etc.
        vm.map_user_memory(mem_region).unwrap();
        vm.enable_dirty_page_tracking().unwrap();
        let bitmaps_1: Vec<u64> = vm.get_dirty_log(0, mem_size, 0x4).unwrap();
        let bitmaps_2: Vec<u64> = vm.get_dirty_log(0, mem_size, 0x8).unwrap();
        vm.disable_dirty_page_tracking().unwrap();
        assert!(bitmaps_1.len() == bitmaps_2.len());
        vm.unmap_user_memory(mem_region).unwrap();
        unsafe { libc::munmap(load_addr as *mut c_void, mem_size) };
    }

    #[test]
    #[ignore]
    fn test_signal_event_direct() {
        // TODO this is used by MSHV synic.
        // Enable the test once synic is implemented.
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        vm.signal_event_direct(0, 0, 1).unwrap();
    }

    #[test]
    #[ignore]
    fn test_post_message_direct() {
        // TODO this is used by MSHV synic.
        // Enable the test once synic is implemented.
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        let hv_message: [u8; mem::size_of::<HvMessage>()] = [0; mem::size_of::<HvMessage>()];
        vm.post_message_direct(0, 0, &hv_message).unwrap();
    }

    #[test]
    fn test_register_deliverabilty_notifications() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        vm.register_deliverabilty_notifications(0, 0).unwrap();
        let res = vm.register_deliverabilty_notifications(0, 1);
        assert!(res.is_err());
        if let Err(e) = res {
            assert!(e == MshvError::from(libc::EINVAL))
        }
    }
}
