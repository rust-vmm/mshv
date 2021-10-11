// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2021 Microsoft

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::ioctls::Result;
use crate::mshv_ioctls::{MSHV_GET_DEVICE_ATTR, MSHV_HAS_DEVICE_ATTR, MSHV_SET_DEVICE_ATTR};
use mshv_bindings::mshv_device_attr;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

/// Wrapper over the file descriptor obtained when creating an emulated device in the kernel.
pub struct DeviceFd {
    fd: File,
}

impl DeviceFd {
    /// Tests whether a device supports a particular attribute.
    ///
    /// See the documentation for `MSHV_HAS_DEVICE_ATTR`.
    /// # Arguments
    ///
    /// * `device_attr` - The device attribute to be tested. `addr` field is ignored.
    pub fn has_device_attr(&self, device_attr: &mshv_device_attr) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, MSHV_HAS_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets a specified piece of device configuration and/or state.
    ///
    /// See the documentation for `MSHV_SET_DEVICE_ATTR`.
    /// # Arguments
    ///
    /// * `device_attr` - The device attribute to be set.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # extern crate mshv_ioctls;
    /// # extern crate mshv_bindings;
    /// # use mshv_ioctls::Mshv;
    /// # use mshv_bindings::{
    ///    mshv_device_type_MSHV_DEV_TYPE_VFIO,
    ///    MSHV_DEV_VFIO_GROUP, MSHV_DEV_VFIO_GROUP_ADD, MSHV_CREATE_DEVICE_TEST
    /// };
    /// let mshv = Mshv::new().unwrap();
    /// let vm = mshv.create_vm().unwrap();
    ///
    /// let mut device = mshv_bindings::mshv_create_device {
    ///     type_: mshv_device_type_MSHV_DEV_TYPE_VFIO,
    ///     fd: 0,
    ///     flags: MSHV_CREATE_DEVICE_TEST,
    /// };
    ///
    /// let device_fd = vm
    ///     .create_device(&mut device)
    ///     .expect("Cannot create MSHV device");
    ///
    /// let dist_attr = mshv_bindings::mshv_device_attr {
    ///     group: MSHV_DEV_VFIO_GROUP,
    ///     attr: u64::from(MSHV_DEV_VFIO_GROUP_ADD),
    ///     addr: 0,
    ///     flags: 0,
    /// };
    ///
    /// if (device_fd.has_device_attr(&dist_attr).is_ok()) {
    ///     device_fd.set_device_attr(&dist_attr).unwrap();
    /// }
    /// ```
    pub fn set_device_attr(&self, device_attr: &mshv_device_attr) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, MSHV_SET_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Gets a specified piece of device configuration and/or state.
    ///
    /// See the documentation for `MSHV_GET_DEVICE_ATTR`.
    ///
    /// # Arguments
    ///
    /// * `device_attr` - The device attribute to be get.
    ///                   Note: This argument serves as both input and output.
    ///                   When calling this function, the user should explicitly provide
    ///                   valid values for the `group` and the `attr` field of the
    ///                   `mshv_device_attr` structure, and a valid userspace address
    ///                   (i.e. the `addr` field) to access the returned device attribute
    ///                   data.
    ///
    /// # Returns
    ///
    /// * Returns the last occured `errno` wrapped in an `Err`.
    /// * `device_attr` - The `addr` field of the `device_attr` structure will point to
    ///                   the device attribute data.
    pub fn get_device_attr(&self, device_attr: &mut mshv_device_attr) -> Result<()> {
        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_GET_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
}

/// Helper function for creating a new device.
pub fn new_device(dev_fd: File) -> DeviceFd {
    DeviceFd { fd: dev_fd }
}

impl AsRawFd for DeviceFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for DeviceFd {
    /// This function is also unsafe as the primitives currently returned have the contract that
    /// they are the sole owner of the file descriptor they are wrapping. Usage of this function
    /// could accidentally allow violating this contract which can cause memory unsafety in code
    /// that relies on it being true.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        DeviceFd {
            fd: File::from_raw_fd(fd),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioctls::system::Mshv;
    #[cfg(target_arch = "x86_64")]
    use mshv_bindings::{
        mshv_device_type_MSHV_DEV_TYPE_VFIO, MSHV_DEV_VFIO_GROUP, MSHV_DEV_VFIO_GROUP_ADD,
    };

    #[test]
    #[ignore]
    #[cfg(target_arch = "x86_64")]
    fn test_create_device() {
        let mshv = Mshv::new().unwrap();
        let vm = mshv.create_vm().unwrap();

        let mut device = mshv_bindings::mshv_create_device {
            type_: mshv_device_type_MSHV_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };
        let device = vm
            .create_device(&mut device)
            .expect("Cannot create MSHV device");

        // Following lines to re-construct device_fd are used to test
        // DeviceFd::from_raw_fd() and DeviceFd::as_raw_fd().
        let raw_fd = unsafe { libc::dup(device.as_raw_fd()) };
        assert!(raw_fd >= 0);
        let device = unsafe { DeviceFd::from_raw_fd(raw_fd) };

        let dist_attr = mshv_bindings::mshv_device_attr {
            group: MSHV_DEV_VFIO_GROUP,
            attr: u64::from(MSHV_DEV_VFIO_GROUP_ADD),
            addr: 0,
            flags: 0,
        };

        let mut dist_attr_mut = dist_attr;

        // We are just creating a test device. Creating a real device would make the CI dependent
        // on host configuration (like having /dev/vfio). We expect this to fail.
        assert!(device.has_device_attr(&dist_attr).is_ok());
        assert!(device.get_device_attr(&mut dist_attr_mut).is_err());
        assert!(device.set_device_attr(&dist_attr).is_err());
        assert_eq!(errno::Error::last().errno(), 14);
    }
}
