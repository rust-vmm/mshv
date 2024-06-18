use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::AsRawFd;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl};

/// Set bits by index and OR them together
#[macro_export]
macro_rules! set_bits {
    ($int_type:ty, $bit:expr) => {{
        let bit: $int_type = ((1 as $int_type) << $bit);
        bit
    }};
    ($int_type:ty, $bit:expr, $($bits:expr),+) => {{
        set_bits!($int_type, $bit) | set_bits!($int_type, $($bits),+)
    }};
}

// SAFETY: The caller is responsible for the safety of the ioctl
pub unsafe fn ioctl_result<F: AsRawFd>(
        descriptor: &F,
        nr: c_ulong,
    ) -> Result<c_int, vmm_sys_util::errno::Error> {
    let ret = ioctl(descriptor, nr);

    if ret >= 0 {
        Ok(ret)
    } else {
        Err(errno::Error::last())
    }
}

// SAFETY: The caller is responsible for the safety of the ioctl
pub unsafe fn ioctl_with_ref_result<F: AsRawFd, T>(
        descriptor: &F,
        nr: c_ulong,
        arg: &T
    ) -> Result<c_int, vmm_sys_util::errno::Error> {
    let ret = ioctl_with_ref(descriptor, nr, arg);

    if ret >= 0 {
        Ok(ret)
    } else {
        Err(errno::Error::last())
    }
}

// SAFETY: The caller is responsible for the safety of the ioctl
pub unsafe fn ioctl_with_mut_ref_result<F: AsRawFd, T>(
        descriptor: &F,
        nr: c_ulong,
        arg: &mut T
    ) -> Result<c_int, vmm_sys_util::errno::Error> {
    let ret = ioctl_with_mut_ref(descriptor, nr, arg);

    if ret >= 0 {
        Ok(ret)
    } else {
        Err(errno::Error::last())
    }
}
