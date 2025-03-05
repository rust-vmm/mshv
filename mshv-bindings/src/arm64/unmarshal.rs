// Copyright © 2025, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::bindings::*;
use vmm_sys_util::errno;

type Result<T> = std::result::Result<T, errno::Error>;
// hv_message implementation for unmarshaling payload
impl hv_message {
    #[inline]
    pub fn to_memory_info(&self) -> Result<hv_arm64_memory_intercept_message> {
        if self.header.message_type != hv_message_type_HVMSG_GPA_INTERCEPT
            && self.header.message_type != hv_message_type_HVMSG_UNMAPPED_GPA
            && self.header.message_type != hv_message_type_HVMSG_UNACCEPTED_GPA
        {
            return Err(errno::Error::new(libc::EINVAL));
        }

        let ret =
            unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(self.u.payload) as *const _) };
        Ok(ret)
    }
}
