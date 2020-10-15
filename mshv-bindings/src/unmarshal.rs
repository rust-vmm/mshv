// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::bindings::*;

// hv_message implementation for unmarshaling payload
impl hv_message {
    #[inline]
    pub fn to_cpuid_info(&self) -> hv_x64_cpuid_intercept_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_X64_CPUID_INTERCEPT);
        let p: *const [u8; std::mem::size_of::<hv_x64_cpuid_intercept_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_cpuid_intercept_message>()]
        };
        let ret: hv_x64_cpuid_intercept_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_memory_info(&self) -> hv_x64_memory_intercept_message {
        assert!(
            self.header.message_type == hv_message_type_HVMSG_GPA_INTERCEPT
                || self.header.message_type == hv_message_type_HVMSG_UNMAPPED_GPA
        );
        let p: *const [u8; std::mem::size_of::<hv_x64_memory_intercept_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_memory_intercept_message>()]
        };
        let ret: hv_x64_memory_intercept_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_ioport_info(&self) -> hv_x64_io_port_intercept_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT);
        let p: *const [u8; std::mem::size_of::<hv_x64_io_port_intercept_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_io_port_intercept_message>()]
        };
        let ret: hv_x64_io_port_intercept_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_msr_info(&self) -> hv_x64_msr_intercept_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_X64_MSR_INTERCEPT);
        let p: *const [u8; std::mem::size_of::<hv_x64_msr_intercept_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_msr_intercept_message>()]
        };
        let ret: hv_x64_msr_intercept_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_exception_info(&self) -> hv_x64_exception_intercept_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT);
        let p: *const [u8; std::mem::size_of::<hv_x64_exception_intercept_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_exception_intercept_message>()]
        };
        let ret: hv_x64_exception_intercept_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_invalid_vp_register_info(&self) -> hv_x64_invalid_vp_register_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_INVALID_VP_REGISTER_VALUE);
        let p: *const [u8; std::mem::size_of::<hv_x64_invalid_vp_register_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_invalid_vp_register_message>()]
        };
        let ret: hv_x64_invalid_vp_register_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_unrecoverable_exception_info(&self) -> hv_x64_unrecoverable_exception_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_UNRECOVERABLE_EXCEPTION);
        let p: *const [u8; std::mem::size_of::<hv_x64_unrecoverable_exception_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_unrecoverable_exception_message>()]
        };
        let ret: hv_x64_unrecoverable_exception_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_interruption_deliverable_info(&self) -> hv_x64_interruption_deliverable_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_X64_INTERRUPTION_DELIVERABLE);
        let p: *const [u8; std::mem::size_of::<hv_x64_interruption_deliverable_message>()] = unsafe {
            self.u.payload.as_ptr()
                as *const [u8; std::mem::size_of::<hv_x64_interruption_deliverable_message>()]
        };
        let ret: hv_x64_interruption_deliverable_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
    #[inline]
    pub fn to_apic_eoi_info(&self) -> hv_x64_apic_eoi_message {
        assert!(self.header.message_type == hv_message_type_HVMSG_X64_APIC_EOI);
        let p: *const [u8; std::mem::size_of::<hv_x64_apic_eoi_message>()] = unsafe {
            self.u.payload.as_ptr() as *const [u8; std::mem::size_of::<hv_x64_apic_eoi_message>()]
        };
        let ret: hv_x64_apic_eoi_message = unsafe { std::ptr::read(p as *const _) };
        ret
    }
}
