// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::bindings::*;
#[cfg(feature = "with-serde")]
use serde_derive::{Deserialize, Serialize};
use std::cmp;
use std::ptr;

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }
    #[inline]
    pub unsafe fn as_ptr(&self) -> *const T {
        ::std::mem::transmute(self)
    }
    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        ::std::mem::transmute(self)
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
impl<T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct StandardRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct SegmentRegister {
    /* segment register + descriptor */
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,   /* type, writeable etc: 4 */
    pub present: u8, /* if not present, exception generated: 1 */
    pub dpl: u8,     /* descriptor privilege level (ring): 2 */
    pub db: u8,      /* default/big (16 or 32 bit size offset): 1*/
    pub s: u8,       /* non-system segment */
    pub l: u8,       /* long (64 bit): 1 */
    pub g: u8,       /* granularity (bytes or 4096 byte pages): 1 */
    pub avl: u8,     /* available (free bit for software to use): 1 */
    pub unusable: __u8,
    pub padding: __u8,
}

impl From<hv_x64_segment_register> for SegmentRegister {
    fn from(reg: hv_x64_segment_register) -> Self {
        unsafe {
            SegmentRegister {
                base: reg.base,
                limit: reg.limit,
                selector: reg.selector,
                type_: (reg.__bindgen_anon_1.attributes & 0xF) as u8,
                present: ((reg.__bindgen_anon_1.attributes >> 7) & 0x1) as u8,
                dpl: ((reg.__bindgen_anon_1.attributes >> 5) & 0x3) as u8,
                db: ((reg.__bindgen_anon_1.attributes >> 14) & 0x1) as u8,
                s: ((reg.__bindgen_anon_1.attributes >> 4) & 0x1) as u8,
                l: ((reg.__bindgen_anon_1.attributes >> 13) & 0x1) as u8,
                g: ((reg.__bindgen_anon_1.attributes >> 15) & 0x1) as u8,
                avl: ((reg.__bindgen_anon_1.attributes >> 12) & 0x1) as u8,
                unusable: 0 as __u8,
                padding: 0 as __u8,
            }
        }
    }
}
impl From<SegmentRegister> for hv_x64_segment_register {
    fn from(reg: SegmentRegister) -> Self {
        hv_x64_segment_register {
            base: reg.base,
            limit: reg.limit,
            selector: reg.selector,
            __bindgen_anon_1: hv_x64_segment_register__bindgen_ty_1 {
                attributes: ((reg.type_ & 0xF) as u16)
                    | (((reg.present & 0x1) as u16) << 7)
                    | (((reg.dpl & 0x3) as u16) << 5)
                    | (((reg.db & 0x1) as u16) << 14)
                    | (((reg.s & 0x1) as u16) << 4)
                    | (((reg.l & 0x1) as u16) << 13)
                    | (((reg.g & 0x1) as u16) << 15)
                    | (((reg.avl & 0x1) as u16) << 12),
            },
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct TableRegister {
    pub base: u64,
    pub limit: u16,
}

impl From<hv_x64_table_register> for TableRegister {
    fn from(reg: hv_x64_table_register) -> Self {
        TableRegister {
            base: reg.base,
            limit: reg.limit,
        }
    }
}

impl From<TableRegister> for hv_x64_table_register {
    fn from(reg: TableRegister) -> Self {
        hv_x64_table_register {
            limit: reg.limit,
            base: reg.base,
            pad: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct SpecialRegisters {
    pub cs: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ss: SegmentRegister,
    pub tr: SegmentRegister,
    pub ldt: TableRegister,
    pub gdt: TableRegister,
    pub idt: TableRegister,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct DebugRegisters {
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct FloatingPointUnit {
    pub fpr: [[u8; 16usize]; 8usize],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16usize]; 16usize],
    pub mxcsr: u32,
    pub pad2: u32,
}

pub const IA32_MSR_TSC: u32 = 0x00000010;
pub const IA32_MSR_EFER: u32 = 0xC0000080;
pub const IA32_MSR_KERNEL_GS_BASE: u32 = 0xC0000102;
pub const IA32_MSR_APIC_BASE: u32 = 0x0000001B;
pub const IA32_MSR_PAT: u32 = 0x0277;
pub const IA32_MSR_SYSENTER_CS: u32 = 0x00000174;
pub const IA32_MSR_SYSENTER_ESP: u32 = 0x00000175;
pub const IA32_MSR_SYSENTER_EIP: u32 = 0x00000176;
pub const IA32_MSR_STAR: u32 = 0xC0000081;
pub const IA32_MSR_LSTAR: u32 = 0xC0000082;
pub const IA32_MSR_CSTAR: u32 = 0xC0000083;
pub const IA32_MSR_SFMASK: u32 = 0xC0000084;

pub const IA32_MSR_MTRR_CAP: u32 = 0x00FE;
pub const IA32_MSR_MTRR_DEF_TYPE: u32 = 0x02FF;
pub const IA32_MSR_MTRR_PHYSBASE0: u32 = 0x0200;
pub const IA32_MSR_MTRR_PHYSMASK0: u32 = 0x0201;
pub const IA32_MSR_MTRR_PHYSBASE1: u32 = 0x0202;
pub const IA32_MSR_MTRR_PHYSMASK1: u32 = 0x0203;
pub const IA32_MSR_MTRR_PHYSBASE2: u32 = 0x0204;
pub const IA32_MSR_MTRR_PHYSMASK2: u32 = 0x0205;
pub const IA32_MSR_MTRR_PHYSBASE3: u32 = 0x0206;
pub const IA32_MSR_MTRR_PHYSMASK3: u32 = 0x0207;
pub const IA32_MSR_MTRR_PHYSBASE4: u32 = 0x0208;
pub const IA32_MSR_MTRR_PHYSMASK4: u32 = 0x0209;
pub const IA32_MSR_MTRR_PHYSBASE5: u32 = 0x020A;
pub const IA32_MSR_MTRR_PHYSMASK5: u32 = 0x020B;
pub const IA32_MSR_MTRR_PHYSBASE6: u32 = 0x020C;
pub const IA32_MSR_MTRR_PHYSMASK6: u32 = 0x020D;
pub const IA32_MSR_MTRR_PHYSBASE7: u32 = 0x020E;
pub const IA32_MSR_MTRR_PHYSMASK7: u32 = 0x020F;

pub const IA32_MSR_MTRR_FIX64K_00000: u32 = 0x0250;
pub const IA32_MSR_MTRR_FIX16K_80000: u32 = 0x0258;
pub const IA32_MSR_MTRR_FIX16K_a0000: u32 = 0x0259;
pub const IA32_MSR_MTRR_FIX4K_c0000: u32 = 0x0268;
pub const IA32_MSR_MTRR_FIX4K_c8000: u32 = 0x0269;
pub const IA32_MSR_MTRR_FIX4K_d0000: u32 = 0x026A;
pub const IA32_MSR_MTRR_FIX4K_d8000: u32 = 0x026B;
pub const IA32_MSR_MTRR_FIX4K_e0000: u32 = 0x026C;
pub const IA32_MSR_MTRR_FIX4K_e8000: u32 = 0x026D;
pub const IA32_MSR_MTRR_FIX4K_f0000: u32 = 0x026E;
pub const IA32_MSR_MTRR_FIX4K_f8000: u32 = 0x026F;

pub const IA32_MSR_TSC_AUX: u32 = 0xC0000103;
pub const IA32_MSR_BNDCFGS: u32 = 0x00000d90;
pub const IA32_MSR_DEBUG_CTL: u32 = 0x1D9;

pub const IA32_MSR_MISC_ENABLE: u32 = 0x000001a0;

pub fn msr_to_hv_reg_name(msr: u32) -> Result<hv_register_name, &'static str> {
    match msr {
        IA32_MSR_TSC => Ok(hv_register_name::HV_X64_REGISTER_TSC),

        IA32_MSR_EFER => Ok(hv_register_name::HV_X64_REGISTER_EFER),
        IA32_MSR_KERNEL_GS_BASE => Ok(hv_register_name::HV_X64_REGISTER_KERNEL_GS_BASE),
        IA32_MSR_APIC_BASE => Ok(hv_register_name::HV_X64_REGISTER_APIC_BASE),
        IA32_MSR_PAT => Ok(hv_register_name::HV_X64_REGISTER_PAT),
        IA32_MSR_SYSENTER_CS => Ok(hv_register_name::HV_X64_REGISTER_SYSENTER_CS),
        IA32_MSR_SYSENTER_ESP => Ok(hv_register_name::HV_X64_REGISTER_SYSENTER_ESP),
        IA32_MSR_SYSENTER_EIP => Ok(hv_register_name::HV_X64_REGISTER_SYSENTER_EIP),
        IA32_MSR_STAR => Ok(hv_register_name::HV_X64_REGISTER_STAR),
        IA32_MSR_LSTAR => Ok(hv_register_name::HV_X64_REGISTER_LSTAR),
        IA32_MSR_CSTAR => Ok(hv_register_name::HV_X64_REGISTER_CSTAR),
        IA32_MSR_SFMASK => Ok(hv_register_name::HV_X64_REGISTER_SFMASK),

        IA32_MSR_MTRR_CAP => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_CAP),
        IA32_MSR_MTRR_DEF_TYPE => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_DEF_TYPE),
        IA32_MSR_MTRR_PHYSBASE0 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0),
        IA32_MSR_MTRR_PHYSMASK0 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0),
        IA32_MSR_MTRR_PHYSBASE1 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE1),
        IA32_MSR_MTRR_PHYSMASK1 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK1),
        IA32_MSR_MTRR_PHYSBASE2 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE2),
        IA32_MSR_MTRR_PHYSMASK2 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK2),
        IA32_MSR_MTRR_PHYSBASE3 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE3),
        IA32_MSR_MTRR_PHYSMASK3 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK3),
        IA32_MSR_MTRR_PHYSBASE4 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE4),
        IA32_MSR_MTRR_PHYSMASK4 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK4),
        IA32_MSR_MTRR_PHYSBASE5 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE5),
        IA32_MSR_MTRR_PHYSMASK5 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK5),
        IA32_MSR_MTRR_PHYSBASE6 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE6),
        IA32_MSR_MTRR_PHYSMASK6 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK6),
        IA32_MSR_MTRR_PHYSBASE7 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_BASE7),
        IA32_MSR_MTRR_PHYSMASK7 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_PHYS_MASK7),

        IA32_MSR_MTRR_FIX64K_00000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX64K00000),
        IA32_MSR_MTRR_FIX16K_80000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX16K80000),
        IA32_MSR_MTRR_FIX16K_a0000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX16KA0000),
        IA32_MSR_MTRR_FIX4K_c0000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KC0000),
        IA32_MSR_MTRR_FIX4K_c8000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KC8000),
        IA32_MSR_MTRR_FIX4K_d0000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KD0000),
        IA32_MSR_MTRR_FIX4K_d8000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KD8000),
        IA32_MSR_MTRR_FIX4K_e0000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KE0000),
        IA32_MSR_MTRR_FIX4K_e8000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KE8000),
        IA32_MSR_MTRR_FIX4K_f0000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KF0000),
        IA32_MSR_MTRR_FIX4K_f8000 => Ok(hv_register_name::HV_X64_REGISTER_MSR_MTRR_FIX4KF8000),

        IA32_MSR_TSC_AUX => Ok(hv_register_name::HV_X64_REGISTER_TSC_AUX),
        IA32_MSR_BNDCFGS => Ok(hv_register_name::HV_X64_REGISTER_BNDCFGS),
        IA32_MSR_DEBUG_CTL => Ok(hv_register_name::HV_X64_REGISTER_DEBUG_CTL),

        IA32_MSR_MISC_ENABLE => Ok(hv_register_name::HV_X64_REGISTER_MSR_IA32_MISC_ENABLE),
        _ => Err("Not a supported hv_register_name msr"),
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct msr_entry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct msrs {
    pub nmsrs: u32,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub pad: u32,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub entries: __IncompleteArrayField<msr_entry>,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct msr_list {
    pub nmsrs: u32,
    pub indices: __IncompleteArrayField<u32>,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct VcpuEvents {
    pub pending_interruption: u64,
    pub interrupt_state: u64,
    pub internal_activity_state: u64,
    pub pending_event0: [u8; 16usize],
    pub pending_event1: [u8; 16usize],
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct Xcrs {
    pub xcr0: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct hv_cpuid_entry {
    pub function: __u32,
    pub index: __u32,
    pub flags: __u32,
    pub eax: __u32,
    pub ebx: __u32,
    pub ecx: __u32,
    pub edx: __u32,
    pub padding: [__u32; 3usize],
}
#[repr(C)]
#[derive(Debug, Default)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct hv_cpuid {
    pub nent: __u32,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub padding: __u32,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub entries: __IncompleteArrayField<hv_cpuid_entry>,
}

pub const LOCAL_APIC_OFFSET_APIC_ID: isize = 0x20; // APIC ID Register.
pub const LOCAL_APIC_OFFSET_VERSION: isize = 0x30; // APIC Version Register.
pub const LOCAL_APIC_OFFSET_TPR: isize = 0x80; // Task Priority Register
pub const LOCAL_APIC_OFFSET_APR: isize = 0x90; // Arbitration Priority Register.
pub const LOCAL_APIC_OFFSET_PPR: isize = 0xA0; // Processor Priority Register.
pub const LOCAL_APIC_OFFSET_EOI: isize = 0xB0; // End Of Interrupt Register.
pub const LOCAL_APIC_OFFSET_REMOTE_READ: isize = 0xC0; // Remote Read Register
pub const LOCAL_APIC_OFFSET_LDR: isize = 0xD0; // Logical Destination Register.
pub const LOCAL_APIC_OFFSET_DFR: isize = 0xE0; // Destination Format Register.
pub const LOCAL_APIC_OFFSET_SPURIOUS: isize = 0xF0; // Spurious Interrupt Vector.
pub const LOCAL_APIC_OFFSET_ISR: isize = 0x100; // In-Service Register.
pub const LOCAL_APIC_OFFSET_TMR: isize = 0x180; // Trigger Mode Register.
pub const LOCAL_APIC_OFFSET_IRR: isize = 0x200; // Interrupt Request Register.
pub const LOCAL_APIC_OFFSET_ERROR: isize = 0x280; // Error Status Register.
pub const LOCAL_APIC_OFFSET_ICR_LOW: isize = 0x300; // ICR Low.
pub const LOCAL_APIC_OFFSET_ICR_HIGH: isize = 0x310; // ICR High.
pub const LOCAL_APIC_OFFSET_TIMER_LVT: isize = 0x320; // LVT Timer Register.
pub const LOCAL_APIC_OFFSET_THERMAL_LVT: isize = 0x330; // LVT Thermal Register.
pub const LOCAL_APIC_OFFSET_PERFMON_LVT: isize = 0x340; // LVT Performance Monitor Register.
pub const LOCAL_APIC_OFFSET_LINT0_LVT: isize = 0x350; // LVT Local Int0; Register.
pub const LOCAL_APIC_OFFSET_LINT1_LVT: isize = 0x360; // LVT Local Int1 Register.
pub const LOCAL_APIC_OFFSET_ERROR_LVT: isize = 0x370; // LVT Error Register.
pub const LOCAL_APIC_OFFSET_INITIAL_COUNT: isize = 0x380; // Initial count Register.
pub const LOCAL_APIC_OFFSET_CURRENT_COUNT: isize = 0x390; // R/O Current count Register.
pub const LOCAL_APIC_OFFSET_DIVIDER: isize = 0x3e0; // Divide configuration Register.
pub const LOCAL_X2APIC_OFFSET_SELF_IPI: isize = 0x3f0; // Self IPI register, only present in x2APIC.

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LapicState {
    pub regs: [::std::os::raw::c_char; 1024usize],
}
impl Default for LapicState {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}
/*
impl Default for hv_register_value {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
} */
#[repr(C)]
#[derive(Copy, Clone)]
pub struct XSave {
    pub flags: u64,
    pub states: u64,
    pub data_size: u64,
    pub data_buffer: [::std::os::raw::c_char; 4096usize],
}
impl Default for XSave {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}
impl From<mshv_vp_state> for XSave {
    fn from(reg: mshv_vp_state) -> Self {
        let mut ret: XSave = XSave::default();
        ret.flags = reg.xsave.flags;
        ret.data_size = reg.buf_size;
        unsafe { ret.states = reg.xsave.states.as_uint64 };
        let min: usize = cmp::min(4096, reg.buf_size as u32) as usize;
        unsafe { ptr::copy(reg.buf.bytes, ret.data_buffer.as_ptr() as *mut u8, min) };
        ret
    }
}

impl From<XSave> for mshv_vp_state {
    fn from(reg: XSave) -> Self {
        let mut ret: mshv_vp_state = mshv_vp_state::default();
        ret.type_ = hv_get_set_vp_state_type_HV_GET_SET_VP_STATE_XSAVE;
        ret.xsave.flags = reg.flags;
        ret.buf_size = reg.data_size;
        ret.xsave.states.as_uint64 = reg.states;
        ret.buf.bytes = reg.data_buffer.as_ptr() as *mut u8;
        ret
    }
}
impl From<mshv_vp_state> for LapicState {
    fn from(reg: mshv_vp_state) -> Self {
        let mut ret: LapicState = LapicState::default();
        let state = ret.regs.as_mut_ptr();
        let hv_state = unsafe { *reg.buf.lapic };
        unsafe {
            *(state.offset(LOCAL_APIC_OFFSET_APIC_ID) as *mut u32) = hv_state.apic_id;
            *(state.offset(LOCAL_APIC_OFFSET_VERSION) as *mut u32) = hv_state.apic_version;
            *(state.offset(LOCAL_APIC_OFFSET_REMOTE_READ) as *mut u32) = hv_state.apic_remote_read;
            *(state.offset(LOCAL_APIC_OFFSET_LDR) as *mut u32) = hv_state.apic_ldr;
            *(state.offset(LOCAL_APIC_OFFSET_DFR) as *mut u32) = hv_state.apic_dfr;
            *(state.offset(LOCAL_APIC_OFFSET_SPURIOUS) as *mut u32) = hv_state.apic_spurious;
            *(state.offset(LOCAL_APIC_OFFSET_ERROR) as *mut u32) = hv_state.apic_esr;
            *(state.offset(LOCAL_APIC_OFFSET_ICR_LOW) as *mut u32) = hv_state.apic_icr_low;
            *(state.offset(LOCAL_APIC_OFFSET_ICR_HIGH) as *mut u32) = hv_state.apic_icr_high;
            *(state.offset(LOCAL_APIC_OFFSET_TIMER_LVT) as *mut u32) = hv_state.apic_lvt_timer;
            *(state.offset(LOCAL_APIC_OFFSET_THERMAL_LVT) as *mut u32) = hv_state.apic_lvt_thermal;
            *(state.offset(LOCAL_APIC_OFFSET_PERFMON_LVT) as *mut u32) = hv_state.apic_lvt_perfmon;
            *(state.offset(LOCAL_APIC_OFFSET_LINT0_LVT) as *mut u32) = hv_state.apic_lvt_lint0;
            *(state.offset(LOCAL_APIC_OFFSET_LINT1_LVT) as *mut u32) = hv_state.apic_lvt_lint1;
            *(state.offset(LOCAL_APIC_OFFSET_ERROR_LVT) as *mut u32) = hv_state.apic_lvt_error;
            *(state.offset(LOCAL_APIC_OFFSET_INITIAL_COUNT) as *mut u32) =
                hv_state.apic_initial_count;
            *(state.offset(LOCAL_APIC_OFFSET_CURRENT_COUNT) as *mut u32) =
                hv_state.apic_counter_value;
            *(state.offset(LOCAL_APIC_OFFSET_DIVIDER) as *mut u32) =
                hv_state.apic_divide_configuration;
        }

        /* vectors ISR TMR IRR */
        for i in 0..8 {
            unsafe {
                *(state.offset(LOCAL_APIC_OFFSET_ISR + i * 16) as *mut u32) =
                    hv_state.apic_isr[i as usize];
                *(state.offset(LOCAL_APIC_OFFSET_TMR + i * 16) as *mut u32) =
                    hv_state.apic_tmr[i as usize];
                *(state.offset(LOCAL_APIC_OFFSET_IRR + i * 16) as *mut u32) =
                    hv_state.apic_irr[i as usize];
            }
        }

        // Highest priority interrupt (isr = in service register) this is how WHP computes it
        let mut isrv: u32 = 0;
        for i in (0..8).rev() {
            let val: u32 = hv_state.apic_isr[i as usize];
            if val != 0 {
                isrv = 31 - val.leading_zeros(); // index of most significant set bit
                isrv += i * 4 * 8; // i don't know
                break;
            }
        }

        // TODO This is meant to be max(tpr, isrv), but tpr is not populated!
        unsafe {
            *(state.offset(LOCAL_APIC_OFFSET_PPR) as *mut u32) = isrv;
        }
        ret
    }
}

impl From<LapicState> for mshv_vp_state {
    fn from(reg: LapicState) -> Self {
        let state = reg.regs.as_ptr();
        let mut vp_state: mshv_vp_state = mshv_vp_state::default();
        unsafe {
            let mut lapic_state = hv_local_interrupt_controller_state {
                apic_id: *(state.offset(LOCAL_APIC_OFFSET_APIC_ID) as *mut u32),
                apic_version: *(state.offset(LOCAL_APIC_OFFSET_VERSION) as *mut u32),
                apic_remote_read: *(state.offset(LOCAL_APIC_OFFSET_REMOTE_READ) as *mut u32),
                apic_ldr: *(state.offset(LOCAL_APIC_OFFSET_LDR) as *mut u32),
                apic_dfr: *(state.offset(LOCAL_APIC_OFFSET_DFR) as *mut u32),
                apic_spurious: *(state.offset(LOCAL_APIC_OFFSET_SPURIOUS) as *mut u32),
                apic_esr: *(state.offset(LOCAL_APIC_OFFSET_ERROR) as *mut u32),
                apic_icr_low: *(state.offset(LOCAL_APIC_OFFSET_ICR_LOW) as *mut u32),
                apic_icr_high: *(state.offset(LOCAL_APIC_OFFSET_ICR_HIGH) as *mut u32),
                apic_lvt_timer: *(state.offset(LOCAL_APIC_OFFSET_TIMER_LVT) as *mut u32),
                apic_lvt_thermal: *(state.offset(LOCAL_APIC_OFFSET_THERMAL_LVT) as *mut u32),
                apic_lvt_perfmon: *(state.offset(LOCAL_APIC_OFFSET_PERFMON_LVT) as *mut u32),
                apic_lvt_lint0: *(state.offset(LOCAL_APIC_OFFSET_LINT0_LVT) as *mut u32),
                apic_lvt_lint1: *(state.offset(LOCAL_APIC_OFFSET_LINT1_LVT) as *mut u32),
                apic_lvt_error: *(state.offset(LOCAL_APIC_OFFSET_ERROR_LVT) as *mut u32),
                apic_initial_count: *(state.offset(LOCAL_APIC_OFFSET_INITIAL_COUNT) as *mut u32),
                apic_counter_value: *(state.offset(LOCAL_APIC_OFFSET_CURRENT_COUNT) as *mut u32),
                apic_divide_configuration: *(state.offset(LOCAL_APIC_OFFSET_DIVIDER) as *mut u32),
                apic_error_status: 0,
                apic_lvt_cmci: 0,
                apic_isr: [0; 8],
                apic_tmr: [0; 8],
                apic_irr: [0; 8],
            };

            /* vectors ISR TMR IRR */
            for i in 0..8 {
                lapic_state.apic_isr[i as usize] =
                    *(state.offset(LOCAL_APIC_OFFSET_ISR + i * 16) as *mut u32);
                lapic_state.apic_tmr[i as usize] =
                    *(state.offset(LOCAL_APIC_OFFSET_TMR + i * 16) as *mut u32);
                lapic_state.apic_irr[i as usize] =
                    *(state.offset(LOCAL_APIC_OFFSET_IRR + i * 16) as *mut u32);
            }
            vp_state.type_ =
                hv_get_set_vp_state_type_HV_GET_SET_VP_STATE_LOCAL_INTERRUPT_CONTROLLER_STATE;
            vp_state.buf_size = 1024;
            let boxed_obj = Box::new(lapic_state);
            vp_state.buf.lapic = Box::into_raw(boxed_obj);
        }
        vp_state
    }
}
