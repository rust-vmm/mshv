// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::ioctls::Result;
use crate::mshv_ioctls::*;
use mshv_bindings::*;
use std::cmp;
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
#[cfg(test)]
use std::slice;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

// Macro for setting up multiple 64 bit registers together
// Arguments:
///             1. vcpud fd
///             2. Array of Tuples of Register name and reguster value Example [(n1, v1), (n2,v2) ....]
#[allow(unused_macros)]
#[macro_export]
macro_rules! set_registers_64 {
    ($vcpu:expr, $arr_t:expr ) => {{
        let len = $arr_t.len();
        // Initialize with zero which is itself a enum value(HV_REGISTER_EXPLICIT_SUSPEND = 0).
        // This value does not have any effect as this is being overwritten anyway.
        let mut assocs: Vec<hv_register_assoc> = vec![
            hv_register_assoc {
                ..Default::default()
            };
            len
        ];
        for (i, x) in $arr_t.iter().enumerate() {
            let (a, b) = x;
            assocs[i].name = *a as u32;
            assocs[i].value = hv_register_value { reg64: *b };
        }
        #[allow(unused_parens)]
        $vcpu.set_reg(&assocs)
    }};
}

#[derive(Debug)]
/// Wrapper over Mshv vCPU ioctls.
pub struct VcpuFd {
    vcpu: File,
}

/// Helper function to create a new `VcpuFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `create_vcpu` from `VmFd`. The function cannot be part of the `VcpuFd` implementation because
/// then it would be exported with the public `VcpuFd` interface.
pub fn new_vcpu(vcpu: File) -> VcpuFd {
    VcpuFd { vcpu }
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vcpu.as_raw_fd()
    }
}

impl VcpuFd {
    /// Get the register values by providing an array of register names
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_reg(&self, reg_names: &mut [hv_register_assoc]) -> Result<()> {
        //TODO: Error if input register len is zero
        let mut mshv_vp_register_args = mshv_vp_registers {
            count: reg_names.len() as i32,
            regs: reg_names.as_mut_ptr(),
        };
        // SAFETY: we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe {
            ioctl_with_mut_ref(self, MSHV_GET_VP_REGISTERS(), &mut mshv_vp_register_args)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
    /// Sets a vCPU register to input value.
    ///
    /// # Arguments
    ///
    /// * `reg_name` - general purpose register name.
    /// * `reg_value` - register value.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_reg(&self, regs: &[hv_register_assoc]) -> Result<()> {
        let hv_vp_register_args = mshv_vp_registers {
            count: regs.len() as i32,
            regs: regs.as_ptr() as *mut hv_register_assoc,
        };
        // SAFETY: IOCTL call with correct types.
        let ret = unsafe { ioctl_with_ref(self, MSHV_SET_VP_REGISTERS(), &hv_vp_register_args) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
    /// Sets the vCPU general purpose registers
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_regs(&self, regs: &StandardRegisters) -> Result<()> {
        let reg_assocs = [
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RAX,
                value: hv_register_value { reg64: regs.rax },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RBX,
                value: hv_register_value { reg64: regs.rbx },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RCX,
                value: hv_register_value { reg64: regs.rcx },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RDX,
                value: hv_register_value { reg64: regs.rdx },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RSI,
                value: hv_register_value { reg64: regs.rsi },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RDI,
                value: hv_register_value { reg64: regs.rdi },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RSP,
                value: hv_register_value { reg64: regs.rsp },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RBP,
                value: hv_register_value { reg64: regs.rbp },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R8,
                value: hv_register_value { reg64: regs.r8 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R9,
                value: hv_register_value { reg64: regs.r9 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R10,
                value: hv_register_value { reg64: regs.r10 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R11,
                value: hv_register_value { reg64: regs.r11 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R12,
                value: hv_register_value { reg64: regs.r12 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R13,
                value: hv_register_value { reg64: regs.r13 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R14,
                value: hv_register_value { reg64: regs.r14 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_R15,
                value: hv_register_value { reg64: regs.r15 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RIP,
                value: hv_register_value { reg64: regs.rip },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RFLAGS,
                value: hv_register_value { reg64: regs.rflags },
                ..Default::default()
            },
        ];
        self.set_reg(&reg_assocs)?;
        Ok(())
    }

    /// Returns the vCPU general purpose registers.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_regs(&self) -> Result<StandardRegisters> {
        let reg_names = [
            hv_register_name_HV_X64_REGISTER_RAX,
            hv_register_name_HV_X64_REGISTER_RBX,
            hv_register_name_HV_X64_REGISTER_RCX,
            hv_register_name_HV_X64_REGISTER_RDX,
            hv_register_name_HV_X64_REGISTER_RSI,
            hv_register_name_HV_X64_REGISTER_RDI,
            hv_register_name_HV_X64_REGISTER_RSP,
            hv_register_name_HV_X64_REGISTER_RBP,
            hv_register_name_HV_X64_REGISTER_R8,
            hv_register_name_HV_X64_REGISTER_R9,
            hv_register_name_HV_X64_REGISTER_R10,
            hv_register_name_HV_X64_REGISTER_R11,
            hv_register_name_HV_X64_REGISTER_R12,
            hv_register_name_HV_X64_REGISTER_R13,
            hv_register_name_HV_X64_REGISTER_R14,
            hv_register_name_HV_X64_REGISTER_R15,
            hv_register_name_HV_X64_REGISTER_RIP,
            hv_register_name_HV_X64_REGISTER_RFLAGS,
        ];
        let mut reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .map(|name| hv_register_assoc {
                name: *name,
                ..Default::default()
            })
            .collect();
        self.get_reg(&mut reg_assocs)?;
        let mut ret_regs = StandardRegisters::default();
        // SAFETY: access union fields
        unsafe {
            ret_regs.rax = reg_assocs[0].value.reg64;
            ret_regs.rbx = reg_assocs[1].value.reg64;
            ret_regs.rcx = reg_assocs[2].value.reg64;
            ret_regs.rdx = reg_assocs[3].value.reg64;
            ret_regs.rsi = reg_assocs[4].value.reg64;
            ret_regs.rdi = reg_assocs[5].value.reg64;
            ret_regs.rsp = reg_assocs[6].value.reg64;
            ret_regs.rbp = reg_assocs[7].value.reg64;
            ret_regs.r8 = reg_assocs[8].value.reg64;
            ret_regs.r9 = reg_assocs[9].value.reg64;
            ret_regs.r10 = reg_assocs[10].value.reg64;
            ret_regs.r11 = reg_assocs[11].value.reg64;
            ret_regs.r12 = reg_assocs[12].value.reg64;
            ret_regs.r13 = reg_assocs[13].value.reg64;
            ret_regs.r14 = reg_assocs[14].value.reg64;
            ret_regs.r15 = reg_assocs[15].value.reg64;
            ret_regs.rip = reg_assocs[16].value.reg64;
            ret_regs.rflags = reg_assocs[17].value.reg64;
        }

        Ok(ret_regs)
    }
    /// Returns the vCPU special registers.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_sregs(&self) -> Result<SpecialRegisters> {
        let reg_names: [::std::os::raw::c_uint; 18] = [
            hv_register_name_HV_X64_REGISTER_CS,
            hv_register_name_HV_X64_REGISTER_DS,
            hv_register_name_HV_X64_REGISTER_ES,
            hv_register_name_HV_X64_REGISTER_FS,
            hv_register_name_HV_X64_REGISTER_GS,
            hv_register_name_HV_X64_REGISTER_SS,
            hv_register_name_HV_X64_REGISTER_TR,
            hv_register_name_HV_X64_REGISTER_LDTR,
            hv_register_name_HV_X64_REGISTER_GDTR,
            hv_register_name_HV_X64_REGISTER_IDTR,
            hv_register_name_HV_X64_REGISTER_CR0,
            hv_register_name_HV_X64_REGISTER_CR2,
            hv_register_name_HV_X64_REGISTER_CR3,
            hv_register_name_HV_X64_REGISTER_CR4,
            hv_register_name_HV_X64_REGISTER_CR8,
            hv_register_name_HV_X64_REGISTER_EFER,
            hv_register_name_HV_X64_REGISTER_APIC_BASE,
            hv_register_name_HV_REGISTER_PENDING_INTERRUPTION,
        ];
        let mut reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .map(|name| hv_register_assoc {
                name: *name,
                ..Default::default()
            })
            .collect();
        self.get_reg(&mut reg_assocs)?;
        let mut ret_regs = SpecialRegisters::default();
        // SAFETY: access union fields
        unsafe {
            ret_regs.cs = SegmentRegister::from(reg_assocs[0].value.segment);
            ret_regs.ds = SegmentRegister::from(reg_assocs[1].value.segment);
            ret_regs.es = SegmentRegister::from(reg_assocs[2].value.segment);
            ret_regs.fs = SegmentRegister::from(reg_assocs[3].value.segment);
            ret_regs.gs = SegmentRegister::from(reg_assocs[4].value.segment);
            ret_regs.ss = SegmentRegister::from(reg_assocs[5].value.segment);
            ret_regs.tr = SegmentRegister::from(reg_assocs[6].value.segment);
            ret_regs.ldt = SegmentRegister::from(reg_assocs[7].value.segment);
            ret_regs.gdt = TableRegister::from(reg_assocs[8].value.table);
            ret_regs.idt = TableRegister::from(reg_assocs[9].value.table);
            ret_regs.cr0 = reg_assocs[10].value.reg64;
            ret_regs.cr2 = reg_assocs[11].value.reg64;
            ret_regs.cr3 = reg_assocs[12].value.reg64;
            ret_regs.cr4 = reg_assocs[13].value.reg64;
            ret_regs.cr8 = reg_assocs[14].value.reg64;
            ret_regs.efer = reg_assocs[15].value.reg64;
            ret_regs.apic_base = reg_assocs[16].value.reg64;
            let pending_reg = reg_assocs[17].value.pending_interruption.as_uint64;
            if (pending_reg & 0x1) == 1 && // interruption pending
            (pending_reg >> 1).trailing_zeros() >= 3
            {
                // interrupt type external
                let interrupt_nr = pending_reg >> 16;
                if interrupt_nr > 255 {
                    panic!("Invalid interrupt vector number > 255");
                }
                // we have a bit array of 4 u64s, so we can split it to get the array index and the
                // bit index
                let bit_offset = pending_reg & 0x3F; // 6 bits = 0-63
                let index = pending_reg >> 6;
                ret_regs.interrupt_bitmap[index as usize] = 1 << (63 - bit_offset);
                // shift from the left
            }
        };

        Ok(ret_regs)
    }
    /// Sets the vCPU special registers
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<()> {
        let reg_names: [hv_register_name; 17] = [
            hv_register_name_HV_X64_REGISTER_CS,
            hv_register_name_HV_X64_REGISTER_DS,
            hv_register_name_HV_X64_REGISTER_ES,
            hv_register_name_HV_X64_REGISTER_FS,
            hv_register_name_HV_X64_REGISTER_GS,
            hv_register_name_HV_X64_REGISTER_SS,
            hv_register_name_HV_X64_REGISTER_TR,
            hv_register_name_HV_X64_REGISTER_LDTR,
            hv_register_name_HV_X64_REGISTER_GDTR,
            hv_register_name_HV_X64_REGISTER_IDTR,
            hv_register_name_HV_X64_REGISTER_CR0,
            hv_register_name_HV_X64_REGISTER_CR2,
            hv_register_name_HV_X64_REGISTER_CR3,
            hv_register_name_HV_X64_REGISTER_CR4,
            hv_register_name_HV_X64_REGISTER_CR8,
            hv_register_name_HV_X64_REGISTER_EFER,
            hv_register_name_HV_X64_REGISTER_APIC_BASE,
        ];
        let reg_values: [hv_register_value; 17] = [
            hv_register_value {
                segment: sregs.cs.into(),
            },
            hv_register_value {
                segment: sregs.ds.into(),
            },
            hv_register_value {
                segment: sregs.es.into(),
            },
            hv_register_value {
                segment: sregs.fs.into(),
            },
            hv_register_value {
                segment: sregs.gs.into(),
            },
            hv_register_value {
                segment: sregs.ss.into(),
            },
            hv_register_value {
                segment: sregs.tr.into(),
            },
            hv_register_value {
                segment: sregs.ldt.into(),
            },
            hv_register_value {
                table: sregs.gdt.into(),
            },
            hv_register_value {
                table: sregs.idt.into(),
            },
            hv_register_value { reg64: sregs.cr0 },
            hv_register_value { reg64: sregs.cr2 },
            hv_register_value { reg64: sregs.cr3 },
            hv_register_value { reg64: sregs.cr4 },
            hv_register_value { reg64: sregs.cr8 },
            hv_register_value { reg64: sregs.efer },
            hv_register_value {
                reg64: sregs.apic_base,
            },
        ];

        // TODO support asserting an interrupt using interrupt_bitmap
        // we can't do this without the vm fd which isn't available here
        for bits in &sregs.interrupt_bitmap {
            if *bits != 0 {
                return Err(errno::Error::new(libc::EINVAL));
            }
        }

        let reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .zip(reg_values.iter())
            .map(|t| hv_register_assoc {
                name: *t.0,
                value: *t.1,
                ..Default::default()
            })
            .collect();
        self.set_reg(&reg_assocs)?;
        Ok(())
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn fpu_registers() -> [hv_register_name; 26] {
        [
            hv_register_name_HV_X64_REGISTER_XMM0,
            hv_register_name_HV_X64_REGISTER_XMM1,
            hv_register_name_HV_X64_REGISTER_XMM2,
            hv_register_name_HV_X64_REGISTER_XMM3,
            hv_register_name_HV_X64_REGISTER_XMM4,
            hv_register_name_HV_X64_REGISTER_XMM5,
            hv_register_name_HV_X64_REGISTER_XMM6,
            hv_register_name_HV_X64_REGISTER_XMM7,
            hv_register_name_HV_X64_REGISTER_XMM8,
            hv_register_name_HV_X64_REGISTER_XMM9,
            hv_register_name_HV_X64_REGISTER_XMM10,
            hv_register_name_HV_X64_REGISTER_XMM11,
            hv_register_name_HV_X64_REGISTER_XMM12,
            hv_register_name_HV_X64_REGISTER_XMM13,
            hv_register_name_HV_X64_REGISTER_XMM14,
            hv_register_name_HV_X64_REGISTER_XMM15,
            hv_register_name_HV_X64_REGISTER_FP_MMX0,
            hv_register_name_HV_X64_REGISTER_FP_MMX1,
            hv_register_name_HV_X64_REGISTER_FP_MMX2,
            hv_register_name_HV_X64_REGISTER_FP_MMX3,
            hv_register_name_HV_X64_REGISTER_FP_MMX4,
            hv_register_name_HV_X64_REGISTER_FP_MMX5,
            hv_register_name_HV_X64_REGISTER_FP_MMX6,
            hv_register_name_HV_X64_REGISTER_FP_MMX7,
            hv_register_name_HV_X64_REGISTER_FP_CONTROL_STATUS,
            hv_register_name_HV_X64_REGISTER_XMM_CONTROL_STATUS,
        ]
    }

    /// Sets the vCPU floating point registers
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_fpu(&self, fpu: &FloatingPointUnit) -> Result<()> {
        let reg_names = Self::fpu_registers();
        let mut reg_values: [hv_register_value; 26] = [hv_register_value { reg64: 0 }; 26];
        // First 16 registers are XMM registers.
        for (i, reg) in reg_values.iter_mut().enumerate().take(16) {
            // SAFETY: we're sure the underlying bit pattern is valid
            unsafe {
                *reg = hv_register_value {
                    reg128: std::mem::transmute::<[u8; 16usize], hv_u128>(fpu.xmm[i]),
                };
            }
        }
        // The next 8 registers are FP registers.
        for (i, reg) in reg_values.iter_mut().enumerate().take(24).skip(16) {
            let fp_i = i - 16;
            // SAFETY: we're sure the underlying bit pattern is valid
            unsafe {
                *reg = hv_register_value {
                    fp: hv_x64_fp_register {
                        as_uint128: std::mem::transmute::<[u8; 16usize], hv_u128>(fpu.fpr[fp_i]),
                    },
                };
            }
        }
        reg_values[24] = hv_register_value {
            fp_control_status: hv_x64_fp_control_status_register {
                __bindgen_anon_1: hv_x64_fp_control_status_register__bindgen_ty_1 {
                    fp_control: fpu.fcw,
                    fp_status: fpu.fsw,
                    fp_tag: fpu.ftwx,
                    reserved: 0x0,
                    last_fp_op: fpu.last_opcode,
                    __bindgen_anon_1:
                        hv_x64_fp_control_status_register__bindgen_ty_1__bindgen_ty_1 {
                            last_fp_rip: fpu.last_ip,
                        },
                },
            },
        };
        reg_values[25] = hv_register_value {
            xmm_control_status: hv_x64_xmm_control_status_register {
                __bindgen_anon_1: hv_x64_xmm_control_status_register__bindgen_ty_1 {
                    xmm_status_control: fpu.mxcsr,
                    xmm_status_control_mask: 0x0,
                    __bindgen_anon_1:
                        hv_x64_xmm_control_status_register__bindgen_ty_1__bindgen_ty_1 {
                            last_fp_rdp: fpu.last_dp,
                        },
                },
            },
        };

        let reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .zip(reg_values.iter())
            .map(|t| hv_register_assoc {
                name: *t.0,
                value: *t.1,
                ..Default::default()
            })
            .collect();

        self.set_reg(&reg_assocs)?;
        Ok(())
    }
    /// Returns the floating point state (FPU) from the vCPU.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_fpu(&self) -> Result<FloatingPointUnit> {
        let reg_names = Self::fpu_registers();
        let mut reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .map(|name| hv_register_assoc {
                name: *name,
                ..Default::default()
            })
            .collect();
        self.get_reg(&mut reg_assocs)?;

        // SAFETY: access union fields
        let fp_control_status: hv_x64_fp_control_status_register__bindgen_ty_1 =
            unsafe { reg_assocs[24].value.fp_control_status.__bindgen_anon_1 };
        let xmm_control_status: hv_x64_xmm_control_status_register__bindgen_ty_1 =
            unsafe { reg_assocs[25].value.xmm_control_status.__bindgen_anon_1 };
        let mut ret_regs = unsafe {
            FloatingPointUnit {
                fpr: [[0x0; 16usize]; 8usize],
                fcw: fp_control_status.fp_control,
                fsw: fp_control_status.fp_status,
                ftwx: fp_control_status.fp_tag,
                pad1: 0x0,
                last_opcode: fp_control_status.last_fp_op,
                last_ip: fp_control_status.__bindgen_anon_1.last_fp_rip,
                last_dp: xmm_control_status.__bindgen_anon_1.last_fp_rdp,
                xmm: [[0; 16usize]; 16usize],
                mxcsr: xmm_control_status.xmm_status_control,
                pad2: 0x0,
            }
        };

        // First 16 registers are XMM registers.
        for (i, reg) in reg_assocs.iter().enumerate().take(16) {
            // SAFETY: we trust the hypervisor returns the expected data type.
            unsafe {
                ret_regs.xmm[i] = std::mem::transmute::<hv_u128, [u8; 16usize]>(reg.value.reg128);
            }
        }
        // The next 8 registers are FP registers.
        for (i, reg) in reg_assocs.iter().enumerate().take(24).skip(16) {
            let fp_i = i - 16;
            // SAFETY: we trust the hypervisor returns the expected data type.
            unsafe {
                ret_regs.fpr[fp_i] =
                    std::mem::transmute::<hv_u128, [u8; 16usize]>(reg.value.fp.as_uint128);
            }
        }

        Ok(ret_regs)
    }
    /// X86 specific call that returns the vcpu's current "debug registers".
    pub fn get_debug_regs(&self) -> Result<DebugRegisters> {
        let reg_names: [hv_register_name; 6] = [
            hv_register_name_HV_X64_REGISTER_DR0,
            hv_register_name_HV_X64_REGISTER_DR1,
            hv_register_name_HV_X64_REGISTER_DR2,
            hv_register_name_HV_X64_REGISTER_DR3,
            hv_register_name_HV_X64_REGISTER_DR6,
            hv_register_name_HV_X64_REGISTER_DR7,
        ];

        let mut reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .map(|name| hv_register_assoc {
                name: *name,
                ..Default::default()
            })
            .collect();

        self.get_reg(&mut reg_assocs)?;

        let ret_regs = unsafe {
            DebugRegisters {
                dr0: reg_assocs[0].value.reg64,
                dr1: reg_assocs[1].value.reg64,
                dr2: reg_assocs[2].value.reg64,
                dr3: reg_assocs[3].value.reg64,
                dr6: reg_assocs[4].value.reg64,
                dr7: reg_assocs[5].value.reg64,
            }
        };

        Ok(ret_regs)
    }
    /// X86 specific call that sets the vcpu's current "debug registers".
    pub fn set_debug_regs(&self, d_regs: &DebugRegisters) -> Result<()> {
        let reg_names = [
            hv_register_name_HV_X64_REGISTER_DR0,
            hv_register_name_HV_X64_REGISTER_DR1,
            hv_register_name_HV_X64_REGISTER_DR2,
            hv_register_name_HV_X64_REGISTER_DR3,
            hv_register_name_HV_X64_REGISTER_DR6,
            hv_register_name_HV_X64_REGISTER_DR7,
        ];
        let reg_values = [
            hv_register_value { reg64: d_regs.dr0 },
            hv_register_value { reg64: d_regs.dr1 },
            hv_register_value { reg64: d_regs.dr2 },
            hv_register_value { reg64: d_regs.dr3 },
            hv_register_value { reg64: d_regs.dr6 },
            hv_register_value { reg64: d_regs.dr7 },
        ];

        let reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .zip(reg_values.iter())
            .map(|t| hv_register_assoc {
                name: *t.0,
                value: *t.1,
                ..Default::default()
            })
            .collect();

        self.set_reg(&reg_assocs)?;
        Ok(())
    }
    /// Returns the machine-specific registers (MSR) for this vCPU.
    pub fn get_msrs(&self, msrs: &mut Msrs) -> Result<usize> {
        let nmsrs = msrs.as_fam_struct_ref().nmsrs as usize;
        let mut reg_assocs: Vec<hv_register_assoc> = Vec::with_capacity(nmsrs);

        for i in 0..nmsrs {
            let name = match msr_to_hv_reg_name(msrs.as_slice()[i].index) {
                Ok(n) => n,
                Err(_) => return Err(errno::Error::new(libc::EINVAL)),
            };
            reg_assocs.push(hv_register_assoc {
                name,
                ..Default::default()
            });
        }

        self.get_reg(&mut reg_assocs)?;

        for (i, reg) in reg_assocs.iter().enumerate().take(nmsrs) {
            // SAFETY: access union fields requires unsafe. The values are initialized by get_reg
            // call.
            unsafe {
                msrs.as_mut_slice()[i].data = reg.value.reg64;
            }
        }

        Ok(nmsrs)
    }
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    pub fn set_msrs(&self, msrs: &Msrs) -> Result<usize> {
        let nmsrs = msrs.as_fam_struct_ref().nmsrs as usize;
        let mut reg_assocs: Vec<hv_register_assoc> = Vec::with_capacity(nmsrs);

        for i in 0..nmsrs {
            let name = match msr_to_hv_reg_name(msrs.as_slice()[i].index) {
                Ok(n) => n,
                Err(_) => return Err(errno::Error::new(libc::EINVAL)),
            };
            reg_assocs.push(hv_register_assoc {
                name,
                value: hv_register_value {
                    reg64: msrs.as_slice()[i].data,
                },
                ..Default::default()
            });
        }

        self.set_reg(&reg_assocs)?;
        Ok(0_usize)
    }
    ///  Triggers the running of the current virtual CPU returning an exit reason.
    pub fn run(&self, mut hv_message_input: hv_message) -> Result<hv_message> {
        // SAFETY: we know that our file is a vCPU fd and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_RUN_VP(), &mut hv_message_input) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(hv_message_input)
    }
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    pub fn get_vcpu_events(&self) -> Result<VcpuEvents> {
        let reg_names: [hv_register_name; 5] = [
            hv_register_name_HV_REGISTER_PENDING_INTERRUPTION,
            hv_register_name_HV_REGISTER_INTERRUPT_STATE,
            hv_register_name_HV_REGISTER_INTERNAL_ACTIVITY_STATE,
            hv_register_name_HV_REGISTER_PENDING_EVENT0,
            hv_register_name_HV_REGISTER_PENDING_EVENT1,
        ];
        let mut reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .map(|name| hv_register_assoc {
                name: *name,
                ..Default::default()
            })
            .collect();
        self.get_reg(&mut reg_assocs)?;
        let mut ret_regs = VcpuEvents::default();
        // SAFETY: access union fields
        unsafe {
            ret_regs.pending_interruption = reg_assocs[0].value.reg64;
            ret_regs.interrupt_state = reg_assocs[1].value.reg64;
            ret_regs.internal_activity_state = reg_assocs[2].value.reg64;
            ret_regs.pending_event0 =
                std::mem::transmute::<hv_u128, [u8; 16usize]>(reg_assocs[3].value.reg128);
            ret_regs.pending_event1 =
                std::mem::transmute::<hv_u128, [u8; 16usize]>(reg_assocs[4].value.reg128);
        }
        Ok(ret_regs)
    }
    /// Sets pending exceptions, interrupts, and NMIs as well as related states of the vcpu.
    pub fn set_vcpu_events(&self, events: &VcpuEvents) -> Result<()> {
        let reg_names: [hv_register_name; 5] = [
            hv_register_name_HV_REGISTER_PENDING_INTERRUPTION,
            hv_register_name_HV_REGISTER_INTERRUPT_STATE,
            hv_register_name_HV_REGISTER_INTERNAL_ACTIVITY_STATE,
            hv_register_name_HV_REGISTER_PENDING_EVENT0,
            hv_register_name_HV_REGISTER_PENDING_EVENT1,
        ];
        // SAFETY: access union fields requires unsafe. For transmuting values we're sure
        // the types and bit patterns are correct.
        let reg_values: [hv_register_value; 5] = unsafe {
            [
                hv_register_value {
                    reg64: events.pending_interruption,
                },
                hv_register_value {
                    reg64: events.interrupt_state,
                },
                hv_register_value {
                    reg64: events.internal_activity_state,
                },
                hv_register_value {
                    reg128: std::mem::transmute::<[u8; 16usize], hv_u128>(events.pending_event0),
                },
                hv_register_value {
                    reg128: std::mem::transmute::<[u8; 16usize], hv_u128>(events.pending_event1),
                },
            ]
        };

        let reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .zip(reg_values.iter())
            .map(|t| hv_register_assoc {
                name: *t.0,
                value: *t.1,
                ..Default::default()
            })
            .collect();
        self.set_reg(&reg_assocs)?;
        Ok(())
    }
    /// X86 specific call that returns the vcpu's current "xcrs".
    pub fn get_xcrs(&self) -> Result<Xcrs> {
        let mut reg_assocs: [hv_register_assoc; 1] = [hv_register_assoc {
            name: hv_register_name_HV_X64_REGISTER_XFEM,
            ..Default::default()
        }];
        self.get_reg(&mut reg_assocs)?;

        // SAFETY: access union fields
        let ret_regs = unsafe {
            Xcrs {
                xcr0: reg_assocs[0].value.reg64,
            }
        };

        Ok(ret_regs)
    }
    /// X86 specific call to set XCRs
    pub fn set_xcrs(&self, xcrs: &Xcrs) -> Result<()> {
        self.set_reg(&[hv_register_assoc {
            name: hv_register_name_HV_X64_REGISTER_XFEM,
            value: hv_register_value { reg64: xcrs.xcr0 },
            ..Default::default()
        }])
    }
    /// X86 specific call that returns the vcpu's current "misc registers".
    pub fn get_misc_regs(&self) -> Result<MiscRegs> {
        let mut reg_assocs: [hv_register_assoc; 1] = [hv_register_assoc {
            name: hv_register_name_HV_X64_REGISTER_HYPERCALL,
            ..Default::default()
        }];
        self.get_reg(&mut reg_assocs)?;

        // SAFETY: access union fields
        let ret_regs = unsafe {
            MiscRegs {
                hypercall: reg_assocs[0].value.reg64,
            }
        };

        Ok(ret_regs)
    }
    /// X86 specific call that sets the vcpu's current "misc registers".
    pub fn set_misc_regs(&self, misc: &MiscRegs) -> Result<()> {
        self.set_reg(&[hv_register_assoc {
            name: hv_register_name_HV_X64_REGISTER_HYPERCALL,
            value: hv_register_value {
                reg64: misc.hypercall,
            },
            ..Default::default()
        }])
    }
    /// Returns the VCpu state. This IOCTLs can be used to get XSave and LAPIC state.
    pub fn get_vp_state_ioctl(&self, state: &mut mshv_vp_state) -> Result<()> {
        // SAFETY: we know that our file is a vCPU fd and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_GET_VP_STATE(), state) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
    /// Set vp states (LAPIC, XSave etc)
    /// Test code already covered by get/set_lapic/xsave
    pub fn set_vp_state_ioctl(&self, state: &mshv_vp_state) -> Result<()> {
        // SAFETY: IOCTL call with correct types
        let ret = unsafe { ioctl_with_ref(self, MSHV_SET_VP_STATE(), state) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
    /// Get the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    pub fn get_lapic(&self) -> Result<LapicState> {
        let buffer = Buffer::new(0x1000, 0x1000)?;
        let mut vp_state: mshv_vp_state = mshv_vp_state::default();
        vp_state.buf.bytes = buffer.buf;
        vp_state.buf_size = buffer.size() as u64;
        vp_state.type_ =
            hv_get_set_vp_state_type_HV_GET_SET_VP_STATE_LOCAL_INTERRUPT_CONTROLLER_STATE;

        self.get_vp_state_ioctl(&mut vp_state)?;
        Ok(LapicState::from(vp_state))
    }
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    pub fn set_lapic(&self, lapic_state: &LapicState) -> Result<()> {
        let mut vp_state: mshv_vp_state = mshv_vp_state::from(*lapic_state);
        let buffer = Buffer::new(0x1000, 0x1000)?;
        let min: usize = cmp::min(buffer.size(), vp_state.buf_size as usize);
        // SAFETY: src and dest are valid and properly aligned
        unsafe { ptr::copy(vp_state.buf.bytes, buffer.buf, min) };
        vp_state.buf_size = buffer.size() as u64;
        vp_state.buf.bytes = buffer.buf;
        self.set_vp_state_ioctl(&vp_state)
    }
    /// Returns the xsave data
    pub fn get_xsave(&self) -> Result<XSave> {
        let buffer = Buffer::new(0x1000, 0x1000)?;
        let mut vp_state: mshv_vp_state = mshv_vp_state::default();
        vp_state.buf.bytes = buffer.buf;
        vp_state.buf_size = buffer.size() as u64;
        vp_state.type_ = hv_get_set_vp_state_type_HV_GET_SET_VP_STATE_XSAVE;
        self.get_vp_state_ioctl(&mut vp_state)?;
        let ret = XSave::from(vp_state);
        Ok(ret)
    }
    /// Set the xsave data
    pub fn set_xsave(&self, data: &XSave) -> Result<()> {
        let mut vp_state: mshv_vp_state = mshv_vp_state::from(*data);
        let buffer = Buffer::new(0x1000, 0x1000)?;
        let min: usize = cmp::min(buffer.size(), vp_state.buf_size as usize);
        // SAFETY: src and dest are valid and properly aligned
        unsafe { ptr::copy(data.buffer.as_ptr().offset(24) as *mut u8, buffer.buf, min) };
        vp_state.buf_size = buffer.size() as u64;
        vp_state.buf.bytes = buffer.buf;
        self.set_vp_state_ioctl(&vp_state)
    }
    /// Translate guest virtual address to guest physical address
    pub fn translate_gva(&self, gva: u64, flags: u64) -> Result<(u64, hv_translate_gva_result)> {
        let gpa: u64 = 0;
        let result = hv_translate_gva_result { as_uint64: 0 };

        let mut args = mshv_translate_gva {
            gva,
            flags,
            gpa: &gpa as *const _ as *mut u64,
            result: &result as *const _ as *mut hv_translate_gva_result,
        };
        // SAFETY: we know that our file is a vCPU fd, we know the kernel honours its ABI.
        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_VP_TRANSLATE_GVA(), &mut args) };
        if ret != 0 {
            return Err(errno::Error::last());
        }

        Ok((gpa, result))
    }
    /// X86 specific call that returns the vcpu's current "suspend registers".
    pub fn get_suspend_regs(&self) -> Result<SuspendRegisters> {
        let reg_names: [hv_register_name; 2] = [
            hv_register_name_HV_REGISTER_EXPLICIT_SUSPEND,
            hv_register_name_HV_REGISTER_INTERCEPT_SUSPEND,
        ];

        let mut reg_assocs: Vec<hv_register_assoc> = reg_names
            .iter()
            .map(|name| hv_register_assoc {
                name: *name,
                ..Default::default()
            })
            .collect();

        self.get_reg(&mut reg_assocs)?;

        // SAFETY: access union fields
        let ret_regs = unsafe {
            SuspendRegisters {
                explicit_register: reg_assocs[0].value.reg64,
                intercept_register: reg_assocs[1].value.reg64,
            }
        };

        Ok(ret_regs)
    }
    /// Register override CPUID values for one leaf.
    pub fn register_intercept_result_cpuid_entry(
        &self,
        entry: &hv_cpuid_entry,
        always_override: Option<u8>,
        subleaf_specific: Option<u8>,
    ) -> Result<()> {
        let subleaf_specific_param = subleaf_specific.unwrap_or(0);
        let always_override_param = always_override.unwrap_or(1);

        let mshv_cpuid = hv_register_x64_cpuid_result_parameters {
            input: hv_register_x64_cpuid_result_parameters__bindgen_ty_1 {
                eax: entry.function,
                // Subleaf index, default is 0. Further subleafs can be
                // overwritten by a repeated call to this function with a desired
                // index passed. Refer to the Intel Dev Manual for a particular
                // EAX input for the further details.
                ecx: entry.index,
                // Whether the intercept result is to be applied to all
                // the subleafs (0) or just to the specific subleaf (1).
                subleaf_specific: subleaf_specific_param,
                // Override even if the hypervisor computed value is zero.
                // If set to 1, the registered result will be still applied.
                always_override: always_override_param,
                // Not relevant, bindgen specific struct padding.
                padding: 0,
            },
            // With regard to masks - these are to specify bits to be overwritten.
            // The current CpuidEntry structure wouldn't allow to carry the masks
            // in addition to the actual register values. For this reason, the
            // masks are set to the exact values of the corresponding register bits
            // to be registered for an overwrite. To view resulting values the
            // hypervisor would return, HvCallGetVpCpuidValues hypercall can be used.
            result: hv_register_x64_cpuid_result_parameters__bindgen_ty_2 {
                eax: entry.eax,
                eax_mask: entry.eax,
                ebx: entry.ebx,
                ebx_mask: entry.ebx,
                ecx: entry.ecx,
                ecx_mask: entry.ecx,
                edx: entry.edx,
                edx_mask: entry.edx,
            },
        };
        let args = mshv_register_intercept_result {
            intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_X64_CPUID,
            parameters: hv_register_intercept_result_parameters { cpuid: mshv_cpuid },
        };
        let ret = unsafe { ioctl_with_ref(self, MSHV_VP_REGISTER_INTERCEPT_RESULT(), &args) };
        if ret != 0 {
            return Err(errno::Error::last());
        }

        Ok(())
    }
    /// Extend CPUID values delivered by hypervisor.
    pub fn register_intercept_result_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        let mut ret = Ok(());

        for entry in cpuid.as_slice().iter() {
            let override_arg = None;
            let mut subleaf_specific = None;

            match entry.function {
                // 0xb - Extended Topology Enumeration Leaf
                // 0x1f - V2 Extended Topology Enumeration Leaf
                0xb | 0x1f => {
                    subleaf_specific = Some(1);
                }
                _ => {}
            }
            let eret =
                self.register_intercept_result_cpuid_entry(entry, override_arg, subleaf_specific);
            if eret.is_err() && ret.is_ok() {
                ret = eret;
            }
        }

        ret
    }
    /// X86 specific call that retrieves the values of the specified CPUID
    /// leaf as observed on the virtual processor.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_cpuid_values(&self, eax: u32, ecx: u32) -> Result<[u32; 4]> {
        let mut parms = mshv_get_vp_cpuid_values {
            function: eax,
            index: ecx,
            ..Default::default()
        };
        // SAFETY: we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_GET_VP_CPUID_VALUES(), &mut parms) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok([parms.eax, parms.ebx, parms.ecx, parms.edx])
    }
    /// Read GPA
    pub fn gpa_read(&self, input: &mut mshv_read_write_gpa) -> Result<mshv_read_write_gpa> {
        // SAFETY: we know that our file is a vCPU fd, we know the kernel honours its ABI.
        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_READ_GPA(), input) };
        if ret != 0 {
            return Err(errno::Error::last());
        }

        Ok(*input)
    }
    /// Write GPA
    pub fn gpa_write(&self, input: &mut mshv_read_write_gpa) -> Result<mshv_read_write_gpa> {
        // SAFETY: we know that our file is a vCPU fd, we know the kernel honours its ABI.
        let ret = unsafe { ioctl_with_mut_ref(self, MSHV_WRITE_GPA(), input) };
        if ret != 0 {
            return Err(errno::Error::last());
        }

        Ok(*input)
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::ioctls::system::Mshv;

    #[test]
    fn test_set_get_regs() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        vcpu.set_reg(&[
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RIP,
                value: hv_register_value { reg64: 0x1000 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RFLAGS,
                value: hv_register_value { reg64: 0x2 },
                ..Default::default()
            },
        ])
        .unwrap();

        let mut get_regs: [hv_register_assoc; 2] = [
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RIP,
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RFLAGS,
                ..Default::default()
            },
        ];

        vcpu.get_reg(&mut get_regs).unwrap();

        // SAFETY: access union fields
        unsafe {
            assert!(get_regs[0].value.reg64 == 0x1000);
            assert!(get_regs[1].value.reg64 == 0x2);
        }
    }

    #[test]
    fn test_set_get_sregs() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let s_sregs = vcpu.get_sregs().unwrap();
        vcpu.set_sregs(&s_sregs).unwrap();
        let g_sregs = vcpu.get_sregs().unwrap();
        assert!(g_sregs.cr0 == s_sregs.cr0);
        assert!(g_sregs.cr2 == s_sregs.cr2);
        assert!(g_sregs.cr3 == s_sregs.cr3);
        assert!(g_sregs.cr4 == s_sregs.cr4);
        assert!(g_sregs.cr8 == s_sregs.cr8);
        assert!(g_sregs.cr8 == s_sregs.cr8);
        assert!(g_sregs.apic_base == s_sregs.apic_base);
        assert!(g_sregs.efer == s_sregs.efer);
    }
    #[test]
    fn test_set_get_standardregisters() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = vcpu.get_regs().unwrap();
        vcpu.set_regs(&s_regs).unwrap();
        let g_regs = vcpu.get_regs().unwrap();
        assert!(g_regs.rax == s_regs.rax);
        assert!(g_regs.rbx == s_regs.rbx);
        assert!(g_regs.rcx == s_regs.rcx);
        assert!(g_regs.rdx == s_regs.rdx);
    }
    #[test]
    fn test_set_get_debug_gisters() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = vcpu.get_debug_regs().unwrap();
        vcpu.set_debug_regs(&s_regs).unwrap();
        let g_regs = vcpu.get_debug_regs().unwrap();
        assert!(g_regs.dr0 == s_regs.dr0);
        assert!(g_regs.dr1 == s_regs.dr1);
        assert!(g_regs.dr2 == s_regs.dr2);
        assert!(g_regs.dr3 == s_regs.dr3);
        assert!(g_regs.dr6 == s_regs.dr6);
        assert!(g_regs.dr7 == s_regs.dr7);
    }
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_get_fpu() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = vcpu.get_fpu().unwrap();
        vcpu.set_fpu(&s_regs).unwrap();
        let g_regs = vcpu.get_fpu().unwrap();
        for i in 0..16 {
            for j in 0..16 {
                assert!(g_regs.xmm[i][j] == s_regs.xmm[i][j]);
            }
        }
        for i in 0..8 {
            for j in 0..16 {
                assert!(g_regs.fpr[i][j] == s_regs.fpr[i][j]);
            }
        }
        assert!(g_regs.fcw == s_regs.fcw);
        assert!(g_regs.fsw == s_regs.fsw);
        assert!(g_regs.ftwx == s_regs.ftwx);
        assert!(g_regs.last_opcode == s_regs.last_opcode);
        assert!(g_regs.last_ip == s_regs.last_ip);
        assert!(g_regs.last_dp == s_regs.last_dp);
        assert!(g_regs.mxcsr == s_regs.mxcsr);
    }
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_run_code() {
        use libc::c_void;

        use super::*;
        use crate::ioctls::system::Mshv;
        use std::io::Write;

        let mshv = Mshv::new().unwrap();
        let vm = mshv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        // This example is based on https://lwn.net/Articles/658511/
        #[rustfmt::skip]
        let code:[u8;11] = [
            0xba, 0xf8, 0x03,  /* mov $0x3f8, %dx */
            0x00, 0xd8,         /* add %bl, %al */
            0x04, b'0',         /* add $'0', %al */
            0xee,               /* out %al, (%dx) */
            /* send a 0 to indicate we're done */
            0xb0, b'\0',        /* mov $'\0', %al */
            0xee,               /* out %al, (%dx) */
        ];

        let mem_size = 0x4000;
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
            guest_pfn: 0x1,
            size: 0x1000,
            userspace_addr: load_addr as u64,
        };

        vm.map_user_memory(mem_region).unwrap();

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        //Get CS Register
        let mut cs_reg = hv_register_assoc {
            name: hv_register_name_HV_X64_REGISTER_CS,
            ..Default::default()
        };
        vcpu.get_reg(slice::from_mut(&mut cs_reg)).unwrap();

        unsafe {
            assert_ne!({ cs_reg.value.segment.base }, 0);
            assert_ne!({ cs_reg.value.segment.selector }, 0);
        };

        cs_reg.value.segment.base = 0;
        cs_reg.value.segment.selector = 0;

        vcpu.set_reg(&[
            cs_reg,
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RAX,
                value: hv_register_value { reg64: 2 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RBX,
                value: hv_register_value { reg64: 2 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RIP,
                value: hv_register_value { reg64: 0x1000 },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RFLAGS,
                value: hv_register_value { reg64: 0x2 },
                ..Default::default()
            },
        ])
        .unwrap();

        let hv_message: hv_message = unsafe { std::mem::zeroed() };
        let mut done = false;
        loop {
            let ret_hv_message: hv_message = vcpu.run(hv_message).unwrap();
            match ret_hv_message.header.message_type {
                hv_message_type_HVMSG_X64_HALT => {
                    println!("VM Halted!");
                    break;
                }
                hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                    let io_message = ret_hv_message.to_ioport_info().unwrap();

                    if !done {
                        assert!(io_message.rax == b'4' as u64);
                        assert!(io_message.port_number == 0x3f8);
                        unsafe {
                            assert!(io_message.access_info.__bindgen_anon_1.string_op() == 0);
                            assert!(io_message.access_info.__bindgen_anon_1.access_size() == 1);
                        }
                        assert!(
                            io_message.header.intercept_access_type == /*HV_INTERCEPT_ACCESS_WRITE*/ 1_u8
                        );
                        done = true;
                        /* Advance rip */
                        vcpu.set_reg(&[hv_register_assoc {
                            name: hv_register_name_HV_X64_REGISTER_RIP,
                            value: hv_register_value {
                                reg64: io_message.header.rip + 1,
                            },
                            ..Default::default()
                        }])
                        .unwrap();
                    } else {
                        assert!(io_message.rax == b'\0' as u64);
                        assert!(io_message.port_number == 0x3f8);
                        unsafe {
                            assert!(io_message.access_info.__bindgen_anon_1.string_op() == 0);
                            assert!(io_message.access_info.__bindgen_anon_1.access_size() == 1);
                        }
                        assert!(
                            io_message.header.intercept_access_type == /*HV_INTERCEPT_ACCESS_WRITE*/ 1_u8
                        );
                        break;
                    }
                }
                _ => {
                    println!("Message type: 0x{:x?}", {
                        ret_hv_message.header.message_type
                    });
                    panic!("Unexpected Exit Type");
                }
            };
        }
        assert!(done);
        vm.unmap_user_memory(mem_region).unwrap();
        unsafe { libc::munmap(load_addr as *mut c_void, mem_size) };
    }
    #[test]
    fn test_set_get_msrs() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = Msrs::from_entries(&[
            msr_entry {
                index: IA32_MSR_SYSENTER_CS,
                data: 0x1,
                ..Default::default()
            },
            msr_entry {
                index: IA32_MSR_SYSENTER_ESP,
                data: 0x2,
                ..Default::default()
            },
        ])
        .unwrap();
        let mut g_regs = Msrs::from_entries(&[
            msr_entry {
                index: IA32_MSR_SYSENTER_CS,
                ..Default::default()
            },
            msr_entry {
                index: IA32_MSR_SYSENTER_ESP,
                ..Default::default()
            },
        ])
        .unwrap();
        vcpu.set_msrs(&s_regs).unwrap();
        vcpu.get_msrs(&mut g_regs).unwrap();
        assert!(g_regs.as_fam_struct_ref().nmsrs == s_regs.as_fam_struct_ref().nmsrs);
        assert!(g_regs.as_slice()[0].data == s_regs.as_slice()[0].data);
        assert!(g_regs.as_slice()[1].data == s_regs.as_slice()[1].data);
    }
    #[test]
    fn test_set_get_vcpu_events() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = vcpu.get_vcpu_events().unwrap();
        vcpu.set_vcpu_events(&s_regs).unwrap();
        let g_regs = vcpu.get_vcpu_events().unwrap();
        assert!(g_regs.pending_interruption == s_regs.pending_interruption);
        assert!(g_regs.interrupt_state == s_regs.interrupt_state);
        assert!(g_regs.internal_activity_state == s_regs.internal_activity_state);
        for i in 0..16 {
            assert!(g_regs.pending_event0[i] == s_regs.pending_event0[i]);
            assert!(g_regs.pending_event1[i] == s_regs.pending_event1[i]);
        }
    }
    #[test]
    fn test_set_get_xcrs() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = vcpu.get_xcrs().unwrap();
        vcpu.set_xcrs(&s_regs).unwrap();
        let g_regs = vcpu.get_xcrs().unwrap();
        assert!(g_regs.xcr0 == s_regs.xcr0);
    }
    #[test]
    fn test_set_get_lapic() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let state = vcpu.get_lapic().unwrap();
        vcpu.set_lapic(&state).unwrap();
        let g_state = vcpu.get_lapic().unwrap();
        for i in 0..1024 {
            assert!(state.regs[i] == g_state.regs[i]);
        }
    }
    #[test]
    fn test_set_registers_64() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let arr_reg_name_value = [
            (hv_register_name_HV_X64_REGISTER_RIP, 0x1000),
            (hv_register_name_HV_X64_REGISTER_RFLAGS, 0x2),
        ];
        set_registers_64!(vcpu, &arr_reg_name_value).unwrap();
        let mut get_regs: [hv_register_assoc; 2] = [
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RIP,
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_X64_REGISTER_RFLAGS,
                ..Default::default()
            },
        ];

        vcpu.get_reg(&mut get_regs).unwrap();

        unsafe {
            /* use returned regs */
            assert!(get_regs[0].value.reg64 == 0x1000);
            assert!(get_regs[1].value.reg64 == 0x2);
        }
    }
    #[test]
    fn test_get_set_xsave() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let state = vcpu.get_xsave().unwrap();

        vcpu.set_xsave(&state).unwrap();
    }
    #[test]
    fn test_get_suspend_regs() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let regs = vcpu.get_suspend_regs().unwrap();
        // Verify the returned values
        assert!(regs.explicit_register == 0x1);
        assert!(regs.intercept_register == 0x0);
    }
    #[test]
    fn test_set_get_misc_regs() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = vcpu.get_misc_regs().unwrap();
        vcpu.set_misc_regs(&s_regs).unwrap();
        let g_regs = vcpu.get_misc_regs().unwrap();
        assert!(g_regs.hypercall == s_regs.hypercall);
    }
    #[test]
    fn test_get_cpuid_values() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let res = vcpu.get_cpuid_values(0, 0).unwrap();
        let max_function = res[0];
        assert!(max_function >= 1);
    }
}
