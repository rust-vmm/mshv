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
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

// Macro for setting up multiple 64 bit registers together
// Arguments:
///             1. vcpud fd
///             2. Array of Tuples of Register name and reguster value Example [(n1, v1), (n2,v2) ....]
///
#[allow(unused_macros)]
#[macro_export]
macro_rules! set_registers_64 {
    ($vcpu:expr, $arr_t:expr ) => {{
        let len = $arr_t.len();
        // Initialize with zero which is itself a enum value(HV_REGISTER_EXPLICIT_SUSPEND = 0).
        // This value does not have any effect as this is being overwritten anyway.
        let mut names: Vec<hv_register_name> =
            vec![hv_register_name::HV_REGISTER_EXPLICIT_SUSPEND; len];
        let mut values: Vec<hv_register_value> = vec![hv_register_value { reg64: 0 }; len];
        for (i, x) in $arr_t.iter().enumerate() {
            let (a, b) = x;
            names[i] = *a;
            values[i] = hv_register_value { reg64: *b };
        }
        #[allow(unused_parens)]
        $vcpu.set_reg(&names, &values)
    }};
}

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
    ///
    /// Get the register values by providing an array of register names
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_reg(&self, reg_names: &[hv_register_name]) -> Result<Vec<hv_register_value>> {
        //TODO: Error if input register len is zero
        let mut reg_values: Vec<hv_register_value> =
            vec![hv_register_value::default(); reg_names.len()];
        let mut mshv_vp_register_args = mshv_vp_registers {
            count: reg_names.len() as i32,
            values: reg_values.as_mut_ptr(),
            names: reg_names.as_ptr() as *mut hv_register_name,
        };
        // Safe because we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe {
            ioctl_with_mut_ref(self, MSHV_GET_VP_REGISTERS(), &mut mshv_vp_register_args)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(reg_values)
    }
    ///
    /// Sets a vCPU register to input value.
    ///
    /// # Arguments
    ///
    /// * `reg_name` - general purpose register name.
    /// * `reg_value` - register value.
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_reg(
        &self,
        reg_names: &[hv_register_name],
        reg_values: &[hv_register_value],
    ) -> Result<()> {
        if reg_names.len() != reg_values.len() {
            return Err(errno::Error::new(libc::EINVAL));
        }
        let hv_vp_register_args = mshv_vp_registers {
            count: reg_names.len() as i32,
            values: reg_values.as_ptr() as *mut hv_register_value,
            names: reg_names.as_ptr() as *mut hv_register_name,
        };
        let ret = unsafe { ioctl_with_ref(self, MSHV_SET_VP_REGISTERS(), &hv_vp_register_args) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
    ///
    /// Sets the vCPU general purpose registers
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_regs(&self, regs: &StandardRegisters) -> Result<()> {
        let reg_names = [
            hv_register_name::HV_X64_REGISTER_RAX,
            hv_register_name::HV_X64_REGISTER_RBX,
            hv_register_name::HV_X64_REGISTER_RCX,
            hv_register_name::HV_X64_REGISTER_RDX,
            hv_register_name::HV_X64_REGISTER_RSI,
            hv_register_name::HV_X64_REGISTER_RDI,
            hv_register_name::HV_X64_REGISTER_RSP,
            hv_register_name::HV_X64_REGISTER_RBP,
            hv_register_name::HV_X64_REGISTER_R8,
            hv_register_name::HV_X64_REGISTER_R9,
            hv_register_name::HV_X64_REGISTER_R10,
            hv_register_name::HV_X64_REGISTER_R11,
            hv_register_name::HV_X64_REGISTER_R12,
            hv_register_name::HV_X64_REGISTER_R13,
            hv_register_name::HV_X64_REGISTER_R14,
            hv_register_name::HV_X64_REGISTER_R15,
            hv_register_name::HV_X64_REGISTER_RIP,
            hv_register_name::HV_X64_REGISTER_RFLAGS,
        ];
        let reg_values = [
            hv_register_value { reg64: regs.rax },
            hv_register_value { reg64: regs.rbx },
            hv_register_value { reg64: regs.rcx },
            hv_register_value { reg64: regs.rdx },
            hv_register_value { reg64: regs.rsi },
            hv_register_value { reg64: regs.rdi },
            hv_register_value { reg64: regs.rsp },
            hv_register_value { reg64: regs.rbp },
            hv_register_value { reg64: regs.r8 },
            hv_register_value { reg64: regs.r9 },
            hv_register_value { reg64: regs.r10 },
            hv_register_value { reg64: regs.r11 },
            hv_register_value { reg64: regs.r12 },
            hv_register_value { reg64: regs.r13 },
            hv_register_value { reg64: regs.r14 },
            hv_register_value { reg64: regs.r15 },
            hv_register_value { reg64: regs.rip },
            hv_register_value { reg64: regs.rflags },
        ];
        self.set_reg(&reg_names, &reg_values)?;
        Ok(())
    }

    ///
    /// Returns the vCPU general purpose registers.
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_regs(&self) -> Result<StandardRegisters> {
        let reg_names: [hv_register_name; 18] = [
            hv_register_name::HV_X64_REGISTER_RAX,
            hv_register_name::HV_X64_REGISTER_RBX,
            hv_register_name::HV_X64_REGISTER_RCX,
            hv_register_name::HV_X64_REGISTER_RDX,
            hv_register_name::HV_X64_REGISTER_RSI,
            hv_register_name::HV_X64_REGISTER_RDI,
            hv_register_name::HV_X64_REGISTER_RSP,
            hv_register_name::HV_X64_REGISTER_RBP,
            hv_register_name::HV_X64_REGISTER_R8,
            hv_register_name::HV_X64_REGISTER_R9,
            hv_register_name::HV_X64_REGISTER_R10,
            hv_register_name::HV_X64_REGISTER_R11,
            hv_register_name::HV_X64_REGISTER_R12,
            hv_register_name::HV_X64_REGISTER_R13,
            hv_register_name::HV_X64_REGISTER_R14,
            hv_register_name::HV_X64_REGISTER_R15,
            hv_register_name::HV_X64_REGISTER_RIP,
            hv_register_name::HV_X64_REGISTER_RFLAGS,
        ];
        let reg_values = self.get_reg(&reg_names)?;
        let mut ret_regs = StandardRegisters::default();
        unsafe {
            ret_regs.rax = reg_values[0].reg64;
            ret_regs.rbx = reg_values[1].reg64;
            ret_regs.rcx = reg_values[2].reg64;
            ret_regs.rdx = reg_values[3].reg64;
            ret_regs.rsi = reg_values[4].reg64;
            ret_regs.rdi = reg_values[5].reg64;
            ret_regs.rsp = reg_values[6].reg64;
            ret_regs.rbp = reg_values[7].reg64;
            ret_regs.r8 = reg_values[8].reg64;
            ret_regs.r9 = reg_values[9].reg64;
            ret_regs.r10 = reg_values[10].reg64;
            ret_regs.r11 = reg_values[11].reg64;
            ret_regs.r12 = reg_values[12].reg64;
            ret_regs.r13 = reg_values[13].reg64;
            ret_regs.r14 = reg_values[14].reg64;
            ret_regs.r15 = reg_values[15].reg64;
            ret_regs.rip = reg_values[16].reg64;
            ret_regs.rflags = reg_values[17].reg64;
        }

        Ok(ret_regs)
    }
    ///
    /// Returns the vCPU special registers.
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_sregs(&self) -> Result<SpecialRegisters> {
        let reg_names: [hv_register_name; 18] = [
            hv_register_name::HV_X64_REGISTER_CS,
            hv_register_name::HV_X64_REGISTER_DS,
            hv_register_name::HV_X64_REGISTER_ES,
            hv_register_name::HV_X64_REGISTER_FS,
            hv_register_name::HV_X64_REGISTER_GS,
            hv_register_name::HV_X64_REGISTER_SS,
            hv_register_name::HV_X64_REGISTER_TR,
            hv_register_name::HV_X64_REGISTER_LDTR,
            hv_register_name::HV_X64_REGISTER_GDTR,
            hv_register_name::HV_X64_REGISTER_IDTR,
            hv_register_name::HV_X64_REGISTER_CR0,
            hv_register_name::HV_X64_REGISTER_CR2,
            hv_register_name::HV_X64_REGISTER_CR3,
            hv_register_name::HV_X64_REGISTER_CR4,
            hv_register_name::HV_X64_REGISTER_CR8,
            hv_register_name::HV_X64_REGISTER_EFER,
            hv_register_name::HV_X64_REGISTER_APIC_BASE,
            hv_register_name::HV_REGISTER_PENDING_INTERRUPTION,
        ];
        let reg_values = self.get_reg(&reg_names)?;
        let mut ret_regs = SpecialRegisters::default();
        unsafe {
            ret_regs.cs = SegmentRegister::from(reg_values[0].segment);
            ret_regs.ds = SegmentRegister::from(reg_values[1].segment);
            ret_regs.es = SegmentRegister::from(reg_values[2].segment);
            ret_regs.fs = SegmentRegister::from(reg_values[3].segment);
            ret_regs.gs = SegmentRegister::from(reg_values[4].segment);
            ret_regs.ss = SegmentRegister::from(reg_values[5].segment);
            ret_regs.tr = SegmentRegister::from(reg_values[6].segment);
            ret_regs.ldt = TableRegister::from(reg_values[7].table);
            ret_regs.gdt = TableRegister::from(reg_values[8].table);
            ret_regs.idt = TableRegister::from(reg_values[9].table);
            ret_regs.cr0 = reg_values[10].reg64;
            ret_regs.cr2 = reg_values[11].reg64;
            ret_regs.cr3 = reg_values[12].reg64;
            ret_regs.cr4 = reg_values[13].reg64;
            ret_regs.cr8 = reg_values[14].reg64;
            ret_regs.efer = reg_values[15].reg64;
            ret_regs.apic_base = reg_values[16].reg64;
            let pending_reg = reg_values[17].pending_interruption.as_uint64;
            if (pending_reg & 0x1) == 1 && // interruption pending
                    ((pending_reg >> 1) & 0x7) == 0
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
    ///
    /// Sets the vCPU special registers
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<()> {
        let reg_names: [hv_register_name; 17] = [
            hv_register_name::HV_X64_REGISTER_CS,
            hv_register_name::HV_X64_REGISTER_DS,
            hv_register_name::HV_X64_REGISTER_ES,
            hv_register_name::HV_X64_REGISTER_FS,
            hv_register_name::HV_X64_REGISTER_GS,
            hv_register_name::HV_X64_REGISTER_SS,
            hv_register_name::HV_X64_REGISTER_TR,
            hv_register_name::HV_X64_REGISTER_LDTR,
            hv_register_name::HV_X64_REGISTER_GDTR,
            hv_register_name::HV_X64_REGISTER_IDTR,
            hv_register_name::HV_X64_REGISTER_CR0,
            hv_register_name::HV_X64_REGISTER_CR2,
            hv_register_name::HV_X64_REGISTER_CR3,
            hv_register_name::HV_X64_REGISTER_CR4,
            hv_register_name::HV_X64_REGISTER_CR8,
            hv_register_name::HV_X64_REGISTER_EFER,
            hv_register_name::HV_X64_REGISTER_APIC_BASE,
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
                table: sregs.ldt.into(),
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

        self.set_reg(&reg_names, &reg_values)?;

        Ok(())
    }
    ///
    /// Sets the vCPU floating point registers
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_fpu(&self, fpu: &FloatingPointUnit) -> Result<()> {
        let reg_names: [hv_register_name; 26] = [
            hv_register_name::HV_X64_REGISTER_XMM0,
            hv_register_name::HV_X64_REGISTER_XMM1,
            hv_register_name::HV_X64_REGISTER_XMM2,
            hv_register_name::HV_X64_REGISTER_XMM3,
            hv_register_name::HV_X64_REGISTER_XMM4,
            hv_register_name::HV_X64_REGISTER_XMM5,
            hv_register_name::HV_X64_REGISTER_XMM6,
            hv_register_name::HV_X64_REGISTER_XMM7,
            hv_register_name::HV_X64_REGISTER_XMM8,
            hv_register_name::HV_X64_REGISTER_XMM9,
            hv_register_name::HV_X64_REGISTER_XMM10,
            hv_register_name::HV_X64_REGISTER_XMM11,
            hv_register_name::HV_X64_REGISTER_XMM12,
            hv_register_name::HV_X64_REGISTER_XMM13,
            hv_register_name::HV_X64_REGISTER_XMM14,
            hv_register_name::HV_X64_REGISTER_XMM15,
            hv_register_name::HV_X64_REGISTER_FP_MMX0,
            hv_register_name::HV_X64_REGISTER_FP_MMX1,
            hv_register_name::HV_X64_REGISTER_FP_MMX2,
            hv_register_name::HV_X64_REGISTER_FP_MMX3,
            hv_register_name::HV_X64_REGISTER_FP_MMX4,
            hv_register_name::HV_X64_REGISTER_FP_MMX5,
            hv_register_name::HV_X64_REGISTER_FP_MMX6,
            hv_register_name::HV_X64_REGISTER_FP_MMX7,
            hv_register_name::HV_X64_REGISTER_FP_CONTROL_STATUS,
            hv_register_name::HV_X64_REGISTER_XMM_CONTROL_STATUS,
        ];
        let mut reg_values: [hv_register_value; 26] = [hv_register_value { reg64: 0 }; 26];
        for i in 0..16 {
            unsafe {
                reg_values[i] = hv_register_value {
                    reg128: std::mem::transmute::<[u8; 16usize], hv_u128>(fpu.xmm[i]),
                };
            }
        }
        for i in 16..24 {
            let fp_i = i - 16;
            unsafe {
                reg_values[i] = hv_register_value {
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

        self.set_reg(&reg_names, &reg_values)?;
        Ok(())
    }
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_fpu(&self) -> Result<FloatingPointUnit> {
        let reg_names: [hv_register_name; 26] = [
            hv_register_name::HV_X64_REGISTER_XMM0,
            hv_register_name::HV_X64_REGISTER_XMM1,
            hv_register_name::HV_X64_REGISTER_XMM2,
            hv_register_name::HV_X64_REGISTER_XMM3,
            hv_register_name::HV_X64_REGISTER_XMM4,
            hv_register_name::HV_X64_REGISTER_XMM5,
            hv_register_name::HV_X64_REGISTER_XMM6,
            hv_register_name::HV_X64_REGISTER_XMM7,
            hv_register_name::HV_X64_REGISTER_XMM8,
            hv_register_name::HV_X64_REGISTER_XMM9,
            hv_register_name::HV_X64_REGISTER_XMM10,
            hv_register_name::HV_X64_REGISTER_XMM11,
            hv_register_name::HV_X64_REGISTER_XMM12,
            hv_register_name::HV_X64_REGISTER_XMM13,
            hv_register_name::HV_X64_REGISTER_XMM14,
            hv_register_name::HV_X64_REGISTER_XMM15,
            hv_register_name::HV_X64_REGISTER_FP_MMX0,
            hv_register_name::HV_X64_REGISTER_FP_MMX1,
            hv_register_name::HV_X64_REGISTER_FP_MMX2,
            hv_register_name::HV_X64_REGISTER_FP_MMX3,
            hv_register_name::HV_X64_REGISTER_FP_MMX4,
            hv_register_name::HV_X64_REGISTER_FP_MMX5,
            hv_register_name::HV_X64_REGISTER_FP_MMX6,
            hv_register_name::HV_X64_REGISTER_FP_MMX7,
            hv_register_name::HV_X64_REGISTER_FP_CONTROL_STATUS,
            hv_register_name::HV_X64_REGISTER_XMM_CONTROL_STATUS,
        ];
        let reg_values = self.get_reg(&reg_names)?;

        let fp_control_status: hv_x64_fp_control_status_register__bindgen_ty_1 =
            unsafe { reg_values[24].fp_control_status.__bindgen_anon_1 };
        let xmm_control_status: hv_x64_xmm_control_status_register__bindgen_ty_1 =
            unsafe { reg_values[25].xmm_control_status.__bindgen_anon_1 };
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

        for i in 0..16 {
            unsafe {
                ret_regs.xmm[i] =
                    std::mem::transmute::<hv_u128, [u8; 16usize]>(reg_values[i].reg128);
            }
        }
        for i in 0..8 {
            unsafe {
                ret_regs.fpr[i] =
                    std::mem::transmute::<hv_u128, [u8; 16usize]>(reg_values[i].fp.as_uint128);
            }
        }

        Ok(ret_regs)
    }
    ///
    /// X86 specific call that returns the vcpu's current "debug registers".
    ///
    pub fn get_debug_regs(&self) -> Result<DebugRegisters> {
        let reg_names: [hv_register_name; 6] = [
            hv_register_name::HV_X64_REGISTER_DR0,
            hv_register_name::HV_X64_REGISTER_DR1,
            hv_register_name::HV_X64_REGISTER_DR2,
            hv_register_name::HV_X64_REGISTER_DR3,
            hv_register_name::HV_X64_REGISTER_DR6,
            hv_register_name::HV_X64_REGISTER_DR7,
        ];
        let reg_values = self.get_reg(&reg_names)?;

        let ret_regs = unsafe {
            DebugRegisters {
                Dr0: reg_values[0].reg64,
                Dr1: reg_values[1].reg64,
                Dr2: reg_values[2].reg64,
                Dr3: reg_values[3].reg64,
                Dr6: reg_values[4].reg64,
                Dr7: reg_values[5].reg64,
            }
        };

        Ok(ret_regs)
    }
    ///
    /// X86 specific call that sets the vcpu's current "debug registers".
    ///
    pub fn set_debug_regs(&self, d_regs: &DebugRegisters) -> Result<()> {
        let reg_names = [
            hv_register_name::HV_X64_REGISTER_DR0,
            hv_register_name::HV_X64_REGISTER_DR1,
            hv_register_name::HV_X64_REGISTER_DR2,
            hv_register_name::HV_X64_REGISTER_DR3,
            hv_register_name::HV_X64_REGISTER_DR6,
            hv_register_name::HV_X64_REGISTER_DR7,
        ];
        let reg_values = [
            hv_register_value { reg64: d_regs.Dr0 },
            hv_register_value { reg64: d_regs.Dr1 },
            hv_register_value { reg64: d_regs.Dr2 },
            hv_register_value { reg64: d_regs.Dr3 },
            hv_register_value { reg64: d_regs.Dr6 },
            hv_register_value { reg64: d_regs.Dr7 },
        ];
        self.set_reg(&reg_names, &reg_values)?;

        Ok(())
    }
    ///
    /// Returns the machine-specific registers (MSR) for this vCPU.
    ///
    pub fn get_msrs(&self, msrs: &mut Msrs) -> Result<usize> {
        let nmsrs = msrs.as_fam_struct_ref().nmsrs as usize;
        let mut reg_names: Vec<hv_register_name> = Vec::with_capacity(nmsrs);

        for i in 0..nmsrs {
            reg_names.push(msr_to_hv_reg_name(msrs.as_slice()[i].index).unwrap());
        }

        let reg_values = self.get_reg(&reg_names)?;

        unsafe {
            for i in 0..nmsrs {
                msrs.as_mut_slice()[i].data = reg_values[i].reg64;
            }
        }

        Ok(nmsrs)
    }
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    pub fn set_msrs(&self, msrs: &Msrs) -> Result<usize> {
        let nmsrs = msrs.as_fam_struct_ref().nmsrs as usize;
        let mut reg_names: Vec<hv_register_name> = Vec::with_capacity(nmsrs);
        let mut reg_values: Vec<hv_register_value> = Vec::with_capacity(nmsrs);

        for i in 0..nmsrs {
            reg_names.push(msr_to_hv_reg_name(msrs.as_slice()[i].index).unwrap());
            reg_values.push(hv_register_value {
                reg64: msrs.as_slice()[i].data,
            });
        }

        self.set_reg(&reg_names, &reg_values)?;
        Ok(0 as usize)
    }
    ///
    ///  Triggers the running of the current virtual CPU returning an exit reason.
    ///
    pub fn run(&self, mut hv_message_input: hv_message) -> Result<hv_message> {
        // Safe because we know that our file is a vCPU fd and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, MSHV_RUN_VP(), &mut hv_message_input) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(hv_message_input)
    }
    ///
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    pub fn get_vcpu_events(&self) -> Result<VcpuEvents> {
        let reg_names: [hv_register_name; 5] = [
            hv_register_name::HV_REGISTER_PENDING_INTERRUPTION,
            hv_register_name::HV_REGISTER_INTERRUPT_STATE,
            hv_register_name::HV_REGISTER_INTERNAL_ACTIVITY_STATE,
            hv_register_name::HV_REGISTER_PENDING_EVENT0,
            hv_register_name::HV_REGISTER_PENDING_EVENT1,
        ];
        let reg_values = self.get_reg(&reg_names)?;
        let mut ret_regs = VcpuEvents::default();
        unsafe {
            ret_regs.pending_interruption = reg_values[0].reg64;
            ret_regs.interrupt_state = reg_values[1].reg64;
            ret_regs.internal_activity_state = reg_values[2].reg64;
            ret_regs.pending_event0 =
                std::mem::transmute::<hv_u128, [u8; 16usize]>(reg_values[3].reg128);
            ret_regs.pending_event1 =
                std::mem::transmute::<hv_u128, [u8; 16usize]>(reg_values[4].reg128);
        }
        Ok(ret_regs)
    }
    ///
    /// Sets pending exceptions, interrupts, and NMIs as well as related states of the vcpu.
    ///
    pub fn set_vcpu_events(&self, events: &VcpuEvents) -> Result<()> {
        let reg_names: [hv_register_name; 4] = [
            hv_register_name::HV_REGISTER_PENDING_INTERRUPTION,
            hv_register_name::HV_REGISTER_INTERRUPT_STATE,
            /*hv_register_name::HV_REGISTER_internal_activity_state,*/ // Not allowed
            hv_register_name::HV_REGISTER_PENDING_EVENT0,
            hv_register_name::HV_REGISTER_PENDING_EVENT1,
        ];
        let reg_values: [hv_register_value; 4] = unsafe {
            [
                hv_register_value {
                    reg64: events.pending_interruption,
                },
                hv_register_value {
                    reg64: events.interrupt_state,
                }, /*
                   hv_register_value {
                       reg64: d_regs.internal_activity_state,
                   },*/
                hv_register_value {
                    reg128: std::mem::transmute::<[u8; 16usize], hv_u128>(events.pending_event0),
                },
                hv_register_value {
                    reg128: std::mem::transmute::<[u8; 16usize], hv_u128>(events.pending_event1),
                },
            ]
        };
        self.set_reg(&reg_names, &reg_values)?;

        Ok(())
    }
    ///
    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    pub fn get_xcrs(&self) -> Result<Xcrs> {
        let reg_names: [hv_register_name; 1] = [hv_register_name::HV_X64_REGISTER_XFEM];
        let reg_values = self.get_reg(&reg_names)?;

        let ret_regs = unsafe {
            Xcrs {
                xcr0: reg_values[0].reg64,
            }
        };

        Ok(ret_regs)
    }
    pub fn set_xcrs(&self, xcrs: &Xcrs) -> Result<()> {
        self.set_reg(
            &[hv_register_name::HV_X64_REGISTER_XFEM],
            &[hv_register_value { reg64: xcrs.xcr0 }],
        )
    }
    ///
    /// Returns the VCpu state. This IOCTLs can be used to get XSave and LAPIC state.
    ///
    pub fn get_vp_state_ioctl(&self, state: &mshv_vp_state) -> Result<()> {
        // Safe because we know that our file is a vCPU fd and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, MSHV_GET_VP_STATE(), state) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    pub fn get_lapic_ioctl(&self) -> Result<hv_local_interrupt_controller_state> {
        let mut vp_state: mshv_vp_state = mshv_vp_state::default();
        vp_state.type_ =
            hv_get_set_vp_state_type_HV_GET_SET_VP_STATE_LOCAL_INTERRUPT_CONTROLLER_STATE;
        // Safe because we know that our file is a vCPU fd and we verify the return result.
        self.get_vp_state_ioctl(&vp_state).unwrap();
        let state: hv_local_interrupt_controller_state = unsafe { *vp_state.buf.lapic };
        Ok(state)
    }
    ///
    /// Set vp states (LAPIC, XSave etc)
    /// Test code already covered by get/set_lapic/xsave
    ///
    pub fn set_vp_state_ioctl(&self, state: &mshv_vp_state) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, MSHV_SET_VP_STATE(), state) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
    ///
    /// Get the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    pub fn get_lapic(&self) -> Result<LapicState> {
        let state = LapicState::default();
        let vp_state: mshv_vp_state = mshv_vp_state::from(state);
        self.get_vp_state_ioctl(&vp_state)?;
        Ok(LapicState::from(vp_state))
    }
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    pub fn set_lapic(&self, lapic_state: &LapicState) -> Result<()> {
        let vp_state: mshv_vp_state = mshv_vp_state::from(*lapic_state);
        self.set_vp_state_ioctl(&vp_state)
    }
    ///
    /// Returns the xsave data
    ///
    pub fn get_xsave(&self) -> Result<XSave> {
        let layout = std::alloc::Layout::from_size_align(0x1000, 0x1000).unwrap();
        let buf = unsafe { std::alloc::alloc(layout) };
        if buf.is_null() {
            return Err(errno::Error::new(libc::ENOMEM));
        }
        let mut vp_state: mshv_vp_state = mshv_vp_state::default();
        vp_state.buf.bytes = buf;
        vp_state.buf_size = 4096;
        vp_state.type_ = hv_get_set_vp_state_type_HV_GET_SET_VP_STATE_XSAVE;
        self.get_vp_state_ioctl(&vp_state).unwrap();
        println!("Size: {}", vp_state.buf_size);
        let ret = XSave::from(vp_state);
        unsafe {
            std::alloc::dealloc(buf, layout);
        }
        Ok(ret)
    }
    ///
    /// Set the xsave data
    ///
    pub fn set_xsave(&self, data: XSave) -> Result<()> {
        let mut vp_state: mshv_vp_state = mshv_vp_state::from(data);
        let layout = std::alloc::Layout::from_size_align(0x1000, 0x1000).unwrap();
        let buf = unsafe { std::alloc::alloc(layout) };
        if buf.is_null() {
            return Err(errno::Error::new(libc::ENOMEM));
        }
        let min: usize = cmp::min(4096, data.data_size as u32) as usize;
        unsafe { ptr::copy(data.data_buffer.as_ptr() as *mut u8, buf, min) };
        vp_state.buf_size = 4096;
        vp_state.buf.bytes = buf;
        let ret = self.set_vp_state_ioctl(&vp_state);
        unsafe {
            std::alloc::dealloc(buf, layout);
        }
        ret
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

        vcpu.set_reg(
            &[
                hv_register_name::HV_X64_REGISTER_RIP,
                hv_register_name::HV_X64_REGISTER_RFLAGS,
            ],
            &[
                hv_register_value { reg64: 0x1000 },
                hv_register_value { reg64: 0x2 },
            ],
        )
        .unwrap();

        let get_reg_names: [hv_register_name; 2] = [
            hv_register_name::HV_X64_REGISTER_RIP,
            hv_register_name::HV_X64_REGISTER_RFLAGS,
        ];

        let reg_values = vcpu.get_reg(&get_reg_names).unwrap();

        unsafe {
            /* use returned regs */
            assert!(reg_values[0].reg64 == 0x1000);
            assert!(reg_values[1].reg64 == 0x2);
            /* index into original array */
            assert!(reg_values[0].reg64 == 0x1000);
            assert!(reg_values[1].reg64 == 0x2);
            /* access raw pointer as array */
            assert!(reg_values[0].reg64 == 0x1000);
            assert!(reg_values[1].reg64 == 0x2);
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
    // fn test_set_get_standardregisters() {
    //     let hv = Mshv::new().unwrap();
    //     let vm = hv.create_vm().unwrap();
    //     let vcpu = vm.create_vcpu(0).unwrap();

    //     let s_regs = vcpu.get_regs().unwrap();
    //     vcpu.set_regs(&s_regs).unwrap();
    //     let g_regs = vcpu.get_regs().unwrap();
    //     assert!(g_regs.rax == s_regs.rax);
    //     assert!(g_regs.rbx == s_regs.rbx);
    //     assert!(g_regs.rcx == s_regs.rcx);
    //     assert!(g_regs.rdx == s_regs.rdx);
    // }
    #[test]
    fn test_set_get_debug_gisters() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let s_regs = vcpu.get_debug_regs().unwrap();
        vcpu.set_debug_regs(&s_regs).unwrap();
        let g_regs = vcpu.get_debug_regs().unwrap();
        assert!(g_regs.Dr0 == s_regs.Dr0);
        assert!(g_regs.Dr1 == s_regs.Dr1);
        assert!(g_regs.Dr2 == s_regs.Dr2);
        assert!(g_regs.Dr3 == s_regs.Dr3);
        assert!(g_regs.Dr6 == s_regs.Dr6);
        assert!(g_regs.Dr7 == s_regs.Dr7);
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
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        //Get CS Register
        let mut cs_reg_value = vcpu
            .get_reg(&[hv_register_name::HV_X64_REGISTER_CS])
            .unwrap()[0];
        unsafe {
            assert_ne!(cs_reg_value.segment.base, 0);
            assert_ne!(cs_reg_value.segment.selector, 0);
        };

        cs_reg_value.segment.base = 0;
        cs_reg_value.segment.selector = 0;

        let _regs = vcpu
            .set_reg(
                &[
                    hv_register_name::HV_X64_REGISTER_CS,
                    hv_register_name::HV_X64_REGISTER_RAX,
                    hv_register_name::HV_X64_REGISTER_RBX,
                    hv_register_name::HV_X64_REGISTER_RIP,
                    hv_register_name::HV_X64_REGISTER_RFLAGS,
                ],
                &[
                    //unsafe because union element is accessed
                    hv_register_value {
                        segment: unsafe { cs_reg_value.segment },
                    },
                    hv_register_value { reg64: 2 },
                    hv_register_value { reg64: 2 },
                    hv_register_value { reg64: 0x1000 },
                    hv_register_value { reg64: 0x2 },
                ],
            )
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
                    let io_message = ret_hv_message.to_ioport_info();

                    if !done {
                        assert!(io_message.rax == b'4' as u64);
                        assert!(io_message.port_number == 0x3f8);
                        unsafe {
                            assert!(io_message.access_info.__bindgen_anon_1.string_op() == 0);
                            assert!(io_message.access_info.__bindgen_anon_1.access_size() == 1);
                        }
                        assert!(
                            io_message.header.intercept_access_type == /*HV_INTERCEPT_ACCESS_WRITE*/ 1 as u8
                        );
                        done = true;
                        /* Advance rip */
                        vcpu.set_reg(
                            &[hv_register_name::HV_X64_REGISTER_RIP],
                            &[hv_register_value {
                                reg64: io_message.header.rip + 1,
                            }],
                        )
                        .unwrap();
                    } else {
                        assert!(io_message.rax == b'\0' as u64);
                        assert!(io_message.port_number == 0x3f8);
                        unsafe {
                            assert!(io_message.access_info.__bindgen_anon_1.string_op() == 0);
                            assert!(io_message.access_info.__bindgen_anon_1.access_size() == 1);
                        }
                        assert!(
                            io_message.header.intercept_access_type == /*HV_INTERCEPT_ACCESS_WRITE*/ 1 as u8
                        );
                        break;
                    }
                }
                _ => {
                    panic!("Unexpected Exit Type");
                }
            };
        }
        assert!(done);
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
        ]);
        let mut g_regs = Msrs::from_entries(&[
            msr_entry {
                index: IA32_MSR_SYSENTER_CS,
                ..Default::default()
            },
            msr_entry {
                index: IA32_MSR_SYSENTER_ESP,
                ..Default::default()
            },
        ]);
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
    fn test_set_get_lapic_ioctl() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut vp_state: mshv_vp_state = mshv_vp_state::default();
        let state: LapicState = LapicState::default();
        vp_state.type_ =
            hv_get_set_vp_state_type_HV_GET_SET_VP_STATE_LOCAL_INTERRUPT_CONTROLLER_STATE;
        vp_state.buf.bytes = state.regs.as_ptr() as *mut u8;
        vp_state.buf_size = 1024;
        vcpu.get_vp_state_ioctl(&vp_state).unwrap();
        vcpu.set_vp_state_ioctl(&vp_state).unwrap();
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
            (hv_register_name::HV_X64_REGISTER_RIP, 0x1000),
            (hv_register_name::HV_X64_REGISTER_RFLAGS, 0x2),
        ];
        set_registers_64!(vcpu, &arr_reg_name_value).unwrap();
        let get_reg_names: [hv_register_name; 2] = [
            hv_register_name::HV_X64_REGISTER_RIP,
            hv_register_name::HV_X64_REGISTER_RFLAGS,
        ];

        let reg_values = vcpu.get_reg(&get_reg_names).unwrap();

        unsafe {
            /* use returned regs */
            assert!(reg_values[0].reg64 == 0x1000);
            assert!(reg_values[1].reg64 == 0x2);
        }
    }
    #[test]
    fn test_get_set_xsave() {
        let hv = Mshv::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let state = vcpu.get_xsave().unwrap();
        vcpu.set_xsave(state).unwrap();
    }
}
