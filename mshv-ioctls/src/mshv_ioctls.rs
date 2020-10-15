// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use mshv_bindings::*;
ioctl_iowr_nr!(MSHV_GET_VP_REGISTERS, MSHV_IOCTL, 0x05, mshv_vp_registers);
ioctl_iow_nr!(MSHV_SET_VP_REGISTERS, MSHV_IOCTL, 0x06, mshv_vp_registers);
ioctl_ior_nr!(MSHV_RUN_VP, MSHV_IOCTL, 0x07, hv_message);
ioctl_iowr_nr!(MSHV_GET_VP_STATE, MSHV_IOCTL, 0x0A, mshv_vp_state);
ioctl_iowr_nr!(MSHV_SET_VP_STATE, MSHV_IOCTL, 0x0B, mshv_vp_state);
