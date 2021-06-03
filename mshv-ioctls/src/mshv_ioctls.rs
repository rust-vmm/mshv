// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use mshv_bindings::*;
ioctl_iow_nr!(MSHV_CHECK_EXTENSION, MSHV_IOCTL, 0x00, u32);
ioctl_iow_nr!(MSHV_CREATE_VP, MSHV_IOCTL, 0x04, mshv_create_vp);
ioctl_iowr_nr!(MSHV_GET_VP_REGISTERS, MSHV_IOCTL, 0x05, mshv_vp_registers);
ioctl_iow_nr!(MSHV_SET_VP_REGISTERS, MSHV_IOCTL, 0x06, mshv_vp_registers);
ioctl_ior_nr!(MSHV_RUN_VP, MSHV_IOCTL, 0x07, hv_message);
ioctl_iowr_nr!(MSHV_GET_VP_STATE, MSHV_IOCTL, 0x0A, mshv_vp_state);
ioctl_iowr_nr!(MSHV_SET_VP_STATE, MSHV_IOCTL, 0x0B, mshv_vp_state);
ioctl_iow_nr!(
    MSHV_CREATE_PARTITION,
    MSHV_IOCTL,
    0x01,
    mshv_create_partition
);
ioctl_iow_nr!(
    HV_SET_PARTITION_PROPERTY,
    MSHV_IOCTL,
    0x0C,
    mshv_partition_property
);
ioctl_iowr_nr!(
    HV_GET_PARTITION_PROPERTY,
    MSHV_IOCTL,
    0x0D,
    mshv_partition_property
);
ioctl_iow_nr!(MSHV_IRQFD, MSHV_IOCTL, 0x0E, mshv_irqfd);
ioctl_iow_nr!(MSHV_IOEVENTFD, MSHV_IOCTL, 0xF, mshv_ioeventfd);
ioctl_iow_nr!(MSHV_SET_MSI_ROUTING, MSHV_IOCTL, 0x11, mshv_msi_routing);
ioctl_iow_nr!(
    MSHV_MAP_GUEST_MEMORY,
    MSHV_IOCTL,
    0x02,
    mshv_user_mem_region
);
ioctl_iow_nr!(
    MSHV_UNMAP_GUEST_MEMORY,
    MSHV_IOCTL,
    0x03,
    mshv_user_mem_region
);
ioctl_iow_nr!(
    MSHV_INSTALL_INTERCEPT,
    MSHV_IOCTL,
    0x08,
    mshv_install_intercept
);
ioctl_iow_nr!(
    MSHV_ASSERT_INTERRUPT,
    MSHV_IOCTL,
    0x09,
    mshv_assert_interrupt
);
ioctl_iowr_nr!(
    MSHV_VP_TRANSLATE_GVA,
    MSHV_IOCTL,
    0x0E,
    mshv_vp_translate_gva
);
