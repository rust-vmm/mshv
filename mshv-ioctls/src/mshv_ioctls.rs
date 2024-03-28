// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
#![allow(missing_docs)]

use mshv_bindings::*;
ioctl_iow_nr!(MSHV_CREATE_VP, MSHV_IOCTL, 0x04, mshv_create_vp);
ioctl_iowr_nr!(MSHV_GET_VP_REGISTERS, MSHV_IOCTL, 0x05, mshv_vp_registers);
ioctl_iow_nr!(MSHV_SET_VP_REGISTERS, MSHV_IOCTL, 0x06, mshv_vp_registers);
ioctl_ior_nr!(MSHV_RUN_VP, MSHV_IOCTL, 0x07, hv_message);
ioctl_iowr_nr!(MSHV_GET_VP_STATE, MSHV_IOCTL, 0x0A, mshv_get_set_vp_state);
ioctl_iowr_nr!(MSHV_SET_VP_STATE, MSHV_IOCTL, 0x0B, mshv_get_set_vp_state);
ioctl_iow_nr!(
    MSHV_CREATE_PARTITION,
    MSHV_IOCTL,
    0x01,
    mshv_create_partition
);
ioctl_iow_nr!(
    MSHV_SET_PARTITION_PROPERTY,
    MSHV_IOCTL,
    0x0C,
    mshv_partition_property
);
ioctl_iowr_nr!(
    MSHV_GET_PARTITION_PROPERTY,
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
ioctl_iowr_nr!(MSHV_VP_TRANSLATE_GVA, MSHV_IOCTL, 0x0E, mshv_translate_gva);
ioctl_iowr_nr!(
    MSHV_GET_GPA_ACCESS_STATES,
    MSHV_IOCTL,
    0x12,
    mshv_get_gpa_pages_access_state
);

ioctl_iowr_nr!(MSHV_CREATE_DEVICE, MSHV_IOCTL, 0x13, mshv_create_device);
ioctl_iow_nr!(MSHV_SET_DEVICE_ATTR, MSHV_IOCTL, 0x14, mshv_device_attr);
ioctl_iow_nr!(MSHV_GET_DEVICE_ATTR, MSHV_IOCTL, 0x15, mshv_device_attr);
ioctl_iow_nr!(MSHV_HAS_DEVICE_ATTR, MSHV_IOCTL, 0x16, mshv_device_attr);

ioctl_iow_nr!(
    MSHV_VP_REGISTER_INTERCEPT_RESULT,
    MSHV_IOCTL,
    0x17,
    mshv_register_intercept_result
);

ioctl_iowr_nr!(
    MSHV_SIGNAL_EVENT_DIRECT,
    MSHV_IOCTL,
    0x18,
    mshv_signal_event_direct
);
ioctl_iow_nr!(
    MSHV_POST_MESSAGE_DIRECT,
    MSHV_IOCTL,
    0x19,
    mshv_post_message_direct
);
ioctl_iow_nr!(
    MSHV_REGISTER_DELIVERABILITY_NOTIFICATIONS,
    MSHV_IOCTL,
    0x1A,
    mshv_register_deliverabilty_notifications
);
ioctl_iowr_nr!(
    MSHV_GET_VP_CPUID_VALUES,
    MSHV_IOCTL,
    0x1B,
    mshv_get_vp_cpuid_values
);
ioctl_iow_nr!(
    MSHV_MODIFY_GPA_HOST_ACCESS,
    MSHV_IOCTL,
    0x28,
    mshv_modify_gpa_host_access
);
ioctl_iow_nr!(
    MSHV_IMPORT_ISOLATED_PAGES,
    MSHV_IOCTL,
    0x29,
    mshv_import_isolated_pages
);
ioctl_iow_nr!(
    MSHV_COMPLETE_ISOLATED_IMPORT,
    MSHV_IOCTL,
    0x30,
    mshv_complete_isolated_import
);
ioctl_iow_nr!(
    MSHV_ISSUE_PSP_GUEST_REQUEST,
    MSHV_IOCTL,
    0x31,
    mshv_issue_psp_guest_request
);
ioctl_iowr_nr!(MSHV_READ_GPA, MSHV_IOCTL, 0x32, mshv_read_write_gpa);
ioctl_iow_nr!(MSHV_WRITE_GPA, MSHV_IOCTL, 0x33, mshv_read_write_gpa);
ioctl_iow_nr!(
    MSHV_SEV_SNP_AP_CREATE,
    MSHV_IOCTL,
    0x34,
    mshv_sev_snp_ap_create
);
