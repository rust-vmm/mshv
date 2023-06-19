// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
#![allow(dead_code)]
use zerocopy::{AsBytes, FromBytes};

pub const HV_CPUID_FUNCTION_VERSION_AND_FEATURES: u32 = 0x00000001;
pub const HV_CPUID_FUNCTION_HV_VENDOR_AND_MAX_FUNCTION: u32 = 0x40000000;
pub const HV_CPUID_FUNCTION_HV_INTERFACE: u32 = 0x40000001;
pub const HV_CPUID_FUNCTION_MS_HV_VERSION: u32 = 0x40000002;
pub const HV_CPUID_FUNCTION_MS_HV_FEATURES: u32 = 0x40000003;
pub const HV_CPUID_FUNCTION_MS_HV_ENLIGHTENMENT_INFORMATION: u32 = 0x40000004;
pub const HV_CPUID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS: u32 = 0x40000005;
pub const HV_CPUID_FUNCTION_MS_HV_HARDWARE_FEATURES: u32 = 0x40000006;

pub const HV_PARTITION_PRIVILEGE_ACCESS_VP_RUNTIME_MSR: u64 = 0x0000000000000001;
pub const HV_PARTITION_PRIVILEGE_PARTITION_REFERENCE_COUNTER: u64 = 0x0000000000000002;
pub const HV_PARTITION_PRIVILEGE_SYNIC_MSRS: u64 = 0x0000000000000004;
pub const HV_PARTITION_PRIVILEGE_ACCESS_SYNTHETIC_TIMER_MSRS: u64 = 0x0000000000000008;
pub const HV_PARTITION_PRIVILEGE_ACCESS_APIC_MSRS: u64 = 0x0000000000000010;
pub const HV_PARTITION_PRIVILEGE_ACCESS_HYPERCALL_MSRS: u64 = 0x0000000000000020;
pub const HV_PARTITION_PRIVILEGE_ACCESS_VP_INDEX: u64 = 0x0000000000000040;
pub const HV_PARTITION_PRIVILEGE_ACCESS_RESET_MSR: u64 = 0x0000000000000080;
pub const HV_PARTITION_PRIVILEGE_ACCESS_STATS_MSR: u64 = 0x0000000000000100;
pub const HV_PARTITION_PRIVILEGE_ACCESS_PARTITION_REFERENCE_TSC: u64 = 0x0000000000000200;
pub const HV_PARTITION_PRIVILEGE_ACCESS_GUEST_IDLE_MSR: u64 = 0x0000000000000400;
pub const HV_PARTITION_PRIVILEGE_ACCESS_FREQUENCY_MSRS: u64 = 0x0000000000000800;
pub const HV_PARTITION_PRIVILEGE_ACCESS_DEBUG_MSRS: u64 = 0x0000000000001000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_REENLIGHTENMENT_CTRLS: u64 = 0x0000000000002000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_ROOT_SCHEDULER_MSR: u64 = 0x0000000000004000;

pub const HV_PARTITION_PRIVILEGE_CREATE_PARTITIONS: u64 = 0x0000000100000000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_PARTITION_ID: u64 = 0x0000000200000000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_MEMORY_POOL: u64 = 0x0000000400000000;
pub const HV_PARTITION_PRIVILEGE_ADJUST_MESSAGE_BUFFERS: u64 = 0x0000000800000000;
pub const HV_PARTITION_PRIVILEGE_POST_MESSAGES: u64 = 0x0000001000000000;
pub const HV_PARTITION_PRIVILEGE_SIGNAL_EVENTS: u64 = 0x0000002000000000;
pub const HV_PARTITION_PRIVILEGE_CREATE_PORT: u64 = 0x0000004000000000;
pub const HV_PARTITION_PRIVILEGE_CONNECT_PORT: u64 = 0x0000008000000000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_STATS: u64 = 0x0000010000000000;
pub const HV_PARTITION_PRIVILEGE_DEBUGGING: u64 = 0x0000080000000000;
pub const HV_PARTITION_PRIVILEGE_CPU_MANAGEMENT: u64 = 0x0000100000000000;
pub const HV_PARTITION_PRIVILEGE_CONFIGURE_PROFILER: u64 = 0x0000200000000000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_VP_EXIT_TRACING: u64 = 0x0000400000000000;
pub const HV_PARTITION_PRIVILEGE_ENABLE_EXTENDED_GVA_RANGES_FLUSH_VA_LIST: u64 = 0x0000800000000000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_VSM: u64 = 0x0001000000000000;
pub const HV_PARTITION_PRIVILEGE_ACCESS_VP_REGISTERS: u64 = 0x0002000000000000;
pub const HV_PARTITION_PRIVILEGE_FAST_HYPERCALL_OUTPUT: u64 = 0x0008000000000000;
pub const HV_PARTITION_PRIVILEGE_ENABLE_EXTENDED_HYPERCALLS: u64 = 0x0010000000000000;
pub const HV_PARTITION_PRIVILEGE_START_VIRTUAL_PROCESSOR: u64 = 0x0020000000000000;
pub const HV_PARTITION_PRIVILEGE_ISOLATION: u64 = 0x0040000000000000;

pub const HV_FEATURE_MWAIT_AVAILABLE_DEPRECATED: u32 = 1 << 0;
pub const HV_FEATURE_GUEST_DEBUGGING_AVAILABLE: u32 = 1 << 1;
pub const HV_FEATURE_PERFORMANCE_MONITORS_AVAILABLE: u32 = 1 << 2;
pub const HV_FEATURE_CPU_DYNAMIC_PARTITIONING_AVAILABLE: u32 = 1 << 3;
pub const HV_FEATURE_XMM_REGISTERS_FOR_FAST_HYPERCALL_AVAILABLE: u32 = 1 << 4;
pub const HV_FEATURE_GUEST_IDLE_AVAILABLE: u32 = 1 << 5;
pub const HV_FEATURE_HYPERVISOR_SLEEP_STATE_SUPPORT_AVAILABLE: u32 = 1 << 6;
pub const HV_FEATURE_NUMA_DISTANCE_QUERY_AVAILABLE: u32 = 1 << 7;
pub const HV_FEATURE_FREQUENCY_REGS_AVAILABLE: u32 = 1 << 8;
pub const HV_FEATURE_SYNTHETIC_MACHINE_CHECK_AVAILABLE: u32 = 1 << 9;
pub const HV_FEATURE_GUEST_CRASH_REGS_AVAILABLE: u32 = 1 << 10;
pub const HV_FEATURE_DEBUG_REGS_AVAILABLE: u32 = 1 << 11;
pub const HV_FEATURE_NPIEP1_AVAILABLE: u32 = 1 << 12;
pub const HV_FEATURE_DISABLE_HYPERVISOR_AVAILABLE: u32 = 1 << 13;
pub const HV_FEATURE_EXTENDED_GVA_RANGES_FOR_FLUSH_VIRTUAL_ADDRESS_LIST_AVAILABLE: u32 = 1 << 14;
pub const HV_FEATURE_FAST_HYPERCALL_OUTPUT_AVAILABLE: u32 = 1 << 15;
pub const HV_FEATURE_SVM_FEATURES_AVAILABLE: u32 = 1 << 16;
pub const HV_FEATURE_SINT_POLLING_MODE_AVAILABLE: u32 = 1 << 17;
pub const HV_FEATURE_HYPERCALL_MSR_LOCK_AVAILABLE: u32 = 1 << 18;
pub const HV_FEATURE_DIRECT_SYNTHETIC_TIMERS: u32 = 1 << 19;
pub const HV_FEATURE_REGISTER_PAT_AVAILABLE: u32 = 1 << 20;
pub const HV_FEATURE_REGISTER_BNDCFGS_AVAILABLE: u32 = 1 << 21;
pub const HV_FEATURE_WATCHDOG_TIMER_AVAILABLE: u32 = 1 << 22;
pub const HV_FEATURE_SYNTHETIC_TIME_UNHALTED_TIMER_AVAILABLE: u32 = 1 << 23;
pub const HV_FEATURE_DEVICE_DOMAINS_AVAILABLE: u32 = 1 << 24; // HDK only.
pub const HV_FEATURE_S1_DEVICE_DOMAINS_AVAILABLE: u32 = 1 << 25; // HDK only.
pub const HV_FEATURE_LBR_AVAILABLE: u32 = 1 << 26;
pub const HV_FEATURE_IPT_AVAILABLE: u32 = 1 << 27;
pub const HV_FEATURE_CROSS_VTL_FLUSH_AVAILABLE: u32 = 1 << 28;

pub const HV_ENLIGHTENMENT_USE_HYPERCALL_FOR_ADDRESS_SPACE_SWITCH: u32 = 1 << 0;
pub const HV_ENLIGHTENMENT_USE_HYPERCALL_FOR_LOCAL_FLUSH: u32 = 1 << 1;
pub const HV_ENLIGHTENMENT_USE_HYPERCALL_FOR_REMOTE_FLUSH_AND_LOCAL_FLUSH_ENTIRE: u32 = 1 << 2;
pub const HV_ENLIGHTENMENT_USE_APIC_MSRS: u32 = 1 << 3;
pub const HV_ENLIGHTENMENT_USE_HV_REGISTER_FOR_RESET: u32 = 1 << 4;
pub const HV_ENLIGHTENMENT_USE_RELAXED_TIMING: u32 = 1 << 5;
pub const HV_ENLIGHTENMENT_USE_DMA_REMAPPING_DEPRECATED: u32 = 1 << 6;
pub const HV_ENLIGHTENMENT_USE_INTERRUPT_REMAPPING_DEPRECATED: u32 = 1 << 7;
pub const HV_ENLIGHTENMENT_USE_X2_APIC_MSRS: u32 = 1 << 8;
pub const HV_ENLIGHTENMENT_DEPRECATE_AUTO_EOI: u32 = 1 << 9;
pub const HV_ENLIGHTENMENT_USE_SYNTHETIC_CLUSTER_IPI: u32 = 1 << 10;
pub const HV_ENLIGHTENMENT_USE_EX_PROCESSOR_MASKS: u32 = 1 << 11;
pub const HV_ENLIGHTENMENT_NESTED: u32 = 1 << 12;
pub const HV_ENLIGHTENMENT_USE_INT_FOR_MBEC_SYSTEM_CALLS: u32 = 1 << 13;
pub const HV_ENLIGHTENMENT_USE_VMCS_ENLIGHTENMENTS: u32 = 1 << 14;
pub const HV_ENLIGHTENMENT_USE_SYNCED_TIMELINE: u32 = 1 << 15;
pub const HV_ENLIGHTENMENT_CORE_SCHEDULER_REQUESTED: u32 = 1 << 16;
pub const HV_ENLIGHTENMENT_USE_DIRECT_LOCAL_FLUSH_ENTIRE: u32 = 1 << 17;
pub const HV_ENLIGHTENMENT_NO_NON_ARCHITECTURAL_CORE_SHARING: u32 = 1 << 18;
pub const HV_ENLIGHTENMENT_RESERVED: u32 = 13 << 19;

pub const HV_CALL_POST_MESSAGE: u64 = 0x005c;
pub const HV_CALL_SIGNAL_EVENT: u64 = 0x005d;
pub const HV_CALL_RETARGET_DEVICE_INTERRUPT: u64 = 0x007e;

pub const MSR_HYPERCALL_ACTIVE: u64 = 1;
pub const MSR_HYPERCALL_LOCKED: u64 = 2;
pub const MSR_HYPERCALL_ADDR_MASK: u64 = !0xfff;

pub const MSR_SIEFP_SIMP_ACTIVE: u64 = 1;
pub const MSR_SIEFP_SIMP_ADDR_MASK: u64 = !0xfff;

#[derive(Debug)]
#[repr(u16)]
pub enum HvError {
    InvalidHypercallCode = 0x0002,
    InvalidHypercallInput = 0x0003,
    InvalidAlignment = 0x0004,
    InvalidParameter = 0x0005,
    AccessDenied = 0x0006,
    InvalidPartitionState = 0x0007,
    OperationDenied = 0x0008,
    UnknownProperty = 0x0009,
    PropertyValueOutOfRange = 0x000A,
    InsufficientMemory = 0x000B,
    PartitionTooDeep = 0x000C,
    InvalidPartitionId = 0x000D,
    InvalidVpIndex = 0x000E,
    NotFound = 0x0010,
    InvalidPortId = 0x0011,
    InvalidConnectionId = 0x0012,
    InsufficientBuffers = 0x0013,
    NotAcknowledged = 0x0014,
    InvalidVpState = 0x0015,
    Acknowledged = 0x0016,
    InvalidSaveRestoreState = 0x0017,
    InvalidSynicState = 0x0018,
    ObjectInUse = 0x0019,
    InvalidProximityDomainInfo = 0x001A,
    NoData = 0x001B,
    Inactive = 0x001C,
    NoResources = 0x001D,
    FeatureUnavailable = 0x001E,
    PartialPacket = 0x001F,
    ProcessorFeatureNotSupported = 0x0020,
    ProcessorCacheLineFlushSizeIncompatible = 0x0030,
    InsufficientBuffer = 0x0033,
    IncompatibleProcessor = 0x0037,
    InsufficientDeviceDomains = 0x0038,
    CpuidFeatureValidationError = 0x003C,
    CpuidXsaveFeatureValidationError = 0x003D,
    ProcessorStartupTimeout = 0x003E,
    SmxEnabled = 0x003F,
    InvalidLpIndex = 0x0041,
    InvalidRegisterValue = 0x0050,
    InvalidVtlState = 0x0051,
    NxNotDetected = 0x0055,
    InvalidDeviceId = 0x0057,
    InvalidDeviceState = 0x0058,
    PendingPageRequests = 0x0059,
    PageRequestInvalid = 0x0060,
    KeyAlreadyExists = 0x0065,
    DeviceAlreadyInDomain = 0x0066,
    InvalidCpuGroupId = 0x006F,
    InvalidCpuGroupState = 0x0070,
    OperationFailed = 0x0071,
    NotAllowedWithNestedVirtActive = 0x0072,
    InsufficientRootMemory = 0x0073,
    EventBufferAlreadyFreed = 0x0074,
}

pub type HvResult<T> = Result<T, HvError>;

#[repr(C)]
#[derive(Copy, Clone, AsBytes, Debug, FromBytes)]
pub struct HvMessageHeader {
    pub typ: u32,
    pub len: u8,
    pub flags: u8,
    pub rsvd: u16,
    pub id: u64,
}

pub const MESSAGE_TYPE_TIMER_EXPIRED: u32 = 0x80000010;

#[repr(C)]
#[derive(Copy, Clone, AsBytes, Debug, FromBytes)]
pub struct HvMessage {
    pub header: HvMessageHeader,
    pub payload: [[u8; 24]; 10],
}

#[repr(C)]
#[derive(Copy, Clone, AsBytes, Debug, FromBytes)]
pub struct TimerMessagePayload {
    pub timer_index: u32,
    pub reserved: u32,
    pub expiration_time: u64,
    pub delivery_time: u64,
}
