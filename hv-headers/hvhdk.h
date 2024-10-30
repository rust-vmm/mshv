/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Type definitions for the hypervisor host interface.
 */
#ifndef _HVHDK_H
#define _HVHDK_H

#include "hvhdk_mini.h"
#include "hvgdk.h"

#define HVHDK_H_VERSION			(25212)

/* Bits for dirty mask of hv_vp_register_page */
#define HV_X64_REGISTER_CLASS_GENERAL		0
#define HV_X64_REGISTER_CLASS_IP		1
#define HV_X64_REGISTER_CLASS_XMM		2
#define HV_X64_REGISTER_CLASS_SEGMENT		3
#define HV_X64_REGISTER_CLASS_FLAGS		4

#define HV_VP_REGISTER_PAGE_VERSION_1		1u

#define HV_VP_REGISTER_PAGE_MAX_VECTOR_COUNT	7

union hv_vp_register_page_interrupt_vectors {
	__u64 as_uint64;
	struct {
		__u8 vector_count;
		__u8 vector[HV_VP_REGISTER_PAGE_MAX_VECTOR_COUNT];
	} __packed;
} __packed;

struct hv_vp_register_page {
	__u16 version;
	__u8 isvalid;
	__u8 rsvdz;
	__u32 dirty;

#if defined(__x86_64__)

	union {
		struct {
			/* General purpose registers
			 * (HV_X64_REGISTER_CLASS_GENERAL)
			 */
			union {
				struct {
					__u64 rax;
					__u64 rcx;
					__u64 rdx;
					__u64 rbx;
					__u64 rsp;
					__u64 rbp;
					__u64 rsi;
					__u64 rdi;
					__u64 r8;
					__u64 r9;
					__u64 r10;
					__u64 r11;
					__u64 r12;
					__u64 r13;
					__u64 r14;
					__u64 r15;
				} __packed;

				__u64 gp_registers[16];
			};
			/* Instruction pointer (HV_X64_REGISTER_CLASS_IP) */
			__u64 rip;
			/* Flags (HV_X64_REGISTER_CLASS_FLAGS) */
			__u64 rflags;
		} __packed;

		__u64 registers[18];
	};
	__u8 reserved[8];
	/* Volatile XMM registers (HV_X64_REGISTER_CLASS_XMM) */
	union {
		struct {
			struct hv_u128 xmm0;
			struct hv_u128 xmm1;
			struct hv_u128 xmm2;
			struct hv_u128 xmm3;
			struct hv_u128 xmm4;
			struct hv_u128 xmm5;
		} __packed;

		struct hv_u128 xmm_registers[6];
	};
	/* Segment registers (HV_X64_REGISTER_CLASS_SEGMENT) */
	union {
		struct {
			struct hv_x64_segment_register es;
			struct hv_x64_segment_register cs;
			struct hv_x64_segment_register ss;
			struct hv_x64_segment_register ds;
			struct hv_x64_segment_register fs;
			struct hv_x64_segment_register gs;
		} __packed;

		struct hv_x64_segment_register segment_registers[6];
	};
	/* Misc. control registers (cannot be set via this interface) */
	__u64 cr0;
	__u64 cr3;
	__u64 cr4;
	__u64 cr8;
	__u64 efer;
	__u64 dr7;
	union hv_x64_pending_interruption_register pending_interruption;
	union hv_x64_interrupt_state_register interrupt_state;
	__u64 instruction_emulation_hints;
	__u64 xfem;

	/*
	 * Fields from this point are not included in the register page save chunk.
	 * The reserved field is intended to maintain alignment for unsaved fields.
	 */
	__u8 reserved1[0x100];

	/*
	 * Interrupts injected as part of HvCallDispatchVp.
	 */
	union hv_vp_register_page_interrupt_vectors interrupt_vectors;

#elif defined(__aarch64__)
	/* Not yet supported in ARM */
#endif

} __packed;

#define HV_PARTITION_SYNTHETIC_PROCESSOR_FEATURES_BANKS 1

union hv_partition_synthetic_processor_features {
	__u64 as_uint64[HV_PARTITION_SYNTHETIC_PROCESSOR_FEATURES_BANKS];

	struct {
		/* Report a hypervisor is present. CPUID leaves
		 * 0x40000000 and 0x40000001 are supported.
		 */
		__u64 hypervisor_present:1;

		/*
		 * Features associated with HV#1:
		 */

		/* Report support for Hv1 (CPUID leaves 0x40000000 - 0x40000006). */
		__u64 hv1:1;

		/* Access to HV_X64_MSR_VP_RUNTIME.
		 * Corresponds to access_vp_run_time_reg privilege.
		 */
		__u64 access_vp_run_time_reg:1;

		/* Access to HV_X64_MSR_TIME_REF_COUNT.
		 * Corresponds to access_partition_reference_counter privilege.
		 */
		__u64 access_partition_reference_counter:1;

		/* Access to SINT-related registers (HV_X64_MSR_SCONTROL through
		 * HV_X64_MSR_EOM and HV_X64_MSR_SINT0 through HV_X64_MSR_SINT15).
		 * Corresponds to access_synic_regs privilege.
		 */
		__u64 access_synic_regs:1;

		/* Access to synthetic timers and associated MSRs
		 * (HV_X64_MSR_STIMER0_CONFIG through HV_X64_MSR_STIMER3_COUNT).
		 * Corresponds to access_synthetic_timer_regs privilege.
		 */
		__u64 access_synthetic_timer_regs:1;

		/* Access to APIC MSRs (HV_X64_MSR_EOI, HV_X64_MSR_ICR and HV_X64_MSR_TPR)
		 * as well as the VP assist page.
		 * Corresponds to access_intr_ctrl_regs privilege.
		 */
		__u64 access_intr_ctrl_regs:1;

		/* Access to registers associated with hypercalls (HV_X64_MSR_GUEST_OS_ID
		 * and HV_X64_MSR_HYPERCALL).
		 * Corresponds to access_hypercall_msrs privilege.
		 */
		__u64 access_hypercall_regs:1;

		/* VP index can be queried. corresponds to access_vp_index privilege. */
		__u64 access_vp_index:1;

		/* Access to the reference TSC. Corresponds to access_partition_reference_tsc
		 * privilege.
		 */
		__u64 access_partition_reference_tsc:1;

#if defined(__x86_64__)

		/* Partition has access to the guest idle reg. Corresponds to
		 * access_guest_idle_reg privilege.
		 */
		__u64 access_guest_idle_reg:1;
#else
		__u64 reserved_z10:1;
#endif

		/* Partition has access to frequency regs. corresponds to access_frequency_regs
		 * privilege.
		 */
		__u64 access_frequency_regs:1;

		__u64 reserved_z12:1; /* Reserved for access_reenlightenment_controls. */
		__u64 reserved_z13:1; /* Reserved for access_root_scheduler_reg. */
		__u64 reserved_z14:1; /* Reserved for access_tsc_invariant_controls. */

#if defined(__x86_64__)

		/* Extended GVA ranges for HvCallFlushVirtualAddressList hypercall.
		 * Corresponds to privilege.
		 */
		__u64 enable_extended_gva_ranges_for_flush_virtual_address_list:1;
#else
		__u64 reserved_z15:1;
#endif

		__u64 reserved_z16:1; /* Reserved for access_vsm. */
		__u64 reserved_z17:1; /* Reserved for access_vp_registers. */

		/* Use fast hypercall output. Corresponds to privilege. */
		__u64 fast_hypercall_output:1;

		__u64 reserved_z19:1; /* Reserved for enable_extended_hypercalls. */

		/*
		 * HvStartVirtualProcessor can be used to start virtual processors.
		 * Corresponds to privilege.
		 */
		__u64 start_virtual_processor:1;

		__u64 reserved_z21:1; /* Reserved for Isolation. */

		/* Synthetic timers in direct mode. */
		__u64 direct_synthetic_timers:1;

		__u64 reserved_z23:1; /* Reserved for synthetic time unhalted timer */

		/* Use extended processor masks. */
		__u64 extended_processor_masks:1;

		/* HvCallFlushVirtualAddressSpace / HvCallFlushVirtualAddressList are supported. */
		__u64 tb_flush_hypercalls:1;

		/* HvCallSendSyntheticClusterIpi is supported. */
		__u64 synthetic_cluster_ipi:1;

		/* HvCallNotifyLongSpinWait is supported. */
		__u64 notify_long_spin_wait:1;

		/* HvCallQueryNumaDistance is supported. */
		__u64 query_numa_distance:1;

		/* HvCallSignalEvent is supported. Corresponds to privilege. */
		__u64 signal_events:1;

		/* HvCallRetargetDeviceInterrupt is supported. */
		__u64 retarget_device_interrupt:1;

#if defined(__x86_64__)
		/* HvCallRestorePartitionTime is supported. */
		__u64 restore_time:1;

		/* EnlightenedVmcs nested enlightenment is supported. */
		__u64 enlightened_vmcs:1;
#else
		__u64 reserved_z31:1;
		__u64 reserved_z32:1;
#endif

		__u64 reserved:30;
	} __packed;
};

/*
 * Definition of the partition isolation state. Used for
 * HV_PARTITION_PROPERTY_ISOLATION_STATE.
 *
 *
 * The isolation states (hv_partition_isolation_state) are sub-states of
 * ObPartitionActive that apply to VBS and hardware isolated partitions.
 * For VBS isolation, the trusted host VTL 1 component uses the isolation
 * state to establish a binding between a hypervisor partition and its
 * own partition context, and to enforce certain invariants.
 *
 * Hardware-isolated partitions (including partitions that simulate
 * hardware isolation) also use isolation states to track the progression
 * of the partition security state through the architectural state machine.
 * Insecure states indicate that there is no architectural state
 * associated with the partition, and Secure indicates that the partition
 * has secure architectural state.
 *
 * ObPartitionRestoring is treated differently for isolated partitions.
 * Only the trusted host component is allowed to restore partition state,
 * and ObPartitionRestoring can only transition directly to/from secure.
 *
 *
 * ..................................................................
 * .         UNINITIALIZED     FINALIZED                            .
 * .               |           ^       ^                            .
 * .    Initialize |          /         \                           .
 * .               |         /           \                          .
 * . --------------|--------/--- ACTIVE --\------------------------ .
 * . |             |       /               \                      | .
 * . |             |      / Finalize        \ Finalize            | .
 * . |             v     /                   \                    | .
 * . |       INSECURE-CLEAN <---------------- INSECURE-DIRTY      | .
 * . |                   \        Scrub      ^                    | .
 * . |                    \                 /                     | .
 * . |                     \               /                      | .
 * . |               Secure \             / Unsecure              | .
 * . |                       \           /                        | .
 * . |                        \         /                         | .
 * . |                         v       /                          | .
 * . |                           SECURE                           | .
 * . |                             ^                              | .
 * . |_____________________________|______________________________| .
 * .                               |                                .
 * .                               v                                .
 * .                           RESTORING                            .
 * ..................................................................
 */
enum hv_partition_isolation_state {
	/*
	 * Initial and final state for all non-isolated partitions.
	 */
	HV_PARTITION_ISOLATION_INVALID		   = 0,

	/*
	 * An "Insecure" partition is not being used by the trusted host
	 * component. In this state, VPs can be created and deleted. VPs cannot
	 * be started, and VP registers cannot be modified.

	 * Initial state of an isolated partition as result of Initialize or
	 * Scrub hypercalls. Guest-visible partition and VP state is considered
	 * "clean", in the sense that a call to ObScrubPartition should not
	 * result in any changes. Also, there are no accepted or confidential
	 * pages assigned to the partition. InsecureRundown is enabled.
	 */
	HV_PARTITION_ISOLATION_INSECURE_CLEAN	    = 1,

	/*
	 * Guest-visible partition and VP state is not "clean". Hence it must
	 * be scrubbed first. One of 2 explicit states the trusted host
	 * component can request. It cannot transition the state to Secure. In
	 * this state,
	 *  - IsolationControl is clear.
	 *  - Secure rundowns are completely disabled.
	 *  - No assigned pages exist.
	 */
	HV_PARTITION_ISOLATION_INSECURE_DIRTY	    = 2,

	/*
	 * The partition is being used by the trusted host component (and is
	 * typically bound to a single partition context in that component).
	 * One of 2 explicit states the trusted host component can request. In
	 * this state,
	 *  - VPs cannot be created or deleted.
	 *  - Partition cannot be finalized, scrubbed.
	 *  - Insecure rundowns are completely disabled.
	 */
	HV_PARTITION_ISOLATION_SECURE		   = 3,

	/*
	 * Represents a failed attempt to transition to Secure state. Partition
	 * in this state cannot be finalized, scrubbed since one or more pages
	 * may be assigned.
	 */
	HV_PARTITION_ISOLATION_SECURE_DIRTY	    = 4,

	/*
	 * An internal state indicating that a partition is in the process of
	 * transitioning from Secure to InsecureDirty.
	 */
	HV_PARTITION_ISOLATION_SECURE_TERMINATING   = 5,
};

union hv_partition_isolation_properties {
	__u64 as_uint64;
	struct {
		__u64 isolation_type: 5;
		__u64 isolation_host_type : 2;
		__u64 rsvd_z: 5;
		__u64 shared_gpa_boundary_page_number: 52;
	} __packed;
};

struct hv_input_get_partition_property {
	__u64 partition_id;
	__u32 property_code; /* enum hv_partition_property_code */
	__u32 padding;
} __packed;

struct hv_output_get_partition_property {
	__u64 property_value;
} __packed;

struct hv_input_set_partition_property {
	__u64 partition_id;
	__u32 property_code; /* enum hv_partition_property_code */
	__u32 padding;
	__u64 property_value;
} __packed;

struct hv_cpuid_leaf_info {
	__u32 eax;
	__u32 ecx;
	__u64 xfem;
	__u64 xss;
} __packed;

union hv_get_vp_cpuid_values_flags {
	__u32 as_uint32;
	struct {
		__u32 use_vp_xfem_xss: 1;
		__u32 apply_registered_values: 1;
		__u32 reserved: 30;
	} __packed;
} __packed;

struct hv_input_get_vp_cpuid_values {
	__u64 partition_id;
	__u32 vp_index;
	union hv_get_vp_cpuid_values_flags flags;
	__u32 reserved;
	__u32 padding;
	struct hv_cpuid_leaf_info cpuid_leaf_info[];
} __packed;

// NOTE: Not in hvhdk headers
union hv_output_get_vp_cpuid_values {
	__u32 as_uint32[4];
	struct {
		__u32 eax;
		__u32 ebx;
		__u32 ecx;
		__u32 edx;
	} __packed;
};

/*
 * Request data read access.
 */
#define HV_TRANSLATE_GVA_VALIDATE_READ	     (0x0001)

/*
 * Request data write access.
 */
#define HV_TRANSLATE_GVA_VALIDATE_WRITE      (0x0002)

/*
 * Request instruction fetch access.
 */
#define HV_TRANSLATE_GVA_VALIDATE_EXECUTE    (0x0004)

#if defined(__x86_64__)

/*
 * Don't enforce any checks related to access mode (supervisor vs. user; SMEP and SMAP are treated
 * as disabled).
 */
#define HV_TRANSLATE_GVA_PRIVILEGE_EXEMPT    (0x0008)

#endif

#define HV_TRANSLATE_GVA_SET_PAGE_TABLE_BITS (0x0010)
#define HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT   (0x0020)

/*
 * Treat the access as a supervisor mode access irrespective of current mode.
 */
#define HV_TRANSLATE_GVA_SUPERVISOR_ACCESS   (0x0040)

/*
 * Treat the access as a user mode access irrespective of current mode.
 */
#define HV_TRANSLATE_GVA_USER_ACCESS	     (0x0080)

#if defined(__x86_64__)

/*
 * Enforce the SMAP restriction on supervisor data access to user mode addresses if CR4.SMAP=1
 * irrespective of current EFLAGS.AC i.e. the behavior for "implicit supervisor-mode accesses"
 * (e.g. to the GDT, etc.) and when EFLAGS.AC=0. Does nothing if CR4.SMAP=0.
 */
#define HV_TRANSLATE_GVA_ENFORCE_SMAP	     (0x0100)

/*
 * Don't enforce the SMAP restriction on supervisor data access to user mode addresses irrespective
 * of current EFLAGS.AC i.e. the behavior when EFLAGS.AC=1.
 */
#define HV_TRANSLATE_GVA_OVERRIDE_SMAP	     (0x0200)

/*
 * Treat the access as a shadow stack access.
 */
#define HV_TRANSLATE_GVA_SHADOW_STACK	     (0x0400)

#else

/*
 * Restrict supervisor data access to user mode addresses irrespective of current PSTATE.PAN i.e.
 * the behavior when PSTATE.PAN=1.
 */
#define HV_TRANSLATE_GVA_PAN_SET	     (0x0100)

/*
 * Don't restrict supervisor data access to user mode addresses irrespective of current PSTATE.PAN
 * i.e. the behavior when PSTATE.PAN=0.
 */
#define HV_TRANSLATE_GVA_PAN_CLEAR	     (0x0200)

#endif

#define HV_TRANSLATE_GVA_INPUT_VTL_MASK      (0xFF00000000000000UI64)

enum hv_translate_gva_result_code {
	HV_TRANSLATE_GVA_SUCCESS			= 0,

	/* Translation failures. */
	HV_TRANSLATE_GVA_PAGE_NOT_PRESENT		= 1,
	HV_TRANSLATE_GVA_PRIVILEGE_VIOLATION		= 2,
	HV_TRANSLATE_GVA_INVALIDE_PAGE_TABLE_FLAGS	= 3,

	/* GPA access failures. */
	HV_TRANSLATE_GVA_GPA_UNMAPPED			= 4,
	HV_TRANSLATE_GVA_GPA_NO_READ_ACCESS		= 5,
	HV_TRANSLATE_GVA_GPA_NO_WRITE_ACCESS		= 6,
	HV_TRANSLATE_GVA_GPA_ILLEGAL_OVERLAY_ACCESS	= 7,

	/*
	 * Intercept for memory access by either
	 *  - a higher VTL
	 *  - a nested hypervisor (due to a violation of the nested page table)
	 */
	HV_TRANSLATE_GVA_INTERCEPT			= 8,

	HV_TRANSLATE_GVA_GPA_UNACCEPTED			= 9,
};

union hv_translate_gva_result {
	__u64 as_uint64;
	struct {
		__u32 result_code; /* enum hv_translate_hva_result_code */
		__u32 cache_type : 8;
		__u32 overlay_page : 1;
		__u32 reserved : 23;
	} __packed;
};

struct hv_x64_apic_eoi_message {
	__u32 vp_index;
	__u32 interrupt_vector;
} __packed;

struct hv_opaque_intercept_message {
	__u32 vp_index;
} __packed;

enum hv_port_type {
	HV_PORT_TYPE_MESSAGE = 1,
	HV_PORT_TYPE_EVENT   = 2,
	HV_PORT_TYPE_MONITOR = 3,
	HV_PORT_TYPE_DOORBELL = 4	/* Root Partition only */
};

struct hv_port_info {
	__u32 port_type; /* enum hv_port_type */
	__u32 padding;
	union {
		struct {
			__u32 target_sint;
			__u32 target_vp;
			__u64 rsvdz;
		} message_port_info;
		struct {
			__u32 target_sint;
			__u32 target_vp;
			__u16 base_flag_number;
			__u16 flag_count;
			__u32 rsvdz;
		} event_port_info;
		struct {
			__u64 monitor_address;
			__u64 rsvdz;
		} monitor_port_info;
		struct {
			__u32 target_sint;
			__u32 target_vp;
			__u64 rsvdz;
		} doorbell_port_info;
	};
} __packed;

union hv_interrupt_control {
	__u64 as_uint64;
	struct {
		__u32 interrupt_type; /* enum hv_interrupt type */
		__u32 level_triggered : 1;
		__u32 logical_dest_mode : 1;
#if defined(__aarch64__)
		__u32 asserted : 1;
		__u32 rsvd : 29;
#else
		__u32 rsvd : 30;
#endif
	} __packed;
};

#if defined(__x86_64__)

struct hv_local_interrupt_controller_state {
	/* HV_X64_INTERRUPT_CONTROLLER_STATE */
	__u32 apic_id;
	__u32 apic_version;
	__u32 apic_ldr;
	__u32 apic_dfr;
	__u32 apic_spurious;
	__u32 apic_isr[8];
	__u32 apic_tmr[8];
	__u32 apic_irr[8];
	__u32 apic_esr;
	__u32 apic_icr_high;
	__u32 apic_icr_low;
	__u32 apic_lvt_timer;
	__u32 apic_lvt_thermal;
	__u32 apic_lvt_perfmon;
	__u32 apic_lvt_lint0;
	__u32 apic_lvt_lint1;
	__u32 apic_lvt_error;
	__u32 apic_lvt_cmci;
	__u32 apic_error_status;
	__u32 apic_initial_count;
	__u32 apic_counter_value;
	__u32 apic_divide_configuration;
	__u32 apic_remote_read;
} __packed;

#endif

struct hv_stimer_state {
	struct {
		// Indicates if there is an undelivered timer expiry message.
		__u32 undelivered_msg_pending:1;
		__u32 reserved:31;
	} __packed flags;

	__u32 resvd;

	// Timer configuration and count.
	__u64 config;
	__u64 count;

	// Timer adjustment.
	__u64 adjustment;

	// Expiration time of the undelivered message.
	__u64 undelivered_exp_time;
} __packed;

struct hv_synthetic_timers_state {
	struct hv_stimer_state timers[HV_SYNIC_STIMER_COUNT];

	// Reserved space for time unhalted timer.
	__u64 reserved[5];
} __packed;

#if defined(__x86_64__)

union hv_x64_vp_execution_state {
	__u16 as_uint16;
	struct {
		__u16 cpl:2;
		__u16 cr0_pe:1;
		__u16 cr0_am:1;
		__u16 efer_lma:1;
		__u16 debug_active:1;
		__u16 interruption_pending:1;
		__u16 vtl:4;
		__u16 enclave_mode:1;
		__u16 interrupt_shadow:1;
		__u16 virtualization_fault_active:1;
		__u16 reserved:2;
	} __packed;
};

struct hv_x64_intercept_message_header {
	__u32 vp_index;
	__u8 instruction_length:4;
	__u8 cr8:4; /* Only set for exo partitions */
	__u8 intercept_access_type;
	union hv_x64_vp_execution_state execution_state;
	struct hv_x64_segment_register cs_segment;
	__u64 rip;
	__u64 rflags;
} __packed;

#define HV_HYPERCALL_INTERCEPT_MAX_XMM_REGISTERS 6

struct hv_x64_hypercall_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u64 rax;
	__u64 rbx;
	__u64 rcx;
	__u64 rdx;
	__u64 r8;
	__u64 rsi;
	__u64 rdi;
	struct hv_u128 xmmregisters[HV_HYPERCALL_INTERCEPT_MAX_XMM_REGISTERS];
	struct {
		__u32 isolated:1;
		__u32 reserved:31;
	} __packed;
} __packed;

union hv_x64_register_access_info {
	union hv_register_value source_value;
	__u32 destination_register;
	__u64 source_address;
	__u64 destination_address;
};

#define HV_SUPPORTS_REGISTER_INTERCEPT

struct hv_x64_register_intercept_message {
	struct hv_x64_intercept_message_header header;
	struct {
		__u8 is_memory_op:1;
		__u8 reserved:7;
	} __packed;
	__u8 reserved8;
	__u16 reserved16;
	__u32 register_name;
	union hv_x64_register_access_info access_info;
} __packed;

union hv_x64_memory_access_info {
	__u8 as_uint8;
	struct {
		__u8 gva_valid:1;
		__u8 gva_gpa_valid:1;
		__u8 hypercall_output_pending:1;
		__u8 tlb_locked_no_overlay:1;
		__u8 reserved:4;
	} __packed;
};

union hv_x64_io_port_access_info {
	__u8 as_uint8;
	struct {
		__u8 access_size:3;
		__u8 string_op:1;
		__u8 rep_prefix:1;
		__u8 reserved:3;
	} __packed;
};

union hv_x64_exception_info {
	__u8 as_uint8;
	struct {
		__u8 error_code_valid:1;
		__u8 software_exception:1;
		__u8 reserved:6;
	} __packed;
};

struct hv_x64_memory_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u32 cache_type; /* enum hv_cache_type */
	__u8 instruction_byte_count;
	union hv_x64_memory_access_info memory_access_info;
	__u8 tpr_priority;
	__u8 reserved1;
	__u64 guest_virtual_address;
	__u64 guest_physical_address;
	__u8 instruction_bytes[16];
} __packed;

struct hv_x64_cpuid_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u64 rax;
	__u64 rcx;
	__u64 rdx;
	__u64 rbx;
	__u64 default_result_rax;
	__u64 default_result_rcx;
	__u64 default_result_rdx;
	__u64 default_result_rbx;
} __packed;

struct hv_x64_msr_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u32 msr_number;
	__u32 reserved;
	__u64 rdx;
	__u64 rax;
} __packed;

struct hv_x64_io_port_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u16 port_number;
	union hv_x64_io_port_access_info access_info;
	__u8 instruction_byte_count;
	__u32 reserved;
	__u64 rax;
	__u8 instruction_bytes[16];
	struct hv_x64_segment_register ds_segment;
	struct hv_x64_segment_register es_segment;
	__u64 rcx;
	__u64 rsi;
	__u64 rdi;
} __packed;

struct hv_x64_exception_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u16 exception_vector;
	union hv_x64_exception_info exception_info;
	__u8 instruction_byte_count;
	__u32 error_code;
	__u64 exception_parameter;
	__u64 reserved;
	__u8 instruction_bytes[16];
	struct hv_x64_segment_register ds_segment;
	struct hv_x64_segment_register ss_segment;
	__u64 rax;
	__u64 rcx;
	__u64 rdx;
	__u64 rbx;
	__u64 rsp;
	__u64 rbp;
	__u64 rsi;
	__u64 rdi;
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
} __packed;

struct hv_x64_invalid_vp_register_message {
	__u32 vp_index;
	__u32 reserved;
} __packed;

struct hv_x64_unrecoverable_exception_message {
	struct hv_x64_intercept_message_header header;
} __packed;

#define HV_UNSUPPORTED_FEATURE_INTERCEPT	1
#define HV_UNSUPPORTED_FEATURE_TASK_SWITCH_TSS	2

struct hv_x64_unsupported_feature_message {
	__u32 vp_index;
	__u32 feature_code;
	__u64 feature_parameter;
} __packed;

struct hv_x64_halt_message {
	struct hv_x64_intercept_message_header header;
} __packed;

#define HV_X64_PENDING_INTERRUPT	0
#define HV_X64_PENDING_NMI		2
#define HV_X64_PENDING_EXCEPTION	3

struct hv_x64_interruption_deliverable_message {
	struct hv_x64_intercept_message_header header;
	__u32 deliverable_type; /* pending interruption type */
	__u32 rsvd;
} __packed;

struct hv_x64_sint_deliverable_message {
	struct hv_x64_intercept_message_header header;
	__u16 deliverable_sints;
	__u16 rsvd1;
	__u32 rsvd2;
} __packed;

struct hv_x64_sipi_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u32 target_vp_index;
	__u32 interrupt_vector;
} __packed;

#define HV_GPA_ATTRIBUTE_INTERCEPT_MAX_RANGES 29

struct hv_x64_gpa_attribute_intercept_message {
	__u32 vp_index;
	struct {
		__u32 range_count : 5;
		__u32 adjust : 1;
		__u32 host_visibility : 2;
		__u32 memory_type : 6;
		__u32 reserved : 18;
	} __packed;
	union hv_gpa_page_range ranges[HV_GPA_ATTRIBUTE_INTERCEPT_MAX_RANGES];
} __packed;

struct hv_register_x64_cpuid_result_parameters {
	struct {
		__u32 eax;
		__u32 ecx;
		__u8 subleaf_specific;
		__u8 always_override;
		__u16 padding;
	} __packed input;
	struct {
		__u32 eax;
		__u32 eax_mask;
		__u32 ebx;
		__u32 ebx_mask;
		__u32 ecx;
		__u32 ecx_mask;
		__u32 edx;
		__u32 edx_mask;
	} __packed result;
} __packed;

struct hv_register_x64_msr_result_parameters {
	__u32 msr_index;
	__u32 access_type;
	__u32 action; /* enum hv_unimplemented_msr_action */
} __packed;

union hv_register_intercept_result_parameters {
	struct hv_register_x64_cpuid_result_parameters cpuid;
	struct hv_register_x64_msr_result_parameters msr;
} __packed;

struct hv_x64_vmgexit_intercept_message {
	struct hv_x64_intercept_message_header header;
	__u64 ghcb_msr;
	struct {
		__u64 ghcb_page_valid : 1;
		__u64 reserved : 63;
	} __packed;
	struct {
		__u32 ghcb_usage;
		__u32 rserved_ghcb_page;
		struct {
			__u16 ghcb_protocol_version;
			__u16 reserved_st[3];
			__u64 sw_exit_code;
			__u64 sw_exit_info1;
			__u64 sw_exit_info2;
			__u64 sw_scratch;
		} __packed;
	} __packed;
} __packed;

#endif /* __x86_64__ */

struct hv_input_translate_virtual_address {
	__u64 partition_id;
	__u32 vp_index;
	__u32 padding;
	__u64 control_flags;
	__u64 gva_page;
} __packed;

struct hv_output_translate_virtual_address {
	union hv_translate_gva_result translation_result;
	__u64 gpa_page;
} __packed;

#if defined(__x86_64__)

struct hv_input_register_intercept_result {
	__u64 partition_id;
	__u32 vp_index;
	__u32 intercept_type; /* enum hv_intercept_type */
	union hv_register_intercept_result_parameters parameters;
} __packed;

struct hv_input_assert_virtual_interrupt {
	__u64 partition_id;
	union hv_interrupt_control control;
	__u64 dest_addr; /* cpu's apic id */
	__u32 vector;
	__u8 target_vtl;
	__u8 rsvd_z0;
	__u16 rsvd_z1;
} __packed;

struct hv_input_signal_event_direct {
	__u64 target_partition;
	__u32 target_vp;
	__u8  target_vtl;
	__u8  target_sint;
	__u16 flag_number;
} __packed;

struct hv_output_signal_event_direct {
	__u8	newly_signaled;
	__u8	reserved[7];
} __packed;

struct hv_input_post_message_direct {
	__u64 partition_id;
	__u32 vp_index;
	__u8  vtl;
	__u8  padding[3];
	__u32 sint_index;
	__u8  message[HV_MESSAGE_SIZE];
	__u32 padding2;
} __packed;

#define HV_SUPPORTS_VP_STATE

struct hv_vp_state_data_xsave {
	__u64 flags;
	union hv_x64_xsave_xfem_register states;
} __packed;

#endif /* __x86_64__ */

struct hv_psp_cpuid_leaf {
	__u32 eax_in;
	__u32 ecx_in;
	__u64 xfem_in;
	__u64 xss_in;
	__u32 eax_out;
	__u32 ebx_out;
	__u32 ecx_out;
	__u32 edx_out;
	__u64 reserved_z;
} __packed;

#define HV_PSP_CPUID_LEAF_COUNT_MAX	64

struct hv_psp_cpuid_page {
	__u32 count;
	__u32 reserved_z1;
	__u64 reserved_z2;
	struct hv_psp_cpuid_leaf cpuid_leaf_info[HV_PSP_CPUID_LEAF_COUNT_MAX];
} __packed;

enum hv_isolated_page_type {
	HV_ISOLATED_PAGE_TYPE_NORMAL = 0,
	HV_ISOLATED_PAGE_TYPE_VMSA = 1,
	HV_ISOLATED_PAGE_TYPE_ZERO = 2,
	HV_ISOLATED_PAGE_TYPE_UNMEASURED = 3,
	HV_ISOLATED_PAGE_TYPE_SECRETS = 4,
	HV_ISOLATED_PAGE_TYPE_CPUID = 5,
	HV_ISOLATED_PAGE_TYPE_COUNT = 6
};

enum hv_isolated_page_size {
	HV_ISOLATED_PAGE_SIZE_4KB = 0,
	HV_ISOLATED_PAGE_SIZE_2MB = 1
};

struct hv_input_import_isolated_pages {
	__u64 partition_id;
	__u32 page_type; /* enum hv_isolated_page_type */
	__u32 page_size; /* enum hv_isolated_page_size */
	__u64 page_number[];
} __packed;

/*
 * Structure that declares the set of enabled offloads for VMGExit handling;
 */
union hv_sev_vmgexit_offload {
	__u64 as_uint64;
	struct {
		/*
		 * Standard format NAEs.
		 */
		__u64 nae_rdtsc : 1;
		__u64 nae_cpuid : 1;
		__u64 nae_reserved_io_port : 1;
		__u64 nae_rdmsr : 1;
		__u64 nae_wrmsr : 1;
		__u64 nae_vmmcall : 1;
		__u64 nae_wbinvd : 1;
		__u64 nae_snp_page_state_change : 1;
		__u64 reserved0 : 24;
		/*
		 * GHCB MSR protocol.
		 */
		__u64 msr_cpuid : 1;
		__u64 msr_snp_page_state_change : 1;
		__u64 reserved1 : 30;
	} __packed;
};

enum hv_access_gpa_result_code {
	HV_ACCESS_GPA_SUCCESS = 0,
	HV_ACCESS_GPA_UNMAPPED = 1,
	HV_ACCESS_GPA_READ_INTERCEPT = 2,
	HV_ACCESS_GPA_WRITE_INTERCEPT = 3,
	HV_ACCESS_GPA_ILLEGAL_OVERLAY_ACCESS = 4
};

union hv_access_gpa_result {
	__u64 as_uint64;
	struct {
		__u32 result_code; /* enum hv_access_gpa_result_code*/
		__u32 reserved;
	} __packed;
};

union hv_access_gpa_control_flags {
	__u64 as_uint64;
	struct {
	__u64 cache_type: 8; /* *enum hv_cache_type /*/
	__u64 reserved: 56;
	} __packed;
};

struct hv_input_read_gpa {
	__u64 partition_id;
	__u32 vp_index;
	__u32 byte_count;
	__u64 base_gpa;
	union hv_access_gpa_control_flags control_flags;
} __packed;

#define HV_READ_WRITE_GPA_MAX_SIZE 16

struct hv_output_read_gpa {
	union hv_access_gpa_result access_result;
	__u8 data[HV_READ_WRITE_GPA_MAX_SIZE];
} __packed;

struct hv_input_write_gpa {
	__u64 partition_id;
	__u32 vp_index;
	__u32 byte_count;
	__u64 base_gpa;
	union hv_access_gpa_control_flags control_flags;
	__u8 data[HV_READ_WRITE_GPA_MAX_SIZE];
} __packed;

struct hv_output_write_gpa {
	union hv_access_gpa_result access_result;
} __packed;

struct hv_input_issue_psp_guest_request {
	__u64 partition_id;
	__u64 request_page;
	__u64 response_page;
} __packed;

#endif /* _HVHDK_H */
