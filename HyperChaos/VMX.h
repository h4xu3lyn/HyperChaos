#pragma once
#include "extern.h"
#include "vmm.h"
#include "ept.h"

#define CPUID_VMX_ENABLED_FUNCTION 1
#define CPUID_VMX_ENABLED_SUBFUNCTION 0
#define CPUID_REGISTER_EAX 0
#define CPUID_REGISTER_EBX 1
#define CPUID_REGISTER_ECX 2
#define CPUID_REGISTER_EDX 3
#define CPUID_VMX_ENABLED_BIT 5
#define VMX_VMXON_NUMBER_PAGES 2
#define VMX_VMCS_NUMBER_PAGES 2

BOOL VmxLaunchProcessor(PVMM_PROCESSOR_CONTEXT Context);
BOOL VmxEnterRootMode(PVMM_PROCESSOR_CONTEXT Context);
BOOL VmxExitRootMode(PVMM_PROCESSOR_CONTEXT Context);

#define VmxVmwriteFieldFromRegister(_FIELD_DEFINE_, _REGISTER_VAR_) \
	VmError |= __vmx_vmwrite(_FIELD_DEFINE_, _REGISTER_VAR_.Flags) \

#define VmxVmwriteFieldFromImmediate(_FIELD_DEFINE_, _IMMEDIATE_) \
	VmError |= __vmx_vmwrite(_FIELD_DEFINE_, _IMMEDIATE_) \

#define VmxVmreadFieldToRegister(_FIELD_DEFINE_, _REGISTER_VAR_) \
	VmError |= __vmx_vmread(_FIELD_DEFINE_, _REGISTER_VAR_.Flags); \

#define VmxVmreadFieldToImmediate(_FIELD_DEFINE_, _IMMEDIATE_) \
	VmError |= __vmx_vmread(_FIELD_DEFINE_, _IMMEDIATE_); \

typedef SIZE_T VMX_ERROR;

typedef struct _VMX_SEGMENT_DESCRIPTOR
{
	SIZE_T Selector;
	SIZE_T BaseAddress;
	UINT32 SegmentLimit;
	VMX_SEGMENT_ACCESS_RIGHTS AccessRights;
} VMX_SEGMENT_DESCRIPTOR, * PVMX_SEGMENT_DESCRIPTOR;

#pragma warning(push, 0)
typedef union _VMX_EXIT_REASON_FIELD_UNION
{
	struct
	{
		SIZE_T BasicExitReason : 16;
		SIZE_T MustBeZero1 : 11;
		SIZE_T WasInEnclaveMode : 1;
		SIZE_T PendingMTFExit : 1;
		SIZE_T ExitFromVMXRoot : 1;
		SIZE_T MustBeZero2 : 1;
		SIZE_T VmEntryFailure : 1;
	};

	SIZE_T Flags;
} VMX_EXIT_REASON, * PVMX_EXIT_REASON;

/*
	pop	rax
	pop	rcx
	pop	rdx
	pop	rbx
	add	rsp, 8
	pop	rbp
	pop	rsi
	pop	rdi
	pop	r8
	pop	r9
	pop	r10
	pop	r11
	pop	r12
	pop	r13
	pop	r14
	pop	r15
 */
typedef struct _GPREGISTER_CONTEXT
{
	SIZE_T GuestRAX;
	SIZE_T GuestRCX;
	SIZE_T GuestRDX;
	SIZE_T GuestRBX;
	SIZE_T GuestRSP;
	SIZE_T GuestRBP;
	SIZE_T GuestRSI;
	SIZE_T GuestRDI;
	SIZE_T GuestR8;
	SIZE_T GuestR9;
	SIZE_T GuestR10;
	SIZE_T GuestR11;
	SIZE_T GuestR12;
	SIZE_T GuestR13;
	SIZE_T GuestR14;
	SIZE_T GuestR15;
} GPREGISTER_CONTEXT, * PGPREGISTER_CONTEXT;


#pragma warning(pop)

VOID VmxGetSegmentDescriptorFromSelector(PVMX_SEGMENT_DESCRIPTOR VmxSegmentDescriptor, SEGMENT_DESCRIPTOR_REGISTER_64 GdtRegister, SEGMENT_SELECTOR SegmentSelector, BOOL ClearRPL);

VOID VmxPrintErrorState(PVMM_PROCESSOR_CONTEXT Context);

VOID __invept(SIZE_T Type, INVEPT_DESCRIPTOR* Descriptor);