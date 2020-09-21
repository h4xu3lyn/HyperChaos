#pragma once
#include "extern.h"
#include "vmm_settings.h"
#include "msr.h"
#include "arch.h"
#include "util.h"
#include "os.h"
#include "EPT.h"

typedef struct _VMXON_REGION
{
	UINT32 VmcsRevisionNumber;

} VMXON_REGION, * PVMXON_REGION;


typedef struct _VMX_VMM_CONTEXT VMX_VMM_CONTEXT, * PVMM_CONTEXT;

typedef struct _VMM_HOST_STACK_REGION
{
	CHAR HostStack[VMM_SETTING_STACK_SPACE];

	PVMM_CONTEXT GlobalContext;

} VMM_HOST_STACK_REGION, * PVMM_HOST_STACK_REGION;

typedef struct _VMM_PROCESSOR_CONTEXT
{
	BOOL HasLaunched;

	PVMM_CONTEXT GlobalContext;
	PVMXON_REGION VmxonRegion;

	PPHYSVOID VmxonRegionPhysical;

	PVMCS VmcsRegion;

	PPHYSVOID VmcsRegionPhysical;

	PVMX_MSR_BITMAP MsrBitmap;

	PPHYSVOID MsrBitmapPhysical;

	REGISTER_CONTEXT InitialRegisters;

	IA32_SPECIAL_REGISTERS InitialSpecialRegisters;

	VMM_HOST_STACK_REGION HostStack;

	EPT_POINTER EptPointer;

	PVMM_EPT_PAGE_TABLE EptPageTable;

} VMM_PROCESSOR_CONTEXT, * PVMM_PROCESSOR_CONTEXT;


typedef struct _VMX_VMM_CONTEXT
{
	SIZE_T ProcessorCount;
	SIZE_T SuccessfulInitializationsCount;
	PVMM_PROCESSOR_CONTEXT* AllProcessorContexts;
	IA32_VMX_BASIC_REGISTER VmxCapabilities;
	SIZE_T SystemDirectoryTableBase;
	MTRR_RANGE_DESCRIPTOR MemoryRanges[9];
	ULONG NumberOfEnabledMemoryRanges;

} VMM_CONTEXT, * PVMM_CONTEXT;

PVMCS HvAllocateVmcsRegion(PVMM_CONTEXT GlobalContext);

VOID HvFreeVmmContext(PVMM_CONTEXT Context);

PVMM_CONTEXT HvAllocateVmmContext();

PVMM_PROCESSOR_CONTEXT HvGetCurrentCPUContext(PVMM_CONTEXT GlobalContext);

PVMM_CONTEXT HvInitializeAllProcessors();

VOID HvpDPCBroadcastFunction(_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2);

BOOL HvBeginInitializeLogicalProcessor(PVMM_PROCESSOR_CONTEXT Context);

VOID HvEnterFromGuest();

VOID HvInitializeLogicalProcessor(PVMM_PROCESSOR_CONTEXT Context, SIZE_T GuestRSP, SIZE_T GuestRIP);

PVMM_PROCESSOR_CONTEXT HvAllocateLogicalProcessorContext(PVMM_CONTEXT GlobalContext);

VOID HvFreeLogicalProcessorContext(PVMM_PROCESSOR_CONTEXT Context);
