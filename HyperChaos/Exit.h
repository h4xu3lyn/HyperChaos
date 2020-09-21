#pragma once

#include "extern.h"
#include "vmcs.h"

typedef struct _VMEXIT_CONTEXT
{
	PGPREGISTER_CONTEXT GuestContext;

	SIZE_T GuestRIP;

	union _GUEST_EFLAGS
	{
		SIZE_T RFLAGS;
		EFLAGS EFLAGS;
	} GuestFlags;

	KIRQL SavedIRQL;

	VMX_EXIT_REASON ExitReason;

	SIZE_T ExitQualification;

	SIZE_T InstructionLength;

	SIZE_T InstructionInformation;

	SIZE_T GuestPhysicalAddress;

	BOOL ShouldStopExecution;

	BOOL ShouldIncrementRIP;

} VMEXIT_CONTEXT, * PVMEXIT_CONTEXT;

BOOL HvExitDispatchFunction(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext);

VOID VmxInitializeExitContext(PVMEXIT_CONTEXT ExitContext, PGPREGISTER_CONTEXT GuestRegisters);