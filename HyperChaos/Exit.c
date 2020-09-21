#include "Exit.h"
#include "EPT.h"

VOID VmxInitializeExitContext(PVMEXIT_CONTEXT ExitContext, PGPREGISTER_CONTEXT GuestRegisters)
{
	VMX_ERROR VmError;

	VmError = 0;

	OsZeroMemory(ExitContext, sizeof(VMEXIT_CONTEXT));

	ExitContext->GuestContext = GuestRegisters;

	ExitContext->ShouldIncrementRIP = TRUE;

	ExitContext->ShouldStopExecution = FALSE;

	VmxVmreadFieldToImmediate(VMCS_GUEST_RSP, &ExitContext->GuestContext->GuestRSP);

	VmxVmreadFieldToImmediate(VMCS_GUEST_RIP, &ExitContext->GuestRIP);

	VmxVmreadFieldToImmediate(VMCS_GUEST_RFLAGS, &ExitContext->GuestFlags.RFLAGS);

	VmxVmreadFieldToRegister(VMCS_EXIT_REASON, &ExitContext->ExitReason);

	VmxVmreadFieldToImmediate(VMCS_EXIT_QUALIFICATION, &ExitContext->ExitQualification);

	VmxVmreadFieldToImmediate(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitContext->InstructionLength);

	VmxVmreadFieldToImmediate(VMCS_VMEXIT_INSTRUCTION_INFO, &ExitContext->InstructionInformation);

	VmxVmreadFieldToImmediate(VMCS_GUEST_PHYSICAL_ADDRESS, &ExitContext->GuestPhysicalAddress);
}


VOID HvExitHandleCpuid(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	INT32 CPUInfo[4];

	UNREFERENCED_PARAMETER(ProcessorContext);

	__cpuidex(CPUInfo, (int)ExitContext->GuestContext->GuestRAX, (int)ExitContext->GuestContext->GuestRCX);

	if (ExitContext->GuestContext->GuestRAX == CPUID_VERSION_INFORMATION)
	{
		CPUInfo[2] = (INT32)HvUtilBitClearBit(CPUInfo[2], CPUID_VMX_ENABLED_BIT);
	}

	ExitContext->GuestContext->GuestRAX = CPUInfo[0];
	ExitContext->GuestContext->GuestRBX = CPUInfo[1];
	ExitContext->GuestContext->GuestRCX = CPUInfo[2];
	ExitContext->GuestContext->GuestRDX = CPUInfo[3];
}

VOID HvExitHandleEptMisconfiguration(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	UNREFERENCED_PARAMETER(ProcessorContext);

	HvUtilLogError("EPT Misconfiguration! A field in the EPT paging structure was invalid. Faulting guest address: 0x%llX\n", ExitContext->GuestPhysicalAddress);

	ExitContext->ShouldIncrementRIP = FALSE;
	ExitContext->ShouldStopExecution = TRUE;

}

VOID HvExitHandleUnknownExit(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	UNREFERENCED_PARAMETER(ProcessorContext);

	__debugbreak();
	HvUtilLogError("Unknown exit reason! An exit was made but no handler was configured to handle it. Reason: 0x%llX\n", ExitContext->ExitReason.BasicExitReason);

	ExitContext->ShouldIncrementRIP = TRUE;

}

BOOL HvExitDispatchFunction(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	VMX_ERROR VmError;
	SIZE_T GuestInstructionLength;

	VmError = 0;

	switch (ExitContext->ExitReason.BasicExitReason)
	{
	case VMX_EXIT_REASON_EXECUTE_CPUID:
		HvExitHandleCpuid(ProcessorContext, ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_INVD:
		__wbinvd();
		break;
	case VMX_EXIT_REASON_EXECUTE_XSETBV:
		_xsetbv((UINT32)ExitContext->GuestContext->GuestRCX,
			ExitContext->GuestContext->GuestRDX << 32 |
			ExitContext->GuestContext->GuestRAX);
		break;
	case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
		HvExitHandleEptMisconfiguration(ProcessorContext, ExitContext);
		break;
	case VMX_EXIT_REASON_EPT_VIOLATION:
		HvExitHandleEptViolation(ProcessorContext, ExitContext);
		break;
	default:
		HvExitHandleUnknownExit(ProcessorContext, ExitContext);
		break;
	}

	if (ExitContext->ShouldStopExecution)
	{
		HvUtilLogError("HvExitDispatchFunction: Leaving VMX mode.\n");
		return FALSE;
	}

	if (ExitContext->ShouldIncrementRIP)
	{
		VmxVmreadFieldToImmediate(VMCS_VMEXIT_INSTRUCTION_LENGTH, &GuestInstructionLength);

		ExitContext->GuestRIP += GuestInstructionLength;

		VmxVmwriteFieldFromImmediate(VMCS_GUEST_RIP, ExitContext->GuestRIP);
	}

	return TRUE;
}
