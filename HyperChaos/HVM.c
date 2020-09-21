#include "vmm.h"
#include "vmx.h"
#include "HVM.h"
#include "EPT.h"
#include "VMX.h"
#include "Utils.h"

VOID NTAPI ExitRootModeOnAllProcessors(_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2)
{
	SIZE_T CurrentProcessorNumber;
	PVMM_PROCESSOR_CONTEXT CurrentContext;

	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	CurrentProcessorNumber = OsGetCurrentProcessorNumber();

	CurrentContext = HvGetCurrentCPUContext(GlobalContext);

	if (VmxExitRootMode(CurrentContext))
	{
		HvUtilLogDebug("ExitRootModeOnAllProcessors[#%i]: Exiting VMX mode.\n", CurrentProcessorNumber);
	}
	else
	{
		HvUtilLogError("ExitRootModeOnAllProcessors[#%i]: Failed to exit VMX mode.\n", CurrentProcessorNumber);
	}

	KeSignalCallDpcSynchronize(SystemArgument2);

	KeSignalCallDpcDone(SystemArgument1);
}

VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if (GlobalContext)
	{
		KeGenericCallDpc(ExitRootModeOnAllProcessors, (PVOID)GlobalContext);
	}

}

BOOLEAN HvmIsHVSupported()
{
	CPU_VENDOR vendor = UtilCPUVendor();
	if (vendor == CPU_Intel)
		return VmxHardSupported();

	return TRUE;
}

VOID HvmCheckFeatures()
{
	CPU_VENDOR vendor = UtilCPUVendor();
	if (vendor == CPU_Intel)
		VmxCheckFeatures();
}

inline VOID IntelSubvertCPU(IN PVCPU Vcpu, IN PVOID SystemDirectoryTableBase)
{
	VmxInitializeCPU(Vcpu, (ULONG64)SystemDirectoryTableBase);
}

inline VOID IntelRestoreCPU(IN PVCPU Vcpu)
{
	if (Vcpu->VmxState > VMX_STATE_OFF)
		VmxShutdown(Vcpu);
}

inline VOID AMDSubvertCPU(IN PVCPU Vcpu, IN PVOID arg)
{
	UNREFERENCED_PARAMETER(Vcpu);
	UNREFERENCED_PARAMETER(arg);
	DPRINT("CPU %d: %s: AMD-V not yet supported\n", CPU_IDX, __FUNCTION__);
}

inline VOID AMDRestoreCPU(IN PVCPU Vcpu)
{
	UNREFERENCED_PARAMETER(Vcpu);
	DPRINT("CPU %d: %s: AMD-V not yet supported\n", CPU_IDX, __FUNCTION__);
}

VOID HvmpHVCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	PVCPU pVCPU = &g_Data->cpu_data[CPU_IDX];

	if (ARGUMENT_PRESENT(Context))
	{
		g_Data->CPUVendor == CPU_Intel ? IntelSubvertCPU(pVCPU, Context) : AMDSubvertCPU(pVCPU, Context);
	}
	else
	{
		g_Data->CPUVendor == CPU_Intel ? IntelRestoreCPU(pVCPU) : AMDRestoreCPU(pVCPU);
	}

	KeSignalCallDpcSynchronize(SystemArgument2);

	KeSignalCallDpcDone(SystemArgument1);
}

NTSTATUS StartHyperV()
{
	if (g_Data->CPUVendor == CPU_Other)
		return STATUS_NOT_SUPPORTED;

	KeGenericCallDpc(HvmpHVCallbackDPC, (PVOID)__readcr3());

	ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	if (count != (ULONG)g_Data->vcpus)
	{
		DPRINT("CPU %d: %s: Some CPU failed to subvert\n", CPU_IDX, __FUNCTION__);
		StopHV();
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS StopHV()
{
	if (g_Data->CPUVendor == CPU_Other)
		return STATUS_NOT_SUPPORTED;

	ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors; processor_index++) {
		PROCESSOR_NUMBER processor_number;
		RtlZeroMemory(&processor_number, sizeof(PROCESSOR_NUMBER));
		NTSTATUS status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status))
		{
			DbgBreakPoint();
		}

		GROUP_AFFINITY affinity;
		RtlZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity;
		RtlZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		PVCPU pVCPU = &g_Data->cpu_data[processor_index];
		IntelRestoreCPU(pVCPU);

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!NT_SUCCESS(status))
		{
			DbgBreakPoint();
		}
	}

	return STATUS_SUCCESS;
}