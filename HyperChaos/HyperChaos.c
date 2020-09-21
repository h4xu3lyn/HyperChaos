#include "VMX.h"
#include "VMM.h"
#include "EPT.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
);

PVMM_CONTEXT GlobalContext;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	HvUtilLog("--------------------------------------------------------------\n");

	GlobalContext = HvInitializeAllProcessors();

	if (!GlobalContext)
	{
		return STATUS_SUCCESS;
	}

	return STATUS_SUCCESS;
}