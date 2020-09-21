#include "Hook.h"

static const UCHAR HkpDetour[] = {
	0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};

#define FULL_DETOUR_SIZE			(sizeof(HkpDetour) + sizeof(PVOID))
#define INTERLOCKED_EXCHANGE_SIZE	(16ul)
#define HK_POOL_TAG					('  kh')

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpReplaceCode16Bytes(
	_In_ PVOID	Address,
	_In_ PUCHAR	Replacement
)
{

	if ((ULONG64)Address != ((ULONG64)Address & ~0xf))
	{
		return STATUS_DATATYPE_MISALIGNMENT;
	}

	PMDL Mdl = IoAllocateMdl(Address, INTERLOCKED_EXCHANGE_SIZE, FALSE, FALSE, NULL);
	if (Mdl == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(Mdl);

		return STATUS_INVALID_ADDRESS;
	}

	PLONG64 RwMapping = MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority
	);

	if (RwMapping == NULL)
	{
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return STATUS_INTERNAL_ERROR;
	}

	NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		MmUnmapLockedPages(RwMapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return Status;
	}

	LONG64 PreviousContent[2];
	PreviousContent[0] = RwMapping[0];
	PreviousContent[1] = RwMapping[1];

	InterlockedCompareExchange128(
		RwMapping,
		((PLONG64)Replacement)[1],
		((PLONG64)Replacement)[0],
		PreviousContent
	);

	MmUnmapLockedPages(RwMapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
static VOID HkpPlaceDetour(
	_In_ PVOID Address,
	_In_ PVOID Destination
)
{

	RtlCopyMemory((PUCHAR)Address, HkpDetour, sizeof(HkpDetour));
	RtlCopyMemory((PUCHAR)Address + sizeof(HkpDetour), &Destination, sizeof(PVOID));
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(
	_In_ PVOID	 HookedFunction,
	_In_ PVOID	 OriginalTrampoline
)
{
	PUCHAR OriginalBytes = (PUCHAR)OriginalTrampoline - INTERLOCKED_EXCHANGE_SIZE;

	NTSTATUS Status = HkpReplaceCode16Bytes(HookedFunction, OriginalBytes);

	LARGE_INTEGER DelayInterval;
	DelayInterval.QuadPart = -100000;
	KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);

	ExFreePoolWithTag(OriginalBytes, HK_POOL_TAG);

	return Status;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(
	_In_ PVOID	 TargetFunction,
	_In_ PVOID	 Hook,
	_In_ SIZE_T  CodeLength,
	_Out_ PVOID* OriginalTrampoline
)
{

	if (CodeLength < FULL_DETOUR_SIZE)
	{
		return STATUS_INVALID_PARAMETER_3;
	}

	PUCHAR Trampoline = ExAllocatePoolWithTag(
		NonPagedPool,
		INTERLOCKED_EXCHANGE_SIZE + FULL_DETOUR_SIZE + CodeLength,
		HK_POOL_TAG
	);
	if (Trampoline == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(Trampoline, TargetFunction, INTERLOCKED_EXCHANGE_SIZE);

	RtlCopyMemory(Trampoline + INTERLOCKED_EXCHANGE_SIZE, TargetFunction, CodeLength);
	HkpPlaceDetour(Trampoline + INTERLOCKED_EXCHANGE_SIZE + CodeLength, (PVOID)((ULONG_PTR)TargetFunction + CodeLength));

	UCHAR DetourBytes[INTERLOCKED_EXCHANGE_SIZE];

	HkpPlaceDetour(DetourBytes, Hook);
	RtlCopyMemory(
		(PUCHAR)DetourBytes + FULL_DETOUR_SIZE,
		(PUCHAR)TargetFunction + FULL_DETOUR_SIZE,
		INTERLOCKED_EXCHANGE_SIZE - FULL_DETOUR_SIZE
	);

	NTSTATUS Status = HkpReplaceCode16Bytes(TargetFunction, DetourBytes);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
	}
	else
	{
		*OriginalTrampoline = Trampoline + INTERLOCKED_EXCHANGE_SIZE;
	}

	return Status;
}