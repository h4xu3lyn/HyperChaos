#pragma once
#include <ntifs.h>
#include <ntddk.h>

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(
	_In_ PVOID	 TargetFunction,
	_In_ PVOID	 Hook,
	_In_ SIZE_T  CodeLength,
	_Out_ PVOID* OriginalTrampoline
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(
	_In_ PVOID	 HookedFunction,
	_In_ PVOID	 OriginalTrampoline
);

#ifndef __BASE_H__
#define __BASE_H__

#ifdef __cplusplus
extern "C"
{
#endif



#ifdef __cplusplus
}
#endif

typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;
	PULONG  ServiceCounterTableBase;
	ULONG   NumberOfService;
	PVOID   ParamTableBase;
} KSYSTEM_SERVICE_TABLE, * PKSYSTEM_SERVICE_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE   ntoskrnl;
	KSYSTEM_SERVICE_TABLE   win32k;
	KSYSTEM_SERVICE_TABLE   notUsed1;
	KSYSTEM_SERVICE_TABLE   notUsed2;
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;


#define MAX_SYSTEM_SERVICE_NUMBER                 1024
#define MAX_SEARCH_FUNTION_NUMBER				  4096

__declspec(dllimport) KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

#endif	// __BASE_H__