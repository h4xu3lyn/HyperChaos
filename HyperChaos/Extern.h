#pragma once

#define PHNT_MODE 0
#define PHNT_VERSION 105

#include <intrin.h>
#include <ntifs.h>

#pragma warning(push, 0)

#include "3rd_party/phnt/phnt.h"

#pragma warning(pop)

typedef UINT32 BOOL;
typedef PVOID PPHYSVOID;
typedef VMCS* PVMCS;
typedef SEGMENT_DESCRIPTOR_64* PSEGMENT_DESCRIPTOR_64;
typedef CR0* PCR0;
typedef CR4* PCR4;
typedef VMX_MSR_BITMAP* PVMX_MSR_BITMAP;

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
);


NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2
);

DECLSPEC_NORETURN
NTSYSAPI
VOID
RtlRestoreContext(
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _EXCEPTION_RECORD* ExceptionRecord
);