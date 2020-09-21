#pragma once
#include "vmm.h"
#include "vmx.h"
#include "vmcs.h"
#include "exit.h"

PVMM_CONTEXT HvInitializeAllProcessors()
{
    SIZE_T FeatureMSR;
    PVMM_CONTEXT GlobalContext;

    HvUtilLog("HvInitializeAllProcessors: Starting.\n");

    if (!ArchIsVMXAvailable())
    {
        HvUtilLogError("VMX is not a feture of this processor.\n");
        return NULL;
    }

    FeatureMSR = ArchGetHostMSR(MSR_IA32_FEATURE_CONTROL_ADDRESS);

    if (!HvUtilBitIsSet(FeatureMSR, FEATURE_BIT_VMX_LOCK))
    {
        HvUtilLogError("VMX support was not locked by BIOS.\n");
        return NULL;
    }

    if (!HvUtilBitIsSet(FeatureMSR, FEATURE_BIT_ALLOW_VMX_OUTSIDE_SMX))
    {
        HvUtilLogError("VMX support was disabled outside of SMX operation by BIOS.\n");
        return NULL;
    }

    HvUtilLog("Total Processor Count: %i\n", OsGetCPUCount());

    GlobalContext = HvAllocateVmmContext();

    if (!GlobalContext)
    {
        return NULL;
    }

    if (!HvEptGlobalInitialize(GlobalContext))
    {
        HvUtilLogError("Processor does not support all necessary EPT features.\n");
        HvFreeVmmContext(GlobalContext);
        return NULL;
    }

    KeGenericCallDpc(HvpDPCBroadcastFunction, (PVOID)GlobalContext);

    if (GlobalContext->SuccessfulInitializationsCount != OsGetCPUCount())
    {
        HvUtilLogError("HvInitializeAllProcessors: Not all processors initialized. [%i successful]\n", GlobalContext->SuccessfulInitializationsCount);
        HvFreeVmmContext(GlobalContext);
        return NULL;
    }

    HvUtilLogSuccess("HvInitializeAllProcessors: Success.\n");
    return GlobalContext;
}

PVMM_CONTEXT HvAllocateVmmContext()
{
    PVMM_CONTEXT Context;

    Context = (PVMM_CONTEXT)OsAllocateNonpagedMemory(sizeof(VMM_CONTEXT));
    if (!Context)
    {
        return NULL;
    }

    OsZeroMemory(Context, sizeof(VMM_CONTEXT));

    Context->ProcessorCount = OsGetCPUCount();
    Context->SuccessfulInitializationsCount = 0;
    Context->SystemDirectoryTableBase = __readcr3();
    Context->VmxCapabilities = ArchGetBasicVmxCapabilities();

    PVMM_PROCESSOR_CONTEXT* ProcessorContexts = OsAllocateNonpagedMemory(Context->ProcessorCount * sizeof(PVMM_PROCESSOR_CONTEXT));
    if (!ProcessorContexts)
    {
        return NULL;
    }

    for (SIZE_T ProcessorNumber = 0; ProcessorNumber < Context->ProcessorCount; ProcessorNumber++)
    {
        ProcessorContexts[ProcessorNumber] = HvAllocateLogicalProcessorContext(Context);
        if (ProcessorContexts[ProcessorNumber] == NULL)
        {
            HvUtilLogError("HvInitializeLogicalProcessor[#%i]: Failed to setup processor context.\n", ProcessorNumber);
            return NULL;
        }

        HvUtilLog("HvInitializeLogicalProcessor[#%i]: Allocated Context [Context = 0x%llx]\n", ProcessorNumber, ProcessorContexts[ProcessorNumber]);
    }

    Context->AllProcessorContexts = ProcessorContexts;
    HvUtilLog("VmcsRevisionNumber: %x\n", Context->VmxCapabilities.VmcsRevisionId);

    return Context;
}

VOID HvFreeVmmContext(PVMM_CONTEXT Context)
{
    if (Context)
    {
        for (SIZE_T ProcessorNumber = 0; ProcessorNumber < Context->ProcessorCount; ProcessorNumber++)
        {
            HvFreeLogicalProcessorContext(Context->AllProcessorContexts[ProcessorNumber]);
        }

        OsFreeNonpagedMemory(Context->AllProcessorContexts);

        OsFreeNonpagedMemory(Context);
    }
}

PVMXON_REGION HvAllocateVmxonRegion(PVMM_CONTEXT GlobalContext)
{
    PVMXON_REGION Region;

    Region = (PVMXON_REGION)OsAllocateContiguousAlignedPages(VMX_VMXON_NUMBER_PAGES);

    OsZeroMemory(Region, VMX_VMXON_NUMBER_PAGES * PAGE_SIZE);

    Region->VmcsRevisionNumber = (UINT32)GlobalContext->VmxCapabilities.VmcsRevisionId;

    return Region;
}

PVMM_PROCESSOR_CONTEXT HvAllocateLogicalProcessorContext(PVMM_CONTEXT GlobalContext)
{
    PVMM_PROCESSOR_CONTEXT Context;

    Context = (PVMM_PROCESSOR_CONTEXT)OsAllocateNonpagedMemory(sizeof(VMM_PROCESSOR_CONTEXT));
    if (!Context)
    {
        return NULL;
    }

    OsZeroMemory(Context, sizeof(VMM_PROCESSOR_CONTEXT));

    Context->GlobalContext = GlobalContext;
    Context->HostStack.GlobalContext = GlobalContext;
    Context->VmxonRegion = HvAllocateVmxonRegion(GlobalContext);
    if (!Context->VmxonRegion)
    {
        return NULL;
    }

    Context->VmxonRegionPhysical = OsVirtualToPhysical(Context->VmxonRegion);
    if (!Context->VmxonRegionPhysical)
    {
        return NULL;
    }

    Context->VmcsRegion = HvAllocateVmcsRegion(GlobalContext);
    if (!Context->VmcsRegion)
    {
        return NULL;
    }

    Context->VmcsRegionPhysical = OsVirtualToPhysical(Context->VmcsRegion);
    if (!Context->VmcsRegionPhysical)
    {
        return NULL;
    }

    Context->MsrBitmap = OsAllocateContiguousAlignedPages(1);
    OsZeroMemory(Context->MsrBitmap, PAGE_SIZE);

    Context->MsrBitmapPhysical = OsVirtualToPhysical(Context->MsrBitmap);

    if (!HvEptLogicalProcessorInitialize(Context))
    {
        OsFreeContiguousAlignedPages(Context);
        return NULL;
    }

    return Context;
}

PVMCS HvAllocateVmcsRegion(PVMM_CONTEXT GlobalContext)
{
    PVMCS VmcsRegion;

    VmcsRegion = (PVMCS)OsAllocateContiguousAlignedPages(VMX_VMCS_NUMBER_PAGES);

    OsZeroMemory(VmcsRegion, VMX_VMCS_NUMBER_PAGES * PAGE_SIZE);

    VmcsRegion->RevisionId = (UINT32)GlobalContext->VmxCapabilities.VmcsRevisionId;

    return VmcsRegion;
}

VOID HvFreeLogicalProcessorContext(PVMM_PROCESSOR_CONTEXT Context)
{
    if (Context)
    {
        OsFreeContiguousAlignedPages(Context->VmxonRegion);
        OsFreeContiguousAlignedPages(Context->MsrBitmap);
        HvEptFreeLogicalProcessorContext(Context);
        OsFreeNonpagedMemory(Context);
    }
}

PVMM_PROCESSOR_CONTEXT HvGetCurrentCPUContext(PVMM_CONTEXT GlobalContext)
{
    SIZE_T CurrentProcessorNumber;
    PVMM_PROCESSOR_CONTEXT CurrentContext;

    CurrentProcessorNumber = OsGetCurrentProcessorNumber();
    CurrentContext = GlobalContext->AllProcessorContexts[CurrentProcessorNumber];

    return CurrentContext;
}

VOID NTAPI HvpDPCBroadcastFunction(_In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    SIZE_T CurrentProcessorNumber;
    PVMM_CONTEXT GlobalContext;
    PVMM_PROCESSOR_CONTEXT CurrentContext;

    UNREFERENCED_PARAMETER(Dpc);

    GlobalContext = (PVMM_CONTEXT)DeferredContext;

    CurrentProcessorNumber = OsGetCurrentProcessorNumber();

    CurrentContext = HvGetCurrentCPUContext(GlobalContext);

    if (HvBeginInitializeLogicalProcessor(CurrentContext))
    {
        InterlockedIncrement((volatile LONG*)&GlobalContext->SuccessfulInitializationsCount);

        CurrentContext->HasLaunched = TRUE;
    }
    else
    {
        HvUtilLogError("HvpDPCBroadcastFunction[#%i]: Failed to VMLAUNCH.\n", CurrentProcessorNumber);
    }

    KeSignalCallDpcSynchronize(SystemArgument2);

    KeSignalCallDpcDone(SystemArgument1);
}

VOID HvInitializeLogicalProcessor(PVMM_PROCESSOR_CONTEXT Context, SIZE_T GuestRSP, SIZE_T GuestRIP)
{
    SIZE_T CurrentProcessorNumber;

    CurrentProcessorNumber = OsGetCurrentProcessorNumber();

    if (!VmxEnterRootMode(Context))
    {
        HvUtilLogError("HvInitializeLogicalProcessor[#%i]: Failed to enter VMX Root Mode.\n", CurrentProcessorNumber);
        return;
    }

    if (!HvSetupVmcsDefaults(Context, (SIZE_T)&HvEnterFromGuest, (SIZE_T)&Context->HostStack.GlobalContext, GuestRIP, GuestRSP))
    {
        HvUtilLogError("HvInitializeLogicalProcessor[#%i]: Failed to enter VMX Root Mode.\n", CurrentProcessorNumber);
        VmxExitRootMode(Context);
        return;
    }

    if (!VmxLaunchProcessor(Context))
    {
        HvUtilLogError("HvInitializeLogicalProcessor[#%i]: Failed to VmxLaunchProcessor.\n", CurrentProcessorNumber);
        return;
    }
}

BOOL HvHandleVmExit(PVMM_CONTEXT GlobalContext, PGPREGISTER_CONTEXT GuestRegisters)
{
    VMEXIT_CONTEXT ExitContext;
    PVMM_PROCESSOR_CONTEXT ProcessorContext;
    BOOL Success;

    Success = FALSE;

    ProcessorContext = HvGetCurrentCPUContext(GlobalContext);

    VmxInitializeExitContext(&ExitContext, GuestRegisters);

    if (ExitContext.ExitReason.VmEntryFailure == 1)
    {
        return FALSE;
    }

    ExitContext.SavedIRQL = KeGetCurrentIrql();
    if (ExitContext.SavedIRQL < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }

    Success = HvExitDispatchFunction(ProcessorContext, &ExitContext);
    if (!Success)
    {
        HvUtilLogError("Failed to handle exit.\n");
    }

    if (ExitContext.SavedIRQL < DISPATCH_LEVEL)
    {
        KeLowerIrql(ExitContext.SavedIRQL);
    }

    return Success;
}

BOOL HvHandleVmExitFailure(PVMM_CONTEXT GlobalContext, PGPREGISTER_CONTEXT GuestRegisters)
{
    PVMM_PROCESSOR_CONTEXT ProcessorContext;

    UNREFERENCED_PARAMETER(GuestRegisters);
    UNREFERENCED_PARAMETER(GlobalContext);
    UNREFERENCED_PARAMETER(ProcessorContext);

    KeBugCheck(0xDEADBEEF);
}
