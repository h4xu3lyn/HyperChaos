#include "vmx.h"
#include "vmm.h"

BOOL VmxLaunchProcessor(PVMM_PROCESSOR_CONTEXT Context)
{
    HvUtilLogDebug("VmxLaunchProcessor: VMLAUNCH....\n");

    __vmx_vmlaunch();

    VmxPrintErrorState(Context);

    VmxExitRootMode(Context);

    return FALSE;
}

VOID VmxPrintErrorState(PVMM_PROCESSOR_CONTEXT Context)
{
    UINT64 FailureCode;

    UNREFERENCED_PARAMETER(Context);

    if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &FailureCode) != 0)
    {
        HvUtilLogError("VmxPrintErrorState: Failed to read error code.\n");
        return;
    }

    HvUtilLogError("VmxPrintErrorState: VMLAUNCH Error = 0x%llx\n", FailureCode);
}

VOID VmxSetFixedBits()
{
    CR0 ControlRegister0;
    CR4 ControlRegister4;

    ControlRegister0.Flags = __readcr0();
    ControlRegister4.Flags = __readcr4();
    ControlRegister0.Flags |= __readmsr(IA32_VMX_CR0_FIXED0);
    ControlRegister0.Flags &= __readmsr(IA32_VMX_CR0_FIXED1);
    ControlRegister4.Flags |= __readmsr(IA32_VMX_CR4_FIXED0);
    ControlRegister4.Flags &= __readmsr(IA32_VMX_CR4_FIXED1);


    __writecr0(ControlRegister0.Flags);
    __writecr4(ControlRegister4.Flags);
}

BOOL VmxEnterRootMode(PVMM_PROCESSOR_CONTEXT Context)
{
    ArchEnableVmxe();

    VmxSetFixedBits();

    HvUtilLogDebug("VmxOnRegion[#%i]: (V) 0x%llx / (P) 0x%llx [%i]\n", OsGetCurrentProcessorNumber(), Context->VmxonRegion, Context->VmxonRegionPhysical, (PUINT32)Context->VmxonRegion->VmcsRevisionNumber);

    if (__vmx_on((ULONGLONG*)&Context->VmxonRegionPhysical) != 0)
    {
        HvUtilLogError("VMXON failed.\n");
        return FALSE;
    }

    if (__vmx_vmclear((ULONGLONG*)&Context->VmcsRegionPhysical) != 0)
    {
        HvUtilLogError("VMCLEAR failed.\n");
        return FALSE;
    }

    if (__vmx_vmptrld((ULONGLONG*)&Context->VmcsRegionPhysical) != 0)
    {
        HvUtilLogError("VMPTRLD failed.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL VmxExitRootMode(PVMM_PROCESSOR_CONTEXT Context)
{
    HvUtilLogError("Exiting VMX.\n");

    if (__vmx_vmclear((ULONGLONG*)&Context->VmcsRegionPhysical) != 0)
    {
        HvUtilLogError("VMCLEAR failed.\n");
    }

    __vmx_off();

    ArchDisableVmxe();

    return TRUE;
}

VOID VmxGetSegmentDescriptorFromSelector(PVMX_SEGMENT_DESCRIPTOR VmxSegmentDescriptor, SEGMENT_DESCRIPTOR_REGISTER_64 GdtRegister, SEGMENT_SELECTOR SegmentSelector, BOOL ClearRPL)
{
    PSEGMENT_DESCRIPTOR_64 OsSegmentDescriptor;

    OsZeroMemory(VmxSegmentDescriptor, sizeof(VMX_SEGMENT_DESCRIPTOR));

    if (SegmentSelector.Flags == 0 || SegmentSelector.Table != 0)
    {
        VmxSegmentDescriptor->AccessRights.Unusable = 1;
        return;
    }

    OsSegmentDescriptor = (PSEGMENT_DESCRIPTOR_64)(((UINT64)GdtRegister.BaseAddress) + (SegmentSelector.Index << 3));

    VmxSegmentDescriptor->BaseAddress = (OsSegmentDescriptor->BaseAddressHigh << 24) |
        (OsSegmentDescriptor->BaseAddressMiddle << 16) |
        (OsSegmentDescriptor->BaseAddressLow);

    VmxSegmentDescriptor->BaseAddress &= 0xFFFFFFFF;

    if (OsSegmentDescriptor->DescriptorType == 0)
    {
        VmxSegmentDescriptor->BaseAddress |= ((UINT64)OsSegmentDescriptor->BaseAddressUpper << 32);
    }

    VmxSegmentDescriptor->SegmentLimit = __segmentlimit(SegmentSelector.Flags);

    if (ClearRPL)
    {
        SegmentSelector.RequestPrivilegeLevel = 0;
    }

    VmxSegmentDescriptor->Selector = SegmentSelector.Flags;
    VmxSegmentDescriptor->AccessRights.Type = OsSegmentDescriptor->Type;
    VmxSegmentDescriptor->AccessRights.DescriptorType = OsSegmentDescriptor->DescriptorType;
    VmxSegmentDescriptor->AccessRights.DescriptorPrivilegeLevel = OsSegmentDescriptor->DescriptorPrivilegeLevel;
    VmxSegmentDescriptor->AccessRights.Present = OsSegmentDescriptor->Present;
    VmxSegmentDescriptor->AccessRights.AvailableBit = OsSegmentDescriptor->System;
    VmxSegmentDescriptor->AccessRights.LongMode = OsSegmentDescriptor->LongMode;
    VmxSegmentDescriptor->AccessRights.DefaultBig = OsSegmentDescriptor->DefaultBig;
    VmxSegmentDescriptor->AccessRights.Granularity = OsSegmentDescriptor->Granularity;
    VmxSegmentDescriptor->AccessRights.Unusable = 0;
}
