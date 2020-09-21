#include "vmcs.h"
#include "arch.h"
#include "vmm.h"
#include "util.h"
#include "vmx.h"

BOOL HvSetupVmcsDefaults(PVMM_PROCESSOR_CONTEXT Context, SIZE_T HostRIP, SIZE_T HostRSP, SIZE_T GuestRIP, SIZE_T GuestRSP)
{
	VMX_ERROR VmError;

	VmError = 0;

	OsCaptureContext(&Context->InitialRegisters);

	ArchCaptureSpecialRegisters(&Context->InitialSpecialRegisters);

	VmError |= HvSetupVmcsControlFields(Context);
	HvUtilLogDebug("HvSetupVmcsControlFields: VmError = %i\n", VmError);

	if (VmError != 0)
	{
		HvUtilLogError("HvSetupVmcsControlFields: VmError = %i\n", VmError);
		return FALSE;
	}

	VmError |= HvSetupVmcsGuestArea(Context, GuestRIP, GuestRSP);

	if (VmError != 0)
	{
		HvUtilLogError("HvSetupVmcsGuestArea: VmError = %i\n", VmError);
		return FALSE;
	}

	VmError |= HvSetupVmcsHostArea(Context, HostRIP, HostRSP);

	if (VmError != 0)
	{
		HvUtilLogError("HvSetupVmcsHostArea: VmError = %i\n", VmError);
		return FALSE;
	}

	return VmError == 0;
}

#define VMCS_SETUP_HOST_SEGMENTATION(_SEGMENT_NAME_UPPER_, _REGISTER_VALUE_) \
	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, _REGISTER_VALUE_, TRUE); \
	VmxVmwriteFieldFromImmediate(VMCS_HOST_##_SEGMENT_NAME_UPPER_##_SELECTOR, SegmentDescriptor.Selector); \
	VmxVmwriteFieldFromImmediate(VMCS_HOST_##_SEGMENT_NAME_UPPER_##_BASE, SegmentDescriptor.BaseAddress);

#define VMCS_SETUP_HOST_SEGMENTATION_NOBASE(_SEGMENT_NAME_UPPER_, _REGISTER_VALUE_) \
	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, _REGISTER_VALUE_, TRUE); \
	VmxVmwriteFieldFromImmediate(VMCS_HOST_##_SEGMENT_NAME_UPPER_##_SELECTOR, SegmentDescriptor.Selector); \

VMX_ERROR HvSetupVmcsHostArea(PVMM_PROCESSOR_CONTEXT Context, SIZE_T HostRIP, SIZE_T HostRSP)
{
	VMX_ERROR VmError;
	PIA32_SPECIAL_REGISTERS SpecialRegisters;
	PREGISTER_CONTEXT Registers;
	SEGMENT_DESCRIPTOR_REGISTER_64 GdtRegister;
	VMX_SEGMENT_DESCRIPTOR SegmentDescriptor;

	VmError = 0;

	Registers = &Context->InitialRegisters;

	SpecialRegisters = &Context->InitialSpecialRegisters;

	GdtRegister = SpecialRegisters->GlobalDescriptorTableRegister;

	VmxVmwriteFieldFromRegister(VMCS_HOST_CR0, SpecialRegisters->ControlRegister0);
	VmxVmwriteFieldFromImmediate(VMCS_HOST_CR3, Context->GlobalContext->SystemDirectoryTableBase);
	VmxVmwriteFieldFromRegister(VMCS_HOST_CR4, SpecialRegisters->ControlRegister4);
	VmxVmwriteFieldFromImmediate(VMCS_HOST_RIP, HostRIP);
	VmxVmwriteFieldFromImmediate(VMCS_HOST_RSP, HostRSP);
	VMCS_SETUP_HOST_SEGMENTATION_NOBASE(CS, Registers->SegCS);
	VMCS_SETUP_HOST_SEGMENTATION_NOBASE(SS, Registers->SegSS);
	VMCS_SETUP_HOST_SEGMENTATION_NOBASE(DS, Registers->SegDS);
	VMCS_SETUP_HOST_SEGMENTATION_NOBASE(ES, Registers->SegES);
	VMCS_SETUP_HOST_SEGMENTATION(FS, Registers->SegFS);
	VMCS_SETUP_HOST_SEGMENTATION(GS, Registers->SegGS);
	VMCS_SETUP_HOST_SEGMENTATION(TR, SpecialRegisters->TaskRegister);
	VmxVmwriteFieldFromImmediate(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));
	VmxVmwriteFieldFromImmediate(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	VmxVmwriteFieldFromImmediate(VMCS_HOST_GDTR_BASE, SpecialRegisters->GlobalDescriptorTableRegister.BaseAddress);
	VmxVmwriteFieldFromImmediate(VMCS_HOST_IDTR_BASE, SpecialRegisters->InterruptDescriptorTableRegister.BaseAddress);
	VmxVmwriteFieldFromRegister(VMCS_HOST_SYSENTER_CS, SpecialRegisters->SysenterCsMsr);
	VmxVmwriteFieldFromImmediate(VMCS_HOST_SYSENTER_ESP, SpecialRegisters->SysenterEspMsr);
	VmxVmwriteFieldFromImmediate(VMCS_HOST_SYSENTER_EIP, SpecialRegisters->SysenterEipMsr);

	return VmError;
}

VMX_ERROR HvSetupVmcsGuestSegment(SEGMENT_DESCRIPTOR_REGISTER_64 GdtRegister, SEGMENT_SELECTOR SegmentSelector, SIZE_T VmcsSelector, SIZE_T VmcsLimit, SIZE_T VmcsAccessRights, SIZE_T VmcsBase)
{
	VMX_SEGMENT_DESCRIPTOR SegmentDescriptor;
	VMX_ERROR VmError;

	VmError = 0;

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, SegmentSelector, FALSE);

	VmxVmwriteFieldFromImmediate(VmcsSelector, SegmentDescriptor.Selector);
	VmxVmwriteFieldFromImmediate(VmcsBase, SegmentDescriptor.BaseAddress);

	VmxVmwriteFieldFromImmediate(VmcsLimit, SegmentDescriptor.SegmentLimit);
	VmxVmwriteFieldFromRegister(VmcsAccessRights, SegmentDescriptor.AccessRights);

	return VmError;
}

#define VMCS_SETUP_GUEST_SEGMENTATION(_SEGMENT_NAME_UPPER_, _REGISTER_VALUE_) \
	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, _REGISTER_VALUE_, FALSE); \
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_##_SEGMENT_NAME_UPPER_##_SELECTOR, SegmentDescriptor.Selector); \
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_##_SEGMENT_NAME_UPPER_##_BASE, SegmentDescriptor.BaseAddress); \
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_##_SEGMENT_NAME_UPPER_##_LIMIT, SegmentDescriptor.SegmentLimit); \
	VmxVmwriteFieldFromRegister(VMCS_GUEST_##_SEGMENT_NAME_UPPER_##_ACCESS_RIGHTS, SegmentDescriptor.AccessRights); \

VMX_ERROR HvSetupVmcsGuestArea(PVMM_PROCESSOR_CONTEXT Context, SIZE_T GuestRIP, SIZE_T GuestRSP)
{
	PREGISTER_CONTEXT Registers;
	VMX_ERROR VmError;
	SEGMENT_DESCRIPTOR_REGISTER_64 GdtRegister;
	PIA32_SPECIAL_REGISTERS SpecialRegisters;
	VMX_SEGMENT_DESCRIPTOR SegmentDescriptor;

	VmError = 0;

	Registers = &Context->InitialRegisters;

	SpecialRegisters = &Context->InitialSpecialRegisters;

	GdtRegister = SpecialRegisters->GlobalDescriptorTableRegister;

	VmxVmwriteFieldFromRegister(VMCS_GUEST_CR0, SpecialRegisters->ControlRegister0);
	VmxVmwriteFieldFromRegister(VMCS_GUEST_CR3, SpecialRegisters->ControlRegister3);
	VmxVmwriteFieldFromRegister(VMCS_GUEST_CR4, SpecialRegisters->ControlRegister4);
	VmxVmwriteFieldFromRegister(VMCS_GUEST_DR7, SpecialRegisters->DebugRegister7);
	VmxVmwriteFieldFromRegister(VMCS_GUEST_RFLAGS, SpecialRegisters->RflagsRegister);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_RIP, GuestRIP);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_RSP, GuestRSP);

	HvUtilLogDebug("GdtRegister: 0x%llx, Base: 0x%llx, Limit: 0x%llx\n", GdtRegister, GdtRegister.BaseAddress, GdtRegister.Limit);

	VMCS_SETUP_GUEST_SEGMENTATION(ES, Registers->SegES);
	VMCS_SETUP_GUEST_SEGMENTATION(CS, Registers->SegCS);
	VMCS_SETUP_GUEST_SEGMENTATION(SS, Registers->SegSS);
	VMCS_SETUP_GUEST_SEGMENTATION(DS, Registers->SegDS);
	VMCS_SETUP_GUEST_SEGMENTATION(GS, Registers->SegGS);
	VMCS_SETUP_GUEST_SEGMENTATION(FS, Registers->SegFS);
	VMCS_SETUP_GUEST_SEGMENTATION(LDTR, SpecialRegisters->LocalDescriptorTableRegister);
	VMCS_SETUP_GUEST_SEGMENTATION(TR, SpecialRegisters->TaskRegister);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_GDTR_BASE, SpecialRegisters->GlobalDescriptorTableRegister.BaseAddress);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_GDTR_LIMIT, SpecialRegisters->GlobalDescriptorTableRegister.Limit);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_IDTR_BASE, SpecialRegisters->InterruptDescriptorTableRegister.BaseAddress);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_IDTR_LIMIT, SpecialRegisters->InterruptDescriptorTableRegister.Limit);
	VmxVmwriteFieldFromRegister(VMCS_GUEST_DEBUGCTL, SpecialRegisters->DebugControlMsr);
	VmxVmwriteFieldFromRegister(VMCS_GUEST_SYSENTER_CS, SpecialRegisters->SysenterCsMsr);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_SYSENTER_EIP, SpecialRegisters->SysenterEipMsr);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_SYSENTER_ESP, SpecialRegisters->SysenterEspMsr);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_ACTIVITY_STATE, 0);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
	VmxVmwriteFieldFromImmediate(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);
	VmxVmwriteFieldFromRegister(VMCS_CTRL_EPT_POINTER, Context->EptPointer);

	return VmError;
}

VMX_ERROR HvSetupVmcsControlFields(PVMM_PROCESSOR_CONTEXT Context)
{
	VMX_ERROR VmError;

	VmError = 0;

	VmxVmwriteFieldFromRegister(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, HvSetupVmcsControlPinBased(Context));
	VmxVmwriteFieldFromRegister(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, HvSetupVmcsControlProcessor(Context));
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_EXCEPTION_BITMAP, 0);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_CR3_TARGET_COUNT, 0);
	VmxVmwriteFieldFromRegister(VMCS_CTRL_VMEXIT_CONTROLS, HvSetupVmcsControlVmExit(Context));
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
	VmxVmwriteFieldFromRegister(VMCS_CTRL_VMENTRY_CONTROLS, HvSetupVmcsControlVmEntry(Context));
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
	VmxVmwriteFieldFromRegister(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, HvSetupVmcsControlSecondaryProcessor(Context));
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_MSR_BITMAP_ADDRESS, (SIZE_T)Context->MsrBitmapPhysical);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
	VmxVmwriteFieldFromRegister(VMCS_CTRL_CR0_READ_SHADOW, Context->InitialSpecialRegisters.ControlRegister0);
	VmxVmwriteFieldFromRegister(VMCS_CTRL_CR4_READ_SHADOW, Context->InitialSpecialRegisters.ControlRegister4);
	VmxVmwriteFieldFromImmediate(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER, 1);

	return VmError;
}

IA32_VMX_PINBASED_CTLS_REGISTER HvSetupVmcsControlPinBased(PVMM_PROCESSOR_CONTEXT Context)
{
	IA32_VMX_PINBASED_CTLS_REGISTER Register;
	SIZE_T ConfigMSR;

	Register.Flags = 0;

	if (Context->GlobalContext->VmxCapabilities.VmxControls == 1)
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_TRUE_PINBASED_CTLS);
	}
	else
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_PINBASED_CTLS);
	}

	Register.Flags = HvUtilEncodeMustBeBits(Register.Flags, ConfigMSR);

	return Register;
}

IA32_VMX_PROCBASED_CTLS_REGISTER HvSetupVmcsControlProcessor(PVMM_PROCESSOR_CONTEXT Context)
{
	IA32_VMX_PROCBASED_CTLS_REGISTER Register;
	SIZE_T ConfigMSR;

	Register.Flags = 0;
	Register.ActivateSecondaryControls = 1;
	Register.UseMsrBitmaps = 1;

	if (Context->GlobalContext->VmxCapabilities.VmxControls == 1)
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_TRUE_PROCBASED_CTLS);
	}
	else
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_PROCBASED_CTLS);
	}

	Register.Flags = HvUtilEncodeMustBeBits(Register.Flags, ConfigMSR);

	return Register;
}

IA32_VMX_PROCBASED_CTLS2_REGISTER HvSetupVmcsControlSecondaryProcessor(PVMM_PROCESSOR_CONTEXT Context)
{
	IA32_VMX_PROCBASED_CTLS2_REGISTER Register;
	SIZE_T ConfigMSR;

	UNREFERENCED_PARAMETER(Context);

	Register.Flags = 0;
	Register.EnableEpt = 1;
	Register.EnableRdtscp = 1;
	Register.EnableVpid = 1;
	Register.EnableInvpcid = 1;
	Register.EnableXsaves = 1;
	Register.ConcealVmxFromPt = 1;

	ConfigMSR = ArchGetHostMSR(IA32_VMX_PROCBASED_CTLS2);

	Register.Flags = HvUtilEncodeMustBeBits(Register.Flags, ConfigMSR);


	return Register;
}

IA32_VMX_ENTRY_CTLS_REGISTER HvSetupVmcsControlVmEntry(PVMM_PROCESSOR_CONTEXT Context)
{
	IA32_VMX_ENTRY_CTLS_REGISTER Register;
	SIZE_T ConfigMSR;

	Register.Flags = 0;
	Register.Ia32EModeGuest = 1;
	Register.ConcealVmxFromPt = 1;

	if (Context->GlobalContext->VmxCapabilities.VmxControls == 1)
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_TRUE_ENTRY_CTLS);
	}
	else
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_ENTRY_CTLS);
	}

	Register.Flags = HvUtilEncodeMustBeBits(Register.Flags, ConfigMSR);

	return Register;
}

IA32_VMX_EXIT_CTLS_REGISTER HvSetupVmcsControlVmExit(PVMM_PROCESSOR_CONTEXT Context)
{
	IA32_VMX_EXIT_CTLS_REGISTER Register;
	SIZE_T ConfigMSR;

	Register.Flags = 0;
	Register.HostAddressSpaceSize = 1;
	Register.ConcealVmxFromPt = 1;

	if (Context->GlobalContext->VmxCapabilities.VmxControls == 1)
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_TRUE_EXIT_CTLS);
	}
	else
	{
		ConfigMSR = ArchGetHostMSR(IA32_VMX_EXIT_CTLS);
	}

	Register.Flags = HvUtilEncodeMustBeBits(Register.Flags, ConfigMSR);

	return Register;
}

