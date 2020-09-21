#pragma once

#include "extern.h"

typedef struct _IA32_SPECIAL_REGISTERS
{
	CR0 ControlRegister0;
	CR3 ControlRegister3;
	CR4 ControlRegister4;
	SEGMENT_DESCRIPTOR_REGISTER_64 GlobalDescriptorTableRegister;
	SEGMENT_DESCRIPTOR_REGISTER_64 InterruptDescriptorTableRegister;
	DR7 DebugRegister7;
	EFLAGS RflagsRegister;
	SEGMENT_SELECTOR TaskRegister;
	SEGMENT_SELECTOR LocalDescriptorTableRegister;
	IA32_DEBUGCTL_REGISTER DebugControlMsr;
	IA32_SYSENTER_CS_REGISTER SysenterCsMsr;
	SIZE_T SysenterEspMsr;
	SIZE_T SysenterEipMsr;
	SIZE_T GlobalPerfControlMsr;
	IA32_PAT_REGISTER PatMsr;
	IA32_EFER_REGISTER EferMsr;

} IA32_SPECIAL_REGISTERS, * PIA32_SPECIAL_REGISTERS;

#pragma warning(push, 0)

typedef struct DECLSPEC_ALIGN(16) _REGISTER_CONTEXT {

	ULONG64 P1Home;
	ULONG64 P2Home;
	ULONG64 P3Home;
	ULONG64 P4Home;
	ULONG64 P5Home;
	ULONG64 P6Home;
	ULONG ContextFlags;
	ULONG MxCsr;
	SEGMENT_SELECTOR SegCS;
	SEGMENT_SELECTOR SegDS;
	SEGMENT_SELECTOR SegES;
	SEGMENT_SELECTOR SegFS;
	SEGMENT_SELECTOR SegGS;
	SEGMENT_SELECTOR SegSS;
	ULONG EFlags;
	ULONG64 Dr0;
	ULONG64 Dr1;
	ULONG64 Dr2;
	ULONG64 Dr3;
	ULONG64 Dr6;
	ULONG64 Dr7;
	ULONG64 Rax;
	ULONG64 Rcx;
	ULONG64 Rdx;
	ULONG64 Rbx;
	ULONG64 Rsp;
	ULONG64 Rbp;
	ULONG64 Rsi;
	ULONG64 Rdi;
	ULONG64 R8;
	ULONG64 R9;
	ULONG64 R10;
	ULONG64 R11;
	ULONG64 R12;
	ULONG64 R13;
	ULONG64 R14;
	ULONG64 R15;
	ULONG64 Rip;

	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	M128A VectorRegister[26];
	ULONG64 VectorControl;
	ULONG64 DebugControl;
	ULONG64 LastBranchToRip;
	ULONG64 LastBranchFromRip;
	ULONG64 LastExceptionToRip;
	ULONG64 LastExceptionFromRip;
} REGISTER_CONTEXT, * PREGISTER_CONTEXT;

#pragma warning(pop)

SIZE_T ArchGetHostMSR(ULONG MsrAddress);

UINT32 ArchGetCPUID(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister);

BOOL ArchIsCPUFeaturePresent(INT32 FunctionId, INT32 SubFunctionId, INT32 CPUIDRegister, INT32 FeatureBit);

BOOL ArchIsVMXAvailable();

IA32_VMX_BASIC_REGISTER ArchGetBasicVmxCapabilities();

VOID ArchEnableVmxe();

VOID ArchDisableVmxe();

VOID ArchCaptureSpecialRegisters(PIA32_SPECIAL_REGISTERS Registers);

VOID ArchCaptureContext(PREGISTER_CONTEXT RegisterContext);

SEGMENT_SELECTOR ArchReadTaskRegister();

SEGMENT_SELECTOR ArchReadLocalDescriptorTableRegister();