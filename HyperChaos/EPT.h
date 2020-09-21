#ifndef EPT_H_
#define EPT_H_

#include <fltKernel.h>
#include "arch.h"

#define VM_VPID             1
#define EPT_TABLE_ORDER     9
#define EPT_TABLE_ENTRIES   512
#define MAX_NUM_OF_PAGES    0x20000
#define EPTE_READ       0x1
#define EPTE_READEXEC   0x5
#define EPTE_WRITE      0x2
#define EPTE_EXECUTE    0x4
#define CACHE_TYPE_UC		0x00
#define CACHE_TYPE_WC		0x01
#define CACHE_TYPE_WT		0x04
#define EPTE_ATTR_MASK  0xFFF
#define EPTE_MT_SHIFT   3
#define EPT_LEVELS      4
#define VMM_EPT_PML4E_COUNT 512
#define VMM_EPT_PML3E_COUNT 512
#define VMM_EPT_PML2E_COUNT 512
#define VMM_EPT_PML1E_COUNT 512
#define SIZE_2_MB ((SIZE_T)(512 * PAGE_SIZE))
#define CACHE_TYPE_WP		0x05 
#define CACHE_TYPE_WB		0x06
#define CACHE_TYPE_UC_MINUS	0x07
#define GMTRR_VCNT		MTRR_VCNT_MAX
#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) (_VAR_ & 0xFFFULL)
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)

typedef EPT_PML4 EPT_PML4_POINTER, * PEPT_PML4_POINTER;
typedef EPDPTE EPT_PML3_POINTER, * PEPT_PML3_POINTER;
typedef EPDE_2MB EPT_PML2_ENTRY, * PEPT_PML2_ENTRY;
typedef EPDE EPT_PML2_POINTER, * PEPT_PML2_POINTER;
typedef EPTE EPT_PML1_ENTRY, * PEPT_PML1_ENTRY;



typedef enum _EPT_ACCESS
{
    EPT_ACCESS_NONE = 0,
    EPT_ACCESS_READ = 1,
    EPT_ACCESS_WRITE = 2,
    EPT_ACCESS_EXEC = 4,
    EPT_ACCESS_RW = EPT_ACCESS_READ | EPT_ACCESS_WRITE,
    EPT_ACCESS_ALL = EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC
} EPT_ACCESS;

typedef enum _EPT_TABLE_LEVEL
{
    EPT_LEVEL_PTE = 0,
    EPT_LEVEL_PDE = 1,
    EPT_LEVEL_PDPTE = 2,
    EPT_LEVEL_PML4 = 3,
    EPT_TOP_LEVEL = EPT_LEVEL_PML4
} EPT_TABLE_LEVEL;

#pragma warning(disable: 4214)
#pragma pack(push, 1)

typedef union _EPT_TABLE_POINTER
{
    ULONG64 All;
    struct
    {
        ULONG64 MemoryType : 3;
        ULONG64 PageWalkLength : 3;
        ULONG64 reserved1 : 6;
        ULONG64 PhysAddr : 40;
        ULONG64 reserved2 : 12;
    } Fields;
} EPT_TABLE_POINTER, * PEPT_TABLE_POINTER;

typedef union _EPT_MMPTE
{
    ULONG64 All;
    struct
    {
        ULONG64 Present : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 reserved1 : 9;
        ULONG64 PhysAddr : 40;
        ULONG64 reserved2 : 12;
    } Fields;
} EPT_PML4_ENTRY, EPT_MMPTE, * PEPT_PML4_ENTRY, * PEPT_MMPTE;

typedef union _EPT_PDE_LARGE_ENTRY
{
    ULONG64 All;
    struct
    {
        ULONG64 Present : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 MemoryType : 3;
        ULONG64 IgnorePat : 1;
        ULONG64 Size : 1;
        ULONG64 reserved1 : 13;
        ULONG64 PhysAddr : 40;
        ULONG64 reserved2 : 12
    } Fields;
} EPT_PDE_LARGE_ENTRY, * PEPT_PDE_LARGE_ENTRY;

typedef union _EPT_PTE_ENTRY
{
    ULONG64 All;
    struct
    {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 MemoryType : 3;
        ULONG64 IgnorePat : 1;
        ULONG64 reserved1 : 5;
        ULONG64 PhysAddr : 40;
        ULONG64 reserved2 : 12;
    } Fields;
} EPT_PTE_ENTRY, * PEPT_PTE_ENTRY;

typedef union _GUEST_PHYSICAL
{
    ULONG64 All;
    struct
    {
        ULONG64 offset : 12;
        ULONG64 pte : 9;
        ULONG64 pde : 9;
        ULONG64 pdpte : 9;
        ULONG64 pml4 : 9;
        ULONG64 reserved : 16;
    } Fields;
} GUEST_PHYSICAL, * PGUEST_PHYSICAL;

typedef union _EPT_VIOLATION_DATA
{
    ULONG64 All;
    struct
    {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 PTERead : 1;
        ULONG64 PTEWrite : 1;
        ULONG64 PTEExecute : 1;
        ULONG64 Reserved1 : 1;
        ULONG64 GuestLinear : 1;
        ULONG64 FailType : 1;
        ULONG64 Reserved2 : 3;
        ULONG64 NMIBlock : 1;
        ULONG64 Reserved3 : 51;
    } Fields;
} EPT_VIOLATION_DATA, * PEPT_VIOLATION_DATA;

struct _EPT_DATA;
#pragma pack(pop)
#pragma warning(default: 4214)

VOID EptEnable(IN PEPT_PML4_ENTRY PML4);

VOID EptDisable();

NTSTATUS EptBuildIdentityMap(IN struct _EPT_DATA* pEPT);

NTSTATUS EptFreeIdentityMap(IN struct _EPT_DATA* pEPT);

NTSTATUS EptUpdateTableRecursive(
    IN struct _EPT_DATA* pEPTData,
    IN PEPT_MMPTE pTable,
    IN EPT_TABLE_LEVEL level,
    IN ULONG64 pfn,
    IN EPT_ACCESS access,
    IN ULONG64 hostPFN,
    IN ULONG count
);

NTSTATUS EptGetPTEForPhysical(IN PEPT_PML4_ENTRY PML4, IN PHYSICAL_ADDRESS phys, OUT PEPT_PTE_ENTRY* pEntry);

typedef struct _VMM_EPT_PAGE_TABLE
{
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4_POINTER PML4[VMM_EPT_PML4E_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML2_ENTRY PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];
	LIST_ENTRY DynamicSplitList;
	LIST_ENTRY PageHookList;

} VMM_EPT_PAGE_TABLE, * PVMM_EPT_PAGE_TABLE;

#pragma warning(push, 0)
typedef struct _VMM_EPT_DYNAMIC_SPLIT
{
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];

	union
	{
		PEPT_PML2_ENTRY Entry;
		PEPT_PML2_POINTER Pointer;
	};

	LIST_ENTRY DynamicSplitList;

} VMM_EPT_DYNAMIC_SPLIT, * PVMM_EPT_DYNAMIC_SPLIT;
#pragma warning(pop, 0)

typedef struct _VMM_EPT_PAGE_HOOK
{
	DECLSPEC_ALIGN(PAGE_SIZE) CHAR FakePage[PAGE_SIZE];
	LIST_ENTRY PageHookList;
	SIZE_T PhysicalBaseAddress;
	PEPT_PML1_ENTRY TargetPage;
	EPT_PML1_ENTRY OriginalEntry;
	EPT_PML1_ENTRY ShadowEntry;
	EPT_PML1_ENTRY HookedEntry;
	PCHAR Trampoline;

} VMM_EPT_PAGE_HOOK, * PVMM_EPT_PAGE_HOOK;

extern "C" {


	typedef struct _VMX_VMM_CONTEXT VMX_VMM_CONTEXT, * PVMM_CONTEXT;

	typedef struct _VMM_PROCESSOR_CONTEXT VMM_PROCESSOR_CONTEXT, * PVMM_PROCESSOR_CONTEXT;

	typedef struct _VMEXIT_CONTEXT VMEXIT_CONTEXT, * PVMEXIT_CONTEXT;

	BOOL HvEptGlobalInitialize(PVMM_CONTEXT GlobalContext);

	BOOL HvEptLogicalProcessorInitialize(PVMM_PROCESSOR_CONTEXT ProcessorContext);

	VOID HvEptFreeLogicalProcessorContext(PVMM_PROCESSOR_CONTEXT ProcessorContext);

	VOID HvExitHandleEptViolation(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext);

	BOOL HvEptAddPageHook(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction);

	typedef struct _MTRR_RANGE_DESCRIPTOR
	{
		SIZE_T PhysicalBaseAddress;
		SIZE_T PhysicalEndAddress;
		UCHAR MemoryType;
	} MTRR_RANGE_DESCRIPTOR, * PMTRR_RANGE_DESCRIPTOR;

    struct EptData;
    struct ProcessorFakePageData;
    struct SharedFakePageData;

    union EptCommonEntry {
        ULONG64 all;
        struct {
            ULONG64 read_access : 1;       //!< [0]
            ULONG64 write_access : 1;      //!< [1]
            ULONG64 execute_access : 1;    //!< [2]
            ULONG64 memory_type : 3;       //!< [3:5]
            ULONG64 reserved1 : 6;         //!< [6:11]
            ULONG64 physial_address : 36;  //!< [12:48-1]
            ULONG64 reserved2 : 16;        //!< [48:63]
        } fields;
    };
    static_assert(sizeof(EptCommonEntry) == 8, "Size check");

    _IRQL_requires_max_(PASSIVE_LEVEL) bool EptIsEptAvailable();

    ULONG64 EptGetEptPointer(_In_ EptData* ept_data);

    _IRQL_requires_max_(PASSIVE_LEVEL) void EptInitializeMtrrEntries();

    _IRQL_requires_max_(PASSIVE_LEVEL) EptData* EptInitialization();

    void EptTermination(_In_ EptData* ept_data);

    _IRQL_requires_min_(DISPATCH_LEVEL) void EptHandleEptViolation(
        _In_ EptData* ept_data, _In_ ProcessorFakePageData* fp_data,
        _In_ SharedFakePageData* shared_fp_data);

    EptCommonEntry* EptGetEptPtEntry(_In_ EptData* ept_data,
        _In_ ULONG64 physical_address);

	VOID
		EptSetPageAccess(
			__in struct vt_ept* Ept,
			__in BOOLEAN Write,
			__in ULONG64 GuestPhys,
			__in ULONG Access,
			__in_opt PKSPIN_LOCK SpinLock
		);

	NTSTATUS
		SwitchToEPTOriginal(
			__inout PVMM_INIT_STATE VMMInitState
		);

	NTSTATUS
		SwitchToEPTShadow(
			__inout PVMM_INIT_STATE VMMInitState
		);

}  // extern "C"

#endif  // EPT_H_