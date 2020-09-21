#ifndef _CPU_H_
#define _CPU_H_

#define X86_CR0_PE              0x00000001
#define X86_CR0_MP              0x00000002
#define X86_CR0_EM              0x00000004
#define X86_CR0_TS              0x00000008
#define X86_CR0_ET              0x00000010
#define X86_CR0_NE              0x00000020
#define X86_CR0_WP              0x00010000
#define X86_CR0_AM              0x00040000
#define X86_CR0_NW              0x20000000
#define X86_CR0_CD              0x40000000
#define X86_CR0_PG              0x80000000 
#define X86_CR4_VME		0x0001 
#define X86_CR4_PVI		0x0002
#define X86_CR4_TSD		0x0004
#define X86_CR4_DE		0x0008
#define X86_CR4_PSE		0x0010  /* enable page size extensions */
#define X86_CR4_PAE		0x0020  /* enable physical address extensions */
#define X86_CR4_MCE		0x0040  /* Machine check enable */
#define X86_CR4_PGE		0x0080  /* enable global pages */
#define X86_CR4_PCE		0x0100  /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200  /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400  /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

typedef struct _EFLAGS
{
	unsigned Reserved1 : 10;
	unsigned ID : 1;
	unsigned VIP : 1;
	unsigned VIF : 1;
	unsigned AC : 1;
	unsigned VM : 1;
	unsigned RF : 1;
	unsigned Reserved2 : 1;
	unsigned NT : 1;
	unsigned IOPL : 2;
	unsigned OF : 1;
	unsigned DF : 1;
	unsigned IF : 1;
	unsigned TF : 1;
	unsigned SF : 1;
	unsigned ZF : 1;
	unsigned Reserved3 : 1;
	unsigned AF : 1;
	unsigned Reserved4 : 1;
	unsigned PF : 1;
	unsigned Reserved5 : 1;
	unsigned CF : 1;
} EFLAGS;

typedef union _RFLAGS
{
	struct
	{
		unsigned Reserved1 : 10;
		unsigned ID : 1;
		unsigned VIP : 1;
		unsigned VIF : 1;
		unsigned AC : 1;
		unsigned VM : 1;		// Virtual 8086 mode
		unsigned RF : 1;
		unsigned Reserved2 : 1;
		unsigned NT : 1;
		unsigned IOPL : 2;		// I/O privilege level
		unsigned OF : 1;
		unsigned DF : 1;
		unsigned IF : 1;		// Interrupt flag
		unsigned TF : 1;
		unsigned SF : 1;
		unsigned ZF : 1;
		unsigned Reserved3 : 1;
		unsigned AF : 1;
		unsigned Reserved4 : 1;
		unsigned PF : 1;
		unsigned Reserved5 : 1;
		unsigned CF : 1;
		unsigned Reserved6 : 32;
	};

	ULONG64 Content;
} RFLAGS;

#define FLAGS_CF_MASK (1 << 0)
#define FLAGS_PF_MASK (1 << 2)
#define FLAGS_AF_MASK (1 << 4)
#define FLAGS_ZF_MASK (1 << 6)
#define FLAGS_SF_MASK (1 << 7)
#define FLAGS_TF_MASK (1 << 8)
#define FLAGS_IF_MASK (1 << 9)
#define FLAGS_RF_MASK (1 << 16)
#define FLAGS_TO_ULONG(f) (*(ULONG32*)(&f))

typedef union _CR0_REG
{
	struct
	{
		unsigned PE : 1;
		unsigned MP : 1;
		unsigned EM : 1;
		unsigned TS : 1;
		unsigned ET : 1;
		unsigned NE : 1;
		unsigned Reserved1 : 10;
		unsigned WP : 1;
		unsigned Reserved2 : 1;
		unsigned AM : 1;
		unsigned Reserved3 : 10;
		unsigned NW : 1;
		unsigned CD : 1;
		unsigned PG : 1;
#ifdef _AMD64_
		unsigned Reserved4 : 32;
#endif
	};

#ifdef _AMD64_
	ULONG64 Content;
#else
	ULONG32 Content;
#endif

} CR0_REG;

typedef union _CR4_REG
{
	struct
	{
		unsigned VME : 1;			// Virtual Mode Extensions
		unsigned PVI : 1;			// Protected-Mode Virtual Interrupts
		unsigned TSD : 1;			// Time Stamp Disable
		unsigned DE : 1;			// Debugging Extensions
		unsigned PSE : 1;			// Page Size Extensions
		unsigned PAE : 1;			// Physical Address Extension
		unsigned MCE : 1;			// Machine-Check Enable
		unsigned PGE : 1;			// Page Global Enable
		unsigned PCE : 1;			// Performance-Monitoring Counter Enable
		unsigned OSFXSR : 1;			// OS Support for FXSAVE/FXRSTOR
		unsigned OSXMMEXCPT : 1;			// OS Support for Unmasked SIMD Floating-Point Exceptions
		unsigned Reserved1 : 2;			// 
		unsigned VMXE : 1;			// Virtual Machine Extensions Enabled
		unsigned Reserved2 : 18;

#ifdef _AMD64_
		unsigned Reserved3 : 32;
#endif
	};

#ifdef _AMD64_
	ULONG64 Content;
#else
	ULONG32 Content;
#endif

} CR4_REG;

#define LA_ACCESSED		0x01
#define LA_READABLE		0x02 
#define LA_WRITABLE		0x02
#define LA_CONFORMING	0x04
#define LA_EXPANDDOWN	0x04
#define LA_CODE			0x08
#define LA_STANDARD		0x10
#define LA_DPL_0		0x00
#define LA_DPL_1		0x20
#define LA_DPL_2		0x40
#define LA_DPL_3		0x60
#define LA_PRESENT		0x80

#define LA_LDT64		0x02
#define LA_ATSS64		0x09
#define LA_BTSS64		0x0b
#define LA_CALLGATE64	0x0c
#define LA_INTGATE64	0x0e
#define LA_TRAPGATE64	0x0f

#define HA_AVAILABLE	0x01
#define HA_LONG			0x02
#define HA_DB			0x04
#define HA_GRANULARITY	0x08


#pragma pack (push, 1)

typedef union
{
	USHORT UCHARs;
	struct
	{
		USHORT type : 4;
		USHORT s : 1;
		USHORT dpl : 2;
		USHORT p : 1;

		USHORT avl : 1;
		USHORT l : 1;
		USHORT db : 1;
		USHORT g : 1;
		USHORT Gap : 4;

	} fields;
} SEGMENT_ATTRIBUTES;


typedef struct
{
	USHORT sel;
	SEGMENT_ATTRIBUTES attributes;
	ULONG32 limit;
	ULONG64 base;
} SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
	USHORT limit0;
	USHORT base0;
	UCHAR  base1;
	UCHAR  attr0;
	UCHAR  limit1attr1;
	UCHAR  base2;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

#pragma pack(pop)

NTSTATUS
GetSegmentDescriptor(
	__in PSEGMENT_SELECTOR SegmentSelector,
	__in USHORT Selector,
	__in PUCHAR GdtBase
);

NTSTATUS
VmxFillGuestSelectorData(
	__in PVOID GdtBase,
	__in ULONG Segreg,
	__in USHORT Selector
);
#endif