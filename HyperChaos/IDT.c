#include <wdm.h>

typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned char BYTE;

typedef struct
{
    WORD IDTLimit;
    WORD LowIDTbase;
    WORD HiIDTbase;
} IDTINFO;

#define MAKELONG(a, b)((LONG)(((WORD)(a))|((DWORD)((WORD)(b))) << 16))
#define MAKELOW(a) ((WORD) a)
#define MAKEHIGH(a) ((WORD) ((LONG) ( ((LONG)a) >> 16) ))

#pragma pack(1)
typedef struct
{
    WORD LowOffset;
    WORD selector;
    BYTE unused_lo;
    unsigned char unused_hi : 5;
    unsigned char DPL : 2;
    unsigned char P : 1;
    WORD HiOffset;
} IDTENTRY;
#pragma pack()

void (*SaveInterrupt1ToHook)();
void (*SaveInterrupt3ToHook)();
IDTENTRY* OurInterrupt1ToHook;
IDTENTRY* OurInterrupt3ToHook;


__declspec(naked) HookInt1()
{
    __asm {
        iretd
    }
}

void HookInt3()
{
    __asm {
        iretd
    }
}

void HookIDT()
{
    IDTINFO IdtInfo;
    IDTENTRY* BeginArray;

    __asm {
        push ecx
        lea ecx, IdtInfo
        sidt fword ptr[ecx]
        pop ecx
    }

    BeginArray = (PVOID)((IdtInfo.LowIDTbase) | ((ULONG)IdtInfo.HiIDTbase << 16));

    SaveInterrupt1ToHook = (unsigned long)MAKELONG(BeginArray[0x01].LowOffset, BeginArray[0x01].HiOffset);
    OurInterrupt1ToHook = (IDTENTRY*)&(BeginArray[0x01]);
    SaveInterrupt3ToHook = (unsigned long)MAKELONG(BeginArray[0x03].LowOffset, BeginArray[0x03].HiOffset);
    OurInterrupt3ToHook = (IDTENTRY*)&(BeginArray[0x03]);

    OurInterrupt1ToHook->LowOffset = MAKELOW(HookInt1);
    OurInterrupt1ToHook->HiOffset = MAKEHIGH(HookInt1);
    OurInterrupt3ToHook->LowOffset = MAKELOW(HookInt3);
    OurInterrupt3ToHook->HiOffset = MAKEHIGH(HookInt3);
}