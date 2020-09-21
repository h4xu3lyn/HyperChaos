#include <wdm.h>

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
    unsigned int* ServiceTableBase;
    unsigned int* ServiceCounterTableBase;
    unsigned int NumberOfServices;
    unsigned char* ParamTableBase;
} SSDT_Entry;
#pragma pack()

__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable;

#define SYSTEMSERVICE(_func) \
  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_func+1)]

typedef NTSTATUS(*ZWSETVALUEKEY)( 
    HANDLE  KeyHandle,
    PUNICODE_STRING  ValueName,
    ULONG  TitleIndex  OPTIONAL,
    ULONG  Type,
    PVOID  Data,
    ULONG  DataSize
    );

ZWSETVALUEKEY ZwSetValueKeyOriginal;

NTSTATUS ZwSetValueKeyHook(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName,
    IN ULONG  TitleIndex  OPTIONAL,
    IN ULONG  Type,
    IN PVOID  Data,
    IN ULONG  DataSize
)
{
    PKEY_BASIC_INFORMATION pKeyInformation = NULL;
    int i, flag = 1;
    NTSTATUS ret;
    WCHAR targetKey1[] = L"Run";
    WCHAR targetKey2[] = L"RunOnce";
    unsigned long size = 0, sizeNeeded = 0;

    DbgPrint("[+] In da hook function =)\n");

    ret = ZwQueryKey(KeyHandle, KeyBasicInformation, pKeyInformation, size, &sizeNeeded); 
    if ((ret == STATUS_BUFFER_TOO_SMALL) || (ret == STATUS_BUFFER_OVERFLOW)) { 
        size = sizeNeeded;
        pKeyInformation = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeNeeded, 'aaaa');

        ret = ZwQueryKey(KeyHandle, KeyBasicInformation, pKeyInformation, size, &sizeNeeded);
    }

    if (ret != STATUS_SUCCESS)
        return ZwSetValueKeyOriginal(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

    if ((pKeyInformation->NameLength / sizeof(WCHAR)) == 3) {
        for (i = 0; i < strlen(targetKey1); i++) {
            if (pKeyInformation->Name[i] != targetKey1[i]) {
                flag = 0;
                break;
            }
        }
    }
    else if ((pKeyInformation->NameLength / sizeof(WCHAR)) == 7) { 
        for (i = 0; i < strlen(targetKey2); i++) {
            if (pKeyInformation->Name[i] != targetKey2[i]) {
                flag = 0;
                break;
            }
        }
    }
    else flag = 0;

    if (!flag)
        return ZwSetValueKeyOriginal(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

    DbgPrint("[+] Bypassing Run key writing\n");

    return STATUS_SUCCESS;
}

void HookSSDT()
{
    DbgPrint("[+] SSDTHOOK: in HookSSDT()\n");

    ZwSetValueKeyOriginal = (ZWSETVALUEKEY)SYSTEMSERVICE(ZwSetValueKey);

    __asm
    {
        push eax
        mov  eax, CR0
        and eax, 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }

    SYSTEMSERVICE(ZwSetValueKey) = (unsigned long*)ZwSetValueKeyHook; 

    __asm
    {
        push eax
        mov  eax, CR0
        or eax, NOT 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }

}

void UnHookSSDT()
{
    DbgPrint("[+] SSDTHOOK: in UnHookSSDT()\n");

    __asm
    {
        push eax
        mov  eax, CR0
        and eax, 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }


    SYSTEMSERVICE(ZwSetValueKey) = (ZWSETVALUEKEY)ZwSetValueKeyOriginal;

    __asm
    {
        push eax
        mov  eax, CR0
        or eax, NOT 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }

}