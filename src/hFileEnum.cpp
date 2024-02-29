#include <iostream>
#include <winternl.h>
#include <Windows.h>

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


int main()
{
    ULONG retLen = 0;
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 2);
    NtQuerySystemInformation(0x10, handleTableInformation, 1024 * 1024 * 2, &retLen);

    for (int i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];
        if (handleInfo.ObjectTypeIndex == 28) {
            printf("[+] Found File Handle at 0x%p, PID : %ld\n" , handleInfo.Object , handleInfo.UniqueProcessId);
        }
    }

    return 0;
}