#include "main.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
    #include <stdint.h>
#else
    #include <inttypes.h>
#endif

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type: 4;
} BASE_RELOCATION_ENTRY;

//
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

	ZwCreateThreadEx = (NTSTATUS (NTAPI *) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID)) GetProcAddress(hNtdll,"NtCreateThreadEx");
	if (ZwCreateThreadEx == NULL) return FALSE;

	ZwUnmapViewOfSection = (NTSTATUS (NTAPI *) (HANDLE, PVOID)) GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
	if (ZwUnmapViewOfSection == NULL) return FALSE;

	ZwClose = (NTSTATUS (NTAPI *) (HANDLE)) GetProcAddress(hNtdll, "ZwClose");
	if (ZwClose == NULL) return FALSE;

	ZwTerminateProcess = (NTSTATUS (NTAPI *) (HANDLE, NTSTATUS)) GetProcAddress(hNtdll, "ZwTerminateProcess");
	if (ZwTerminateProcess == NULL) return FALSE;

	RtlImageNtHeader = (PIMAGE_NT_HEADERS (NTAPI *) (PVOID)) GetProcAddress(hNtdll, "RtlImageNtHeader");
	if (RtlImageNtHeader == NULL) return FALSE;

	return TRUE;
}

BOOL load_kernel32_functions()
{
	HMODULE hKernel32 = GetModuleHandleA("kernel32");
	CreateProcessInternalW = (BOOL (WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE)) GetProcAddress(hKernel32,"CreateProcessInternalW");
	if (CreateProcessInternalW == NULL) return FALSE;

	return TRUE;
}

BOOL applyRelocBlock(BASE_RELOCATION_ENTRY *block, size_t entriesNum, DWORD page, PVOID newBase, PVOID bufBase)
{
    PVOID ImageBaseAddress = NtCurrentTeb()->Peb->ImageBaseAddress;
    BASE_RELOCATION_ENTRY* entry = block;

    for (int i = 0; i < entriesNum; i++) {
        DWORD offset = entry->Offset;
        DWORD type = entry->Type;
        if (entry == NULL || type == 0 || offset == 0) {
            //printf("Applied relocations: %d\n", i);
            return TRUE; //finish
        }
        if (type != 3) { //for now only 32-bit field is supported
            printf("Not supported relocations format at %d: %d\n", i, type);
            return FALSE;
        }
        uint32_t* relocateAddr = (uint32_t*) ((ULONG_PTR) bufBase + page + offset);
        (*relocateAddr) = ((*relocateAddr) - (ULONG_PTR) ImageBaseAddress) + (ULONG_PTR) newBase;
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(uint16_t));
    }
    return TRUE;
}

BOOL applyRelocations(PIMAGE_NT_HEADERS NtHeaders, PVOID newBase, PVOID bufBase)
{
    PVOID ImageBaseAddress = NtCurrentTeb()->Peb->ImageBaseAddress;
    //fetch relocation table from current image:
    IMAGE_DATA_DIRECTORY relocDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == NULL) {
        printf ("Cannot relocate - the application have no relocation table!");
        return FALSE;
    }
    DWORD maxSize = relocDir.Size;
    DWORD parsedSize = 0;

    DWORD relocAddr = relocDir.VirtualAddress;
    IMAGE_BASE_RELOCATION* reloc = NULL;

    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR) ImageBaseAddress);
        parsedSize += reloc->SizeOfBlock;

        if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) {
            continue;
        }

        printf("relocBlock: %p %p\n", reloc->VirtualAddress, reloc->SizeOfBlock);
        
        size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(uint32_t))  / sizeof(uint16_t);
        DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) reloc + sizeof(uint32_t) + sizeof(uint32_t));
        if (applyRelocBlock(block, entriesNum, page, newBase, bufBase) == FALSE) {
            return FALSE;
        }
    }
    return TRUE;
}

void NTAPI testFunction(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    MessageBoxA(NULL, "Say hello to the Test Function!", "testFunction!", 0);
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

	PVOID ImageBaseAddress = NtCurrentTeb()->Peb->ImageBaseAddress;

	PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBaseAddress);
	if (NtHeaders == NULL)
	{
		printf("[ERROR] RtlImageNtHeader failed, error : %d\n", GetLastError());
		system("pause");
		return (-1);
	}

	LARGE_INTEGER MaximumSize;
	ULONG ImageSize = NtHeaders->OptionalHeader.SizeOfImage;

	MaximumSize.LowPart = ImageSize;
	MaximumSize.HighPart = 0;

	NTSTATUS Status = NULL;
	if ((Status = ZwCreateSection( &hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS)
	{
		printf("[ERROR] ZwCreateSection failed, status : %x\n", Status);
		system("pause");
		return (-1);
	}

    HANDLE hProcess = NULL;
    PVOID sectionBaseAddress = NULL;
    SIZE_T viewSize = 0;
    DWORD inheritDisposition = 1; //VIEW_SHARE

    // map the section in context of current process:
    if ((Status = NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE))!= STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", Status);
        system("pause");
        return (-1);
    }
	printf("New section, BaseAddress: %p ViewSize: %p\n", sectionBaseAddress, viewSize);
    printf("Mapping into: %p <- current image: %p %p\n", sectionBaseAddress, ImageBaseAddress, ImageSize);
    //copy full current image into a new section:
    RtlCopyMemory(sectionBaseAddress, ImageBaseAddress, ImageSize);
    printf("Content copied!\n");

    // map the new section into context of opened process
    printf("Mapping the new section into context of opened process...\n");
    PVOID sectionBaseAddress2 = NULL;

    if ((Status = NtMapViewOfSection(hSection, pi.hProcess, &sectionBaseAddress2, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE))!= STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", Status);
        system("pause");
        return (-1);
    }

    printf("Section mapped at address: %p\n", sectionBaseAddress2);
    //apply relocations
    printf("Applying relocations...\n");
    if (applyRelocations(NtHeaders, sectionBaseAddress2, sectionBaseAddress) == FALSE) {
        printf("Applying relocations failed, cannot continue!");
        ZwTerminateProcess(pi.hProcess, STATUS_FAILURE);
        ZwTerminateProcess(GetCurrentProcess(), STATUS_FAILURE);
    }
    printf("Relocations applied!\n");

    ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);
    ZwClose(hSection);
    hSection = NULL;

    ULONG_PTR offsetFromBase = (ULONG_PTR) &testFunction - (ULONG_PTR)ImageBaseAddress;
    printf("testFunction offset: %p\n", offsetFromBase);

    ULONG_PTR newMain = ((ULONG_PTR) sectionBaseAddress2 + offsetFromBase);

    // inject to the main thread
    if ((Status = NtQueueApcThread(pi.hThread, (PVOID) newMain, 0, 0, 0)) != STATUS_SUCCESS)
    {
        printf("[ERROR] NtQueueApcThread failed, status : %x\n", Status);
        system("pause");
        return (-1);
    }
    ZwSetInformationThread(pi.hThread, 1, 0, 0);
    
    printf("Resuming main thread...\n");
    ResumeThread(pi.hThread);

    //close handles:
    ZwClose(pi.hThread);
    ZwClose(pi.hProcess);
    system("pause");
    ZwTerminateProcess(GetCurrentProcess(), STATUS_SUCCESS);
}