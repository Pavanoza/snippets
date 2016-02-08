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

BOOL applyRelocBlock(BASE_RELOCATION_ENTRY *block, size_t entriesNum, DWORD page, PVOID newBase)
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
        if (type != 3) {
            printf("Not supported relocations format at %d: %d\n", i, type);
            return FALSE;
        }
        uint32_t* relocateAddr = (uint32_t*) ((ULONG_PTR) newBase + page + offset);
        (*relocateAddr) = ((*relocateAddr) - (ULONG_PTR) ImageBaseAddress) + (ULONG_PTR) newBase;
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(uint16_t));
    }
    return TRUE;
}

BOOL applyRelocations(PIMAGE_NT_HEADERS NtHeaders, PVOID newBase)
{
    PVOID ImageBaseAddress = NtCurrentTeb()->Peb->ImageBaseAddress;
    //fetch relocation table from current image:
    IMAGE_DATA_DIRECTORY relocDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == NULL) {
        printf ("Cannot relocate - application have no relocation table!");
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

        printf("RelocBlock: %p %p\n", reloc->VirtualAddress, reloc->SizeOfBlock);
        
        size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(uint32_t))  / sizeof(uint16_t);
        DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) reloc + sizeof(uint32_t) + sizeof(uint32_t));
        if (applyRelocBlock(block, entriesNum, page, newBase) == FALSE) {
            return FALSE;
        }
        
    }
    return TRUE;
}

void NTAPI testFunction(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    MessageBoxA(NULL, "Say hello to the Test Function!", "testFunction!", 0);
}


int main(int argc, char *argv[])
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

  printf("Section handle: %x\n", hSection);

  HANDLE hProcess = NULL;
  PVOID pSectionBaseAddress = NULL;
  SIZE_T ViewSize = 0;
  DWORD dwInheritDisposition = 1; //VIEW_SHARE

  // map the section in context of current process:
  if ((Status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pSectionBaseAddress, NULL, NULL, NULL, &ViewSize, dwInheritDisposition, NULL, PAGE_EXECUTE_READWRITE))!= STATUS_SUCCESS)
  {
    printf("[ERROR] NtMapViewOfSection failed, status : %x\n", Status);
    system("pause");
    return (-1);
  }
    
  printf("Created new section, BaseAddress: %p ViewSize: %p\n", pSectionBaseAddress, ViewSize);
    printf("Mapping into: %p <- current image: %p %p\n", pSectionBaseAddress, ImageBaseAddress, ImageSize);
    RtlCopyMemory(pSectionBaseAddress, ImageBaseAddress, ImageSize);
    
    ZwClose(hSection);
    hSection = NULL;
    if (applyRelocations(NtHeaders, pSectionBaseAddress) == FALSE) {
        printf("Applying relocations failed, cannot continue!");
        ZwTerminateProcess(GetCurrentProcess(), STATUS_FAILURE);
    }
  printf("Applied relocations!\n");

    ULONG_PTR offsetFromBase = (ULONG_PTR) &testFunction - (ULONG_PTR)ImageBaseAddress;
    printf("testFunction offset: %p\n", offsetFromBase);

    ULONG_PTR newMain = ((ULONG_PTR) pSectionBaseAddress + offsetFromBase);
    printf("testFunction address in new section: %p\n", newMain);
    __asm {
        call newMain
    };
    system("pause");
    return (0);
}

