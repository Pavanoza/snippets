// Performs defensive environment check - against VM, sandbox, monitoring tools etc.
// CC-BY: hasherezade
// implementation based on: Neutrino Bot Loader
// read more: https://blog.malwarebytes.com/threat-analysis/2017/02/new-neutrino-bot-comes-in-a-protective-loader/

#include <stdio.h>

#include <Windows.h>
#include <psapi.h>
#include <TlHelp32.h>

#include <set>

FILE *logFile = NULL;

void log_checksum(DWORD checksum, char *name)
{
    printf("%08X : %s\n", checksum, name);

    if (logFile == NULL) return;
    fprintf(logFile, "%08X : %s\n", checksum, name);
}

inline DWORD rotl32a(DWORD x, DWORD n)
{
    return (x<<n) | (x>>(32-n));
}

inline char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        c = c - 'A' + 'a';
    }
    return c;
}

DWORD calc_checksum(char *str, bool enable_tolower)
{
    if (str == NULL) return 0;

    DWORD checksum = 0;
    size_t len = strlen(str);
    for (int i = 0; i < len; i++) {
        checksum = rotl32a(checksum, 7);
        char c = str[i];
        if (enable_tolower) {
            c = to_lower(c);
        }
        checksum ^= c;
    }
    return checksum;
}

size_t find_blacklisted_processes(std::set<DWORD> &process_blacklist, bool enable_tolower)
{
    size_t found = 0;
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    PROCESSENTRY32 process_entry = { 0 };
    process_entry.dwSize = sizeof(process_entry);

    if (!Process32First(hProcessSnapShot, &process_entry)) {
        return 0;
    }

    DWORD checksum = calc_checksum(process_entry.szExeFile, enable_tolower);
    if (process_blacklist.find(checksum) != process_blacklist.end()){
        log_checksum(checksum, process_entry.szExeFile);
        found++;
    }

    while (Process32Next(hProcessSnapShot, &process_entry)) {
        checksum = calc_checksum(process_entry.szExeFile, enable_tolower);
        if (process_blacklist.find(checksum) != process_blacklist.end()) {
            log_checksum(checksum, process_entry.szExeFile);
            found++;
        }
    }

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return found;
}

size_t find_blacklisted_modules(std::set<DWORD> &blacklist, bool enable_tolower)
{
    size_t found = 0;
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, GetCurrentProcessId());
    MODULEENTRY32 module_entry = { 0 };
    module_entry.dwSize = sizeof(module_entry);

    if (!Module32First(hProcessSnapShot, &module_entry)) {
        return 0;
    }

    DWORD checksum = calc_checksum(module_entry.szModule, enable_tolower);
    if (blacklist.find(checksum) != blacklist.end()) {
        found++;
        log_checksum(checksum, module_entry.szModule);
    }

    while (Module32Next(hProcessSnapShot, &module_entry)) {
        checksum = calc_checksum(module_entry.szModule, enable_tolower);
        if (blacklist.find(checksum) != blacklist.end()) {
            found++;
            log_checksum(checksum, module_entry.szModule);
        }
    }

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return found;
}

size_t find_blacklisted_devices(std::set<DWORD> &devs_blacklist)
{
    size_t found = 0;
    char dev[0x20000] = { 0 };
    char dev2[0x2000] = { 0 };
    DWORD res = QueryDosDeviceA(0, dev, 0x20000);

    char* ptr = dev;
    DWORD total_len = 0;

    while (total_len < res) {
        DWORD res2 = QueryDosDeviceA(ptr, dev2, sizeof(dev2));
        if (!res2) break;

        DWORD checksum = calc_checksum(ptr, false);
        if (devs_blacklist.find(checksum) != devs_blacklist.end()) {
            log_checksum(checksum, ptr);
            found++;
        }
        size_t len = strlen(ptr) + 1;
        ptr += len;
        total_len += len;
    }
    return found;
}

BOOL CALLBACK check_window(HWND hWnd, LPARAM lParam)
{
    bool hide_found_window = false;
    if (lParam == NULL) {
        return FALSE;
    }

    std::set<DWORD>* class_blacklist = (std::set<DWORD>*) lParam;

    char class_name[MAX_PATH];
    GetClassName(hWnd, class_name, MAX_PATH);

    DWORD checksum = calc_checksum(class_name, true);
    if (class_blacklist->find(checksum) != class_blacklist->end()) {
        log_checksum(checksum, class_name);

        if (hide_found_window) {
            ShowWindow(hWnd, SW_HIDE);
        } else {
            ShowWindow(hWnd, SW_SHOW);
        }
    }
    return TRUE;
}

int main(int argc, char *argv[])
{
    size_t found = 0;
    logFile = fopen("logfile.txt", "w");

    std::set<DWORD> process_blacklist;
    process_blacklist.insert(0x6169078A);
    process_blacklist.insert(0x47000343);
    process_blacklist.insert(0xC608982D);
    process_blacklist.insert(0x46EE4F10);
    process_blacklist.insert(0xF6EC4B30);
    process_blacklist.insert(0xB1CBC652); // VBoxService.exe
    process_blacklist.insert(0x6D3E6FDD); // VBoxTray.exe
    process_blacklist.insert(0x583EB7E8);
    process_blacklist.insert(0xC03EAA65);

    found = find_blacklisted_processes(process_blacklist, false);
    found += find_blacklisted_processes(process_blacklist, true);
    printf("Found blacklisted processes: %d\n", found);

    std::set<DWORD> module_blacklist;
    module_blacklist.insert(0x1C669D6A);
    module_blacklist.insert(0xC2F56A18);
    module_blacklist.insert(0x7457D9DD);
    module_blacklist.insert(0xC106E17B);
    module_blacklist.insert(0x5608BCC4);
    module_blacklist.insert(0x6512F9D0);
    module_blacklist.insert(0xC604D52A); // snxhk.dll
    module_blacklist.insert(0x4D0651A5);
    module_blacklist.insert(0xAC12B9FB); // sbiedll.dll
    module_blacklist.insert(0x5B747561);
    module_blacklist.insert(0x53309C85);
    module_blacklist.insert(0xE53ED522);

    found = find_blacklisted_modules(module_blacklist, false);
    found += find_blacklisted_modules(module_blacklist, true);
    printf("Found blacklisted modules: %d\n", found);

    std::set<DWORD> devs_blacklist;
    devs_blacklist.insert(0x642742FF); // VBoxMiniRdrDN
    devs_blacklist.insert(0x283CC630); // VBoxGuest
    devs_blacklist.insert(0x911E353);
    devs_blacklist.insert(0xEDB71E9);
    found = find_blacklisted_devices(devs_blacklist);
    printf("Found blacklisted devices: %d\n", found);

    std::set<DWORD> class_blacklist;
    class_blacklist.insert(0xFE9EA0D5);
    class_blacklist.insert(0x6689BB92);
    class_blacklist.insert(0x3C5FF312); // procexpl
    class_blacklist.insert(0x9B5A88D9); // procmon_window_class
    class_blacklist.insert(0x4B4576B5);
    class_blacklist.insert(0xAED304FC);
    class_blacklist.insert(0x225FD98F);
    class_blacklist.insert(0x6D3FA1CA);
    class_blacklist.insert(0xCF388E01);
    class_blacklist.insert(0xD486D951);
    class_blacklist.insert(0x39177889);
    EnumWindows(&check_window, (LPARAM)&class_blacklist);

    fclose(logFile);
    system("pause");
    return 0;
}
