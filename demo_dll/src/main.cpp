#include "main.h"
#define TEST_NAME "Test DLL"

DWORD __stdcall Test1(void)
{
    MessageBox(NULL, "Test1 called!", TEST_NAME, MB_ICONINFORMATION);
    return 1;
}

DWORD __stdcall Test2(int id)
{
    MessageBox(NULL, "Test2 called!", TEST_NAME, MB_ICONINFORMATION);
    return id * 2;
}

BOOL WINAPI DllMain (HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            {
                MessageBox(NULL, "Test DLL loaded!", TEST_NAME, MB_ICONINFORMATION);
                break;
            }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            MessageBox(NULL, "Test DLL unloaded!",TEST_NAME, MB_ICONINFORMATION);
            break;
    }
    return TRUE;
}

