#include <windows.h>

extern "C" {
    DWORD  __declspec(dllexport) __stdcall Test1(void);
    DWORD  __declspec(dllexport) __stdcall Test2(DWORD id);
};
