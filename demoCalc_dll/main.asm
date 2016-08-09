; Demo DLL - deploys calc on load 

.386
.model flat,stdcall
option casemap:none

include windows.inc
include kernel32.inc
Include shell32.inc

includelib kernel32.lib
includelib SHELL32.LIB

.data
szOpen DB "open",0
szCalcPath db "%SystemRoot%\\system32\\calc.exe",0

.code
DeployCalc proc
    Local Buffer[MAX_PATH]:BYTE

    invoke ExpandEnvironmentStrings, OFFSET szCalcPath, ADDR Buffer, MAX_PATH
    Invoke ShellExecute, NULL,Offset szOpen, ADDR Buffer ,NULL, NULL, SW_SHOWNORMAL
    ret
DeployCalc endp

DllEntry proc hInstance:HINSTANCE, reason:DWORD, reserved1:DWORD
    .if reason == DLL_PROCESS_ATTACH
        invoke DeployCalc
    .endif
    mov  eax, TRUE
    ret
DllEntry Endp

End DllEntry
