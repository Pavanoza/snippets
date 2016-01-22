#pragma once

#include <stdio.h>
#include <Windows.h>

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined THREADINFOCLASS
typedef LONG THREADINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB *PPEB;
#endif

#if !defined PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif;

typedef LONG NTSTATUS, *PNTSTATUS;
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (WINAPI * PFN_ZWQUERYINFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS,
    PVOID, ULONG, PULONG);

//ntdll api:
NTSTATUS (NTAPI *ZwQueryInformationProcess)(
  HANDLE  ProcessHandle,
  PROCESSINFOCLASS  ProcessInformationClass,
  PVOID  ProcessInformation,
  ULONG  ProcessInformationLength,
  PULONG  ReturnLength  OPTIONAL
);

NTSTATUS (NTAPI *ZwCreateSection)(
    _Out_    PHANDLE            SectionHandle, 
    _In_     ACCESS_MASK        DesiredAccess, 
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER     MaximumSize,
    _In_     ULONG              SectionPageProtection,
    _In_     ULONG              AllocationAttributes, 
    _In_opt_ HANDLE             FileHandle
);


NTSTATUS (NTAPI *NtMapViewOfSection)(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID           *BaseAddress,
    _In_        ULONG_PTR       ZeroBits, 
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset, 
    _Inout_     PSIZE_T         ViewSize,
    _In_        DWORD InheritDisposition, 
    _In_        ULONG           AllocationType, 
    _In_        ULONG           Win32Protect
);

NTSTATUS (NTAPI *ZwCreateThreadEx) (
    _Out_ PHANDLE ThreadHandle, 
    _In_ ACCESS_MASK DesiredAccess, 
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, 
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_opt_ ULONG_PTR ZeroBits, 
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize, 
    _In_opt_ PVOID AttributeList 
);

NTSTATUS (NTAPI *ZwUnmapViewOfSection) (
    _In_     HANDLE ProcessHandle,
    _In_opt_ PVOID  BaseAddress
);

NTSTATUS (NTAPI *ZwClose) (
    _In_ HANDLE Handle
);

NTSTATUS (NTAPI *ZwTerminateProcess) (
  _In_opt_ HANDLE   ProcessHandle,
  _In_     NTSTATUS ExitStatus
);

NTSTATUS (NTAPI *NtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_ PVOID ApcRoutineContext OPTIONAL,
    _In_ PVOID ApcStatusBlock OPTIONAL,
    _In_ ULONG ApcReserved OPTIONAL
);

NTSTATUS (NTAPI *ZwSetInformationThread) (
  _In_ HANDLE ThreadHandle,
  _In_ THREADINFOCLASS ThreadInformationClass,
  _In_ PVOID ThreadInformation,
  _In_ ULONG ThreadInformationLength
);

//kernel32 api
BOOL 
(WINAPI *CreateProcessInternalW)(HANDLE hToken, 
    LPCWSTR lpApplicationName, 
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags, 
    LPVOID lpEnvironment, 
    LPCWSTR lpCurrentDirectory, 
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken
    );

