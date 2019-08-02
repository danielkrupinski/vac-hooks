#pragma once

#include <Windows.h>
#define SECURITY_WIN32
#include <security.h>

HMODULE  WINAPI     Hooks_LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
FARPROC  WINAPI     Hooks_GetProcAddress(HMODULE, LPCSTR);
HANDLE   WINAPI     Hooks_OpenProcess(DWORD, BOOL, DWORD);
DWORD    WINAPI     Hooks_GetProcessImageFileNameA(HANDLE, LPSTR, DWORD);
int      WINAPI     Hooks_GetWindowTextW(HWND, LPWSTR, int);
BOOL     WINAPI     Hooks_QueryFullProcessImageNameW(HANDLE, DWORD, LPWSTR, PDWORD);
DWORD    WINAPI     Hooks_GetModuleBaseNameA(HANDLE, HMODULE, LPSTR, DWORD);
DWORD    WINAPI     Hooks_GetModuleBaseNameW(HANDLE, HMODULE, LPWSTR, DWORD);
DWORD    WINAPI     Hooks_GetModuleFileNameA(HMODULE, LPSTR, DWORD);
DWORD    WINAPI     Hooks_GetModuleFileNameExA(HANDLE, HMODULE, LPSTR, DWORD);
DWORD    WINAPI     Hooks_GetModuleFileNameExW(HANDLE, HMODULE, LPWSTR, DWORD);
BOOL     WINAPI     Hooks_GetComputerNameExW(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
HANDLE   WINAPI     Hooks_CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
NTSTATUS NTAPI      Hooks_NtOpenProcess(PHANDLE, ACCESS_MASK, PVOID, PVOID);
BOOL     WINAPI     Hooks_ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
int      WINAPI     Hooks_MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
BOOLEAN  SEC_ENTRY  Hooks_GetUserNameExW(EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
UINT     WINAPI     Hooks_GetDriveTypeW(LPCWSTR);
