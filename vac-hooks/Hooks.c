#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

#include "Hooks.h"
#include "Utils.h"

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE result = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

    Utils_log("LoadLibraryExW(lpLibFileName: %ws, hFile: %p, dwFlags: %d) -> HMODULE: %p\n", lpLibFileName, hFile, dwFlags, result);

    Utils_hookImport(lpLibFileName, "kernel32.dll", "GetProcAddress", Hooks_GetProcAddress);
    return result;
}

FARPROC WINAPI Hooks_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC result = GetProcAddress(hModule, lpProcName);

    Utils_log("GetProcAddress(hModule: %p, lpProcName: %s) -> FARPROC: %p \n", hModule, lpProcName, result);

    if (!strcmp(lpProcName, "GetProcAddress"))
        return (FARPROC)Hooks_GetProcAddress;
    else if (!strcmp(lpProcName, "OpenProcess"))
        return (FARPROC)Hooks_OpenProcess;
    else if (!strcmp(lpProcName, "GetProcessImageFileNameA"))
        return (FARPROC)Hooks_GetProcessImageFileNameA;
    else if (!strcmp(lpProcName, "GetWindowTextW"))
        return (FARPROC)Hooks_GetWindowTextW;
    else if (!strcmp(lpProcName, "QueryFullProcessImageNameW"))
        return (FARPROC)Hooks_QueryFullProcessImageNameW;
    else if (!strcmp(lpProcName, "GetModuleBaseNameA"))
        return (FARPROC)Hooks_GetModuleBaseNameA;
    else if (!strcmp(lpProcName, "GetModuleBaseNameW"))
        return (FARPROC)Hooks_GetModuleBaseNameW;
    else if (!strcmp(lpProcName, "GetModuleFileNameA"))
        return (FARPROC)Hooks_GetModuleFileNameA;
    else if (!strcmp(lpProcName, "GetModuleFileNameExA"))
        return (FARPROC)Hooks_GetModuleFileNameExA;
    else if (!strcmp(lpProcName, "GetModuleFileNameExW"))
        return (FARPROC)Hooks_GetModuleFileNameExW;
    else if (!strcmp(lpProcName, "GetComputerNameExW"))
        return (FARPROC)Hooks_GetComputerNameExW;
    else if (!strcmp(lpProcName, "CreateRemoteThread"))
        return (FARPROC)Hooks_CreateRemoteThread;
    else if (!strcmp(lpProcName, "NtOpenProcess"))
        return (FARPROC)Hooks_NtOpenProcess;
    else if (!strcmp(lpProcName, "ReadProcessMemory"))
        return (FARPROC)Hooks_ReadProcessMemory;

    return result;
}

HANDLE WINAPI Hooks_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    HANDLE result = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

    Utils_log("OpenProcess(dwDesiredAccess: %d, bInheritHandle: %d, dwProcessId: %d) -> HANDLE: %p\n", dwDesiredAccess, bInheritHandle, dwProcessId, result);

    return result;
}

DWORD WINAPI Hooks_GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize)
{
    DWORD result = GetProcessImageFileNameA(hProcess, lpImageFileName, nSize);

    Utils_log("GetProcessImageFileNameA(hProcess: %p, lpImageFileName: %s, nSize: %d) -> DWORD: %d\n", hProcess, lpImageFileName, nSize, result);

    return result;
}

int WINAPI Hooks_GetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
    int result = GetWindowTextW(hWnd, lpString, nMaxCount);

    Utils_log("GetWindowTextW(hWnd: %p, lpString: %ws, nMaxCount: %d) -> int %d\n", hWnd, lpString, nMaxCount, result);

    return result;
}

BOOL WINAPI Hooks_QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize)
{
    BOOL result = QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);

    Utils_log("QueryFullProcessImageNameW(hProcess: %p, dwFlags: %d, lpExeName: %ws, lpdwSize: %p) -> BOOL: %d\n", hProcess, dwFlags, lpExeName, lpdwSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleBaseNameA(HANDLE hProcess, HMODULE hModule, LPSTR lpBaseName, DWORD nSize)
{
    DWORD result = GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize);

    Utils_log("GetModuleBaseNameA(hProcess: %p, hModule: %p, lpBaseName: %s, nSize: %d) -> DWORD: %d\n", hProcess, hModule, lpBaseName, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleBaseNameW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize)
{
    DWORD result = GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize);

    Utils_log("GetModuleBaseNameW(hProcess: %p, hModule: %p, lpBaseName: %ws, nSize: %d) -> DWORD: %d\n", hProcess, hModule, lpBaseName, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    DWORD result = GetModuleFileNameA(hModule, lpFilename, nSize);

    Utils_log("GetModuleFileNameA(hModule: %p, lpFilename: %s, nSize: %d) -> DWORD: %d\n", hModule, lpFilename, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    DWORD result = GetModuleFileNameExA(hProcess, hModule, lpFilename, nSize);

    Utils_log("GetModuleFileNameExA(hProcess: %p, hModule: %p, lpFilename: %s, nSize: %d) -> DWORD: %d\n", hProcess, hModule, lpFilename, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    DWORD result = GetModuleFileNameExW(hProcess, hModule, lpFilename, nSize);

    Utils_log("GetModuleFileNameExW(hProcess: %p, hModule: %p, lpFilename: %ws, nSize: %d) -> DWORD: %d\n", hProcess, hModule, lpFilename, nSize, result);

    return result;
}

BOOL WINAPI Hooks_GetComputerNameExW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize)
{
    BOOL result = GetComputerNameExW(NameType, lpBuffer, nSize);

    Utils_log("GetComputerNameExW(NameType: %d, lpBuffer: %ws, nSize: %d) -> BOOL: %d\n", NameType, lpBuffer, *nSize, result);

    return result;
}

HANDLE WINAPI Hooks_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    HANDLE result = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    Utils_log("CreateRemoteThread(hProcess: %p, lpThreadAttributes: %p, dwStackSize: %d, lpStartAddress: %p, lpParameter: %p, dwCreationFlags: %d, lpThreadId: %p) -> HANDLE: %p\n", hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId)
{
    NTSTATUS(NTAPI* NtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PVOID) = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtOpenProcess");
    NTSTATUS result = NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    Utils_log("NtOpenProcess(ProcessHandle: %p, DesiredAccess: %d, ObjectAttributes: %p, ClientId: %p) -> NTSTATUS: %l\n", ProcessHandle, DesiredAccess, ObjectAttributes, ClientId, result);

    return result;
}

BOOL WINAPI Hooks_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    BOOL result = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    Utils_log("ReadProcessMemory(hProcess: %p, lpBaseAddress: %p, lpBuffer: %p, nSize: %d, lpNumberOfBytesRead: %p) -> BOOL: %d\n", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead, result);

    return result;
}
