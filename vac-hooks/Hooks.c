#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

#include "Hooks.h"
#include "Utils.h"

#define LOG_FILENAME "vac-hooks.txt"
#define LOG_BUFFER_SIZE 500

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE result = LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "LoadLibraryExW(lpLibFileName: %ws, hFile: %p, dwFlags: %d) -> HMODULE: %p\n", lpLibFileName, hFile, dwFlags, result);
        fprintf(out, buf);
        fclose(out);
    }

    Utils_hookImport(lpLibFileName, "kernel32.dll", "GetProcAddress", Hooks_GetProcAddress);
    return result;
}

FARPROC WINAPI Hooks_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC result = GetProcAddress(hModule, lpProcName);

    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "GetProcAddress(hModule: %p, lpProcName: %s) -> FARPROC: %p \n", hModule, lpProcName, result);
        fprintf(out, buf);
        fclose(out);
    }

    if (!strcmp(lpProcName, "GetProcAddress"))
        return (FARPROC)Hooks_GetProcAddress;
    else if (!strcmp(lpProcName, "OpenProcess"))
        return (FARPROC)Hooks_OpenProcess;
    else if (!strcmp(lpProcName, "GetProcessImageFileNameA"))
        return (FARPROC)Hooks_GetProcessImageFileNameA;
    else if (!strcmp(lpProcName, "GetWindowTextW"))
        return (FARPROC)Hooks_GetWindowTextW;

    return result;
}

HANDLE WINAPI Hooks_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    HANDLE result = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "OpenProcess(dwDesiredAccess: %d, bInheritHandle: %d, dwProcessId: %d) -> HANDLE: %p\n", dwDesiredAccess, bInheritHandle, dwProcessId, result);
        fprintf(out, buf);
        fclose(out);
    }

    return result;
}

DWORD WINAPI Hooks_GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize)
{
    DWORD result = GetProcessImageFileNameA(hProcess, lpImageFileName, nSize);

    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "GetProcessImageFileNameA(hProcess: %p, lpImageFileName: %s, nSize: %d) -> DWORD: %d\n", hProcess, lpImageFileName, nSize, result);
        fprintf(out, buf);
        fclose(out);
    }

    return result;
}

int WINAPI Hooks_GetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
    int result = GetWindowTextW(hWnd, lpString, nMaxCount);

    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "GetWindowTextW(hWnd: %p, lpString: %ws, nMaxCount: %d) -> int %d\n", hWnd, lpString, nMaxCount, result);
        fprintf(out, buf);
        fclose(out);
    }

    return result;
}

BOOL WINAPI Hooks_QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize)
{
    BOOL result = QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);

    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "QueryFullProcessImageNameW(hProcess: %p, dwFlags: %d, lpExeName: %ws, lpdwSize: %p) -> BOOL: %d\n", hProcess, dwFlags, lpExeName, lpdwSize, result);
        fprintf(out, buf);
        fclose(out);
    }

    return result;
}

DWORD WINAPI Hooks_GetModuleBaseNameA(HANDLE hProcess, HMODULE hModule, LPSTR lpBaseName, DWORD nSize)
{
    DWORD result = GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize);

    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "GetModuleBaseNameA(hProcess: %p, hModule: %p, lpBaseName: %s, nSize: %d) -> DWORD: %d\n", hProcess, hModule, lpBaseName, nSize, result);
        fprintf(out, buf);
        fclose(out);
    }

    return result;
}
