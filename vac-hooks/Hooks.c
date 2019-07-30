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
        sprintf_s(buf, sizeof(buf), "LoadLibraryExW(lpLibFileName: %ws, hFile: %p, dwFlags: %d)\n", lpLibFileName, hFile, dwFlags);
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
        sprintf_s(buf, sizeof(buf), "GetProcAddress(hModule: %d, lpProcName: %s)\n", (DWORD)hModule, lpProcName);
        fprintf(out, buf);
        fclose(out);
    }

    if (!strcmp(lpProcName, "GetProcAddress"))
        return (FARPROC)Hooks_GetProcAddress;
    else if (!strcmp(lpProcName, "OpenProcess"))
        return (FARPROC)Hooks_OpenProcess;
    else if (!strcmp(lpProcName, "GetProcessImageFileNameA"))
        return (FARPROC)Hooks_GetProcessImageFileNameA;

    return result;
}

HANDLE WINAPI Hooks_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    HANDLE result = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    FILE* out;

    if (!fopen_s(&out, LOG_FILENAME, "a")) {
        CHAR buf[LOG_BUFFER_SIZE];
        sprintf_s(buf, sizeof(buf), "OpenProcess(dwDesiredAccess: %d, bInheritHandle: %d, dwProcessId: %d)\n", dwDesiredAccess, bInheritHandle, dwProcessId);
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
        sprintf_s(buf, sizeof(buf), "GetProcessImageFileNameA(hProcess: %p, lpImageFileName: %s, nSize: %d)\n", hProcess, lpImageFileName, nSize);
        fprintf(out, buf);
        fclose(out);
    }

    return result;
}
