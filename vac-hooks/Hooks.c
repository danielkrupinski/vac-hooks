#include <stdio.h>

#include "Hooks.h"
#include "Utils.h"

#define LOG_FILENAME "vac-hooks.txt"
#define LOG_BUFFER_SIZE 500

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE result = LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    FILE* out;

    if (fopen_s(&out, LOG_FILENAME, "a")) {
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
    if (!strcmp(lpProcName, "GetProcAddress"))
        return (FARPROC)Hooks_GetProcAddress;
    else if (!strcmp(lpProcName, "OpenProcess"))
        return (FARPROC)Hooks_OpenProcess;
    return result;
}

HANDLE WINAPI Hooks_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    HANDLE result = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    return result;
}
