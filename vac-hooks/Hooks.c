#include "Hooks.h"
#include "Utils.h"

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE result = LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "GetProcAddress", Hooks_GetProcAddress);
    return result;
}

FARPROC WINAPI Hooks_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC result = GetProcAddress(hModule, lpProcName);
    if (!strcmp(lpProcName, "GetProcAddress"))
        return (FARPROC)Hooks_GetProcAddress;
    return result;
}
