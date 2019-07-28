#include "Hooks.h"

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    return LoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

FARPROC WINAPI Hooks_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return GetProcAddress(hModule, lpProcName);
}
