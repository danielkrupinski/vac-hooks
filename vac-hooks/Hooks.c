#include "Hooks.h"

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    return LoadLibraryExW(lpLibFileName, hFile, dwFlags);
}
