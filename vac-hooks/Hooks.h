#pragma once

#include <Windows.h>

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
FARPROC WINAPI Hooks_GetProcAddress(HMODULE, LPCSTR);
HANDLE WINAPI Hooks_OpenProcess(DWORD, BOOL, DWORD);
DWORD WINAPI Hooks_GetProcessImageFileNameA(HANDLE, LPSTR, DWORD);
int WINAPI Hooks_GetWindowTextW(HWND, LPWSTR, int);
BOOL WINAPI Hooks_QueryFullProcessImageNameW(HANDLE, DWORD, LPWSTR, PDWORD);
DWORD WINAPI Hooks_GetModuleBaseNameA(HANDLE, HMODULE, LPSTR, DWORD);
