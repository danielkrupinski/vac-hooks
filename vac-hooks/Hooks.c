#include "Hooks.h"

#include <intrin.h>
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <sddl.h>
#include <SoftPub.h>
#include <TlHelp32.h>

#include "Functions.h"
#include "Utils.h"

#define LOG_FILTER FALSE

HMODULE WINAPI Hooks_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE result = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

    Utils_log("%ws: LoadLibraryExW(lpLibFileName: %ws, hFile: %p, dwFlags: %d) -> HMODULE: %p\n",
        Utils_getModuleName(_ReturnAddress()), lpLibFileName, hFile, dwFlags, result);

    PCSTR timestamp = Utils_getModuleTimestamp(result);
    if (timestamp)
        Utils_log("Loaded module %ws with timestamp: %s", lpLibFileName, timestamp);

    Utils_hookImport(lpLibFileName, "kernel32.dll", "GetProcAddress", Hooks_GetProcAddress);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "VirtualAlloc", Hooks_VirtualAlloc);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "VirtualFree", Hooks_VirtualFree);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "VirtualProtect", Hooks_VirtualProtect);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "GetModuleHandleA", Hooks_GetModuleHandleA);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "GetProcessHeap", Hooks_GetProcessHeap);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "CompareStringW", Hooks_CompareStringW);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "lstrlenW", Hooks_lstrlenW);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "lstrcatW", Hooks_lstrcatW);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "GetSystemInfo", Hooks_GetSystemInfo);
    Utils_hookImport(lpLibFileName, "kernel32.dll", "lstrcmpiW", Hooks_lstrcmpiW);
    Utils_hookImport(lpLibFileName, "user32.dll", "CharUpperW", Hooks_CharUpperW);
    Utils_hookImport(lpLibFileName, "user32.dll", "wsprintfW", Hooks_wsprintfW);

    return result;
}

FARPROC WINAPI Hooks_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC result = GetProcAddress(hModule, lpProcName);
    static UINT index = 0;
    if (!strcmp(lpProcName, "LoadLibraryExA"))
        index = 0;

#if !LOG_FILTER
    Utils_log("%ws: GetProcAddress(hModule: %p, lpProcName: %s (%u)) -> FARPROC: %p\n",
        Utils_getModuleName(_ReturnAddress()), hModule, lpProcName, index, result);
#endif
    index++;

    if (result) {
        FARPROC function = Functions_find(lpProcName);
        if (function)
            return function;

        Utils_log("Function not hooked: %s\n", lpProcName);
    } else {
        Utils_log("Function not found: %s\n", lpProcName);
    }
    return result;
}

HANDLE WINAPI Hooks_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    HANDLE result = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

    Utils_log("%ws: OpenProcess(dwDesiredAccess: %d, bInheritHandle: %d, dwProcessId: %d) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), dwDesiredAccess, bInheritHandle, dwProcessId, result);

    return result;
}

DWORD WINAPI Hooks_GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize)
{
    DWORD result = GetProcessImageFileNameA(hProcess, lpImageFileName, nSize);

    Utils_log("%ws: GetProcessImageFileNameA(hProcess: %p, lpImageFileName: %s, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpImageFileName, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize)
{
    DWORD result = GetProcessImageFileNameW(hProcess, lpImageFileName, nSize);

    Utils_log("%ws: GetProcessImageFileNameW(hProcess: %p, lpImageFileName: %ws, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpImageFileName, nSize, result);

    return result;
}

int WINAPI Hooks_GetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
    int result = GetWindowTextW(hWnd, lpString, nMaxCount);

    Utils_log("%ws: GetWindowTextW(hWnd: %p, lpString: %ws, nMaxCount: %d) -> int %d\n",
        Utils_getModuleName(_ReturnAddress()), hWnd, lpString, nMaxCount, result);

    return result;
}

BOOL WINAPI Hooks_QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize)
{
    BOOL result = QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);

    Utils_log("%ws: QueryFullProcessImageNameW(hProcess: %p, dwFlags: %d, lpExeName: %ws, lpdwSize: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, dwFlags, lpExeName, lpdwSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleBaseNameA(HANDLE hProcess, HMODULE hModule, LPSTR lpBaseName, DWORD nSize)
{
    DWORD result = GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize);

    Utils_log("%ws: GetModuleBaseNameA(hProcess: %p, hModule: %p, lpBaseName: %s, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, hModule, lpBaseName, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleBaseNameW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize)
{
    DWORD result = GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize);

    Utils_log("%ws: GetModuleBaseNameW(hProcess: %p, hModule: %p, lpBaseName: %ws, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, hModule, lpBaseName, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    DWORD result = GetModuleFileNameA(hModule, lpFilename, nSize);

    Utils_log("%ws: GetModuleFileNameA(hModule: %p, lpFilename: %s, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hModule, lpFilename, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    DWORD result = GetModuleFileNameExA(hProcess, hModule, lpFilename, nSize);

    Utils_log("%ws: GetModuleFileNameExA(hProcess: %p, hModule: %p, lpFilename: %s, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, hModule, lpFilename, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    DWORD result = GetModuleFileNameExW(hProcess, hModule, lpFilename, nSize);

    Utils_log("%ws: GetModuleFileNameExW(hProcess: %p, hModule: %p, lpFilename: %ws, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, hModule, lpFilename, nSize, result);

    return result;
}

BOOL WINAPI Hooks_GetComputerNameExW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize)
{
    BOOL result = GetComputerNameExW(NameType, lpBuffer, nSize);

    Utils_log("%ws: GetComputerNameExW(NameType: %d, lpBuffer: %ws, nSize: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), NameType, lpBuffer, *nSize, result);

    return result;
}

HANDLE WINAPI Hooks_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    HANDLE result = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    Utils_log("%ws: CreateRemoteThread(hProcess: %p, lpThreadAttributes: %p, dwStackSize: %d, lpStartAddress: %p, lpParameter: %p, dwCreationFlags: %d, lpThreadId: %p) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId)
{
    extern NTSTATUS(NTAPI NtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
    NTSTATUS result = NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    Utils_log("%ws: NtOpenProcess(ProcessHandle: %p, DesiredAccess: %d, ObjectAttributes: %p, ClientId: %p) -> NTSTATUS: %ld\n",
        Utils_getModuleName(_ReturnAddress()), ProcessHandle, DesiredAccess, ObjectAttributes, ClientId, result);

    return result;
}

BOOL WINAPI Hooks_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    BOOL result = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    Utils_log("%ws: ReadProcessMemory(hProcess: %p, lpBaseAddress: %p, lpBuffer: %p, nSize: %lu, lpNumberOfBytesRead: %lu) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpBaseAddress, lpBuffer, nSize, SAFE_PTR(lpNumberOfBytesRead, 0), result);

    return result;
}

BOOL WINAPI Hooks_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    BOOL result = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    Utils_log("%ws: WriteProcessMemory(hProcess: %p, lpBaseAddress: %p, lpBuffer: %p, nSize: %d, lpNumberOfBytesWritten: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten, result);

    return result;
}

int WINAPI Hooks_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
{
    int result = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);

    Utils_log("%ws: MultiByteToWideChar(CodePage: %u, dwFlags: %d, lpMultiByteStr: %s, cbMultiByte: %d, lpWideCharStr: %ws, cchWideChar: %d) -> int: %d\n",
        Utils_getModuleName(_ReturnAddress()), CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar, result);

    return result;
}

BOOLEAN SEC_ENTRY Hooks_GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize)
{
    BOOLEAN result = GetUserNameExW(NameFormat, lpNameBuffer, nSize);

    Utils_log("%ws: GetUserNameExW(NameFormat: %d, lpNameBuffer: %ws, nSize: %lu) -> BOOLEAN: %d\n",
        Utils_getModuleName(_ReturnAddress()), NameFormat, lpNameBuffer, *nSize, result);

    return result;
}

UINT WINAPI Hooks_GetDriveTypeW(LPCWSTR lpRootPathName)
{
    UINT result = GetDriveTypeW(lpRootPathName);

    Utils_log("%ws: GetDriveTypeW(lpRootPathName: %ws) -> UINT: %u\n",
        Utils_getModuleName(_ReturnAddress()), lpRootPathName, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
{
    LSTATUS result = RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);

    Utils_log("%ws: RegEnumKeyExA(hKey: %p, dwIndex: %d, lpName: %s, lpcchName: %d, lpReserved: %p, lpClass: %p, lpcchClass: %p, lpftLastWriteTime: %p) -> LSTATUS: %ld\n",
        Utils_getModuleName(_ReturnAddress()), hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    LSTATUS result = RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    Utils_log("%ws: RegOpenKeyExA(hKey: %p, lpSubKey: %s, ulOptions: %d, samDesired: %d, phkResult: %p) -> LSTATUS: %ld\n",
        Utils_getModuleName(_ReturnAddress()), hKey, SAFE_STR(lpSubKey, ""), ulOptions, samDesired, phkResult, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegCloseKey(HKEY hKey)
{
    LSTATUS result = RegCloseKey(hKey);

    Utils_log("%ws: RegCloseKey(hKey: %p) -> LSTATUS: %ld\n",
        Utils_getModuleName(_ReturnAddress()), hKey, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime)
{
    LSTATUS result = RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);

    Utils_log("%ws: RegQueryInfoKeyA(hKey: %p, lpClass: %s, lpcchClass: %p, lpReserved: %p, lpcSubKeys: %p, lpcbMaxSubKeyLen: %p, lpcbMaxClassLen: %p, lpcValues: %p, lpcbMaxValueNameLen: %p, lpcbMaxValueLen: %p, lpcbSecurityDescriptor: %p, lpftLastWriteTime: %p) -> LSTATUS: %ld\n",
        Utils_getModuleName(_ReturnAddress()), hKey, SAFE_STR(lpClass, ""), lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LSTATUS result = RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    Utils_log("%ws: RegQueryValueExA(hKey: %p, lpValueName: %s, lpcchClass: %p, lpReserved: %p, lpType: %p, lpData: %p, lpcbData: %p) -> LSTATUS: %ld\n",
        Utils_getModuleName(_ReturnAddress()), hKey, SAFE_STR(lpValueName, ""), lpReserved, lpType, lpData, lpcbData, result);

    return result;
}

VOID WINAPI Hooks_OutputDebugStringA(LPCSTR lpOutputString)
{
    OutputDebugStringA(lpOutputString);

    Utils_log("%ws: OutputDebugStringA(lpOutputString: %s) -> VOID\n",
        Utils_getModuleName(_ReturnAddress()), lpOutputString);
}

BOOL APIENTRY Hooks_GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    BOOL result = GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);

    Utils_log("%ws: GetFileVersionInfoA(lptstrFilename: %s, dwHandle: %d, dwLen: %d, lpData: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lptstrFilename, dwHandle, dwLen, lpData, result);

    return result;
}

BOOL APIENTRY Hooks_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    BOOL result = GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);

    Utils_log("%ws: GetFileVersionInfoW(lptstrFilename: %ws, dwHandle: %d, dwLen: %d, lpData: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lptstrFilename, dwHandle, dwLen, lpData, result);

    return result;
}

DWORD APIENTRY Hooks_GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle)
{
    DWORD result = GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);

    Utils_log("%ws: GetFileVersionInfoSizeA(lptstrFilename: %s, lpdwHandle: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), lptstrFilename, lpdwHandle, result);

    return result;
}

DWORD APIENTRY Hooks_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
    DWORD result = GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);

    Utils_log("%ws: GetFileVersionInfoSizeW(lptstrFilename: %ws, lpdwHandle: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), lptstrFilename, lpdwHandle, result);

    return result;
}

DWORD WINAPI Hooks_GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
{
    DWORD result = GetFileSize(hFile, lpFileSizeHigh);
    WCHAR filename[MAX_PATH];

    Utils_log("%ws: GetFileSize(hFile: %p (%ws), lpFileSizeHigh: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, GetFinalPathNameByHandleW(hFile, filename, MAX_PATH, 0) ? filename : L"", lpFileSizeHigh, result);

    return result;
}

BOOL WINAPI Hooks_GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
    BOOL result = GetFileSizeEx(hFile, lpFileSize);
    WCHAR filename[MAX_PATH];

    Utils_log("%ws: GetFileSizeEx(hFile: %p (%ws), lpFileSize: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, GetFinalPathNameByHandleW(hFile, filename, MAX_PATH, 0) ? filename : L"", lpFileSize, result);

    return result;
}

BOOL WINAPI Hooks_GetWindowInfo(HWND hwnd, PWINDOWINFO pwi)
{
    BOOL result = GetWindowInfo(hwnd, pwi);

    Utils_log("%ws: GetWindowInfo(hwnd: %p, pwi: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hwnd, pwi, result);

    return result;
}

UINT WINAPI Hooks_GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize)
{
    UINT result = GetWindowsDirectoryA(lpBuffer, uSize);

    Utils_log("%ws: GetWindowsDirectoryA(lpBuffer: %s, uSize: %u) -> UINT: %u\n",
        Utils_getModuleName(_ReturnAddress()), lpBuffer, uSize, result);

    return result;
}

UINT WINAPI Hooks_GetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize)
{
    UINT result = GetWindowsDirectoryW(lpBuffer, uSize);

    Utils_log("%ws: GetWindowsDirectoryW(lpBuffer: %ws, uSize: %u) -> UINT: %u\n",
        Utils_getModuleName(_ReturnAddress()), lpBuffer, uSize, result);

    return result;
}

HMODULE WINAPI Hooks_GetModuleHandleA(LPCSTR lpModuleName)
{
    HMODULE result = GetModuleHandleA(lpModuleName);

    Utils_log("%ws: GetModuleHandleA(lpModuleName: %s) -> HMODULE: %p\n",
        Utils_getModuleName(_ReturnAddress()), SAFE_STR(lpModuleName, ""), result);

    return result;
}

PVOID WINAPI Hooks_AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
{
    PVOID result = AddVectoredExceptionHandler(First, Handler);

    Utils_log("%ws: AddVectoredExceptionHandler(First: %lu, Handler: %p) -> PVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), First, Handler, result);

    return result;
}

BOOL WINAPI Hooks_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
{
    BOOL result = AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);

    Utils_log("%ws: AdjustTokenPrivileges(TokenHandle: %p, DisableAllPrivileges: %d, NewState: %p, BufferLength: %d, PreviousState: %p, ReturnLength: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength, result);

    return result;
}

DWORD WINAPI Hooks_CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void* pvTypePara, LPWSTR pszNameString, DWORD cchNameString)
{
    DWORD result = CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString);

    Utils_log("%ws: CertGetNameStringW(pCertContext: %p, dwType: %d, dwFlags: %p, pvTypePara: %p, pszNameString: %ws, cchNameString: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), pCertContext, dwType, dwFlags, pvTypePara, SAFE_STR(pszNameString, L""), cchNameString, result);

    return result;
}

HANDLE WINAPI Hooks_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE result = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    Utils_log("%ws: CreateFileA(lpFileName: %s, dwDesiredAccess: %d, dwShareMode: %d, lpSecurityAttributes: %p, dwCreationDisposition: %d, dwFlagsAndAttributes: %d, hTemplateFile: %p) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, result);

    return result;
}

HANDLE WINAPI Hooks_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE result = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    Utils_log("%ws: CreateFileW(lpFileName: %ws, dwDesiredAccess: %d, dwShareMode: %d, lpSecurityAttributes: %p, dwCreationDisposition: %d, dwFlagsAndAttributes: %d, hTemplateFile: %p) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, result);

    return result;
}

HANDLE WINAPI Hooks_GetCurrentProcess(VOID)
{
    HANDLE result = GetCurrentProcess();

#if !LOG_FILTER
    Utils_log("%ws: GetCurrentProcess() -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), result);
#endif

    return result;;
}

DWORD WINAPI Hooks_GetCurrentProcessId(VOID)
{
    DWORD result = GetCurrentProcessId();

    Utils_log("%ws: GetCurrentProcessId() -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), result);

    return result;;
}

HANDLE WINAPI Hooks_GetCurrentThread(VOID)
{
    HANDLE result = GetCurrentThread();

    Utils_log("%ws: GetCurrentThread() -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), result);

    return result;
}

DWORD WINAPI Hooks_GetCurrentThreadId(VOID)
{
    DWORD result = GetCurrentThreadId();

    Utils_log("%ws: GetCurrentThreadId() -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), result);

    return result;
}

HANDLE WINAPI Hooks_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    HANDLE result = CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

    Utils_log("%ws: CreateToolhelp32Snapshot(dwFlags: %d, th32ProcessID: %d) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), dwFlags, th32ProcessID, result);

    return result;
}

BOOL WINAPI Hooks_EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
    BOOL result = EnumChildWindows(hWndParent, lpEnumFunc, lParam);

    Utils_log("%ws: EnumChildWindows(hWndParent: %p, lpEnumFunc: %p, lParam: %ld) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hWndParent, lpEnumFunc, lParam, result);

    return result;
}

BOOL WINAPI Hooks_EnumProcesses(DWORD* lpidProcess, DWORD cb, LPDWORD lpcbNeeded)
{
    BOOL result = EnumProcesses(lpidProcess, cb, lpcbNeeded);

    Utils_log("%ws: EnumProcesses(lpidProcess: %p, cb: %d, lpcbNeeded: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpidProcess, cb, lpcbNeeded, result);

    return result;
}

BOOL WINAPI Hooks_EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
    BOOL result = EnumWindows(lpEnumFunc, lParam);

    Utils_log("%ws: EnumWindows(lpEnumFunc: %p, lParam: %ld) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpEnumFunc, lParam, result);

    return result;
}

BOOL WINAPI Hooks_GetProcessTimes(HANDLE hProcess, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime)
{
    BOOL result = GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);

    Utils_log("%ws: GetProcessTimes(hProcess: %p, lpCreationTime: %p, lpExitTime: %p, lpKernelTime: %p, lpUserTime: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime, result);

    return result;
}

DWORD WINAPI Hooks_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    DWORD result = WaitForSingleObject(hHandle, dwMilliseconds);

    Utils_log("%ws: WaitForSingleObject(hHandle: %p, dwMilliseconds: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hHandle, dwMilliseconds, result);

    return result;
}

LPVOID WINAPI Hooks_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID result = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    Utils_log("%ws: VirtualAlloc(lpAddress: %p, dwSize: %d, flAllocationType: %d, flProtect: %d) -> LPVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), lpAddress, dwSize, flAllocationType, flProtect, result);

    return result;
}

LPVOID WINAPI Hooks_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID result = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    Utils_log("%ws: VirtualAllocEx(hProcess: %p, lpAddress: %p, dwSize: %d, flAllocationType: %d, flProtect: %d) -> LPVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpAddress, dwSize, flAllocationType, flProtect, result);

    return result;
}

BOOL WINAPI Hooks_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = VirtualFree(lpAddress, dwSize, dwFreeType);

    Utils_log("%ws: VirtualFree(lpAddress: %p, dwSize: %d, dwFreeType: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpAddress, dwSize, dwFreeType, result);

    return result;
}

BOOL WINAPI Hooks_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);

    Utils_log("%ws: VirtualFreeEx(hProcess: %p, lpAddress: %p, dwSize: %d, dwFreeType: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpAddress, dwSize, dwFreeType, result);

    return result;
}

BOOL WINAPI Hooks_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    BOOL result = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    Utils_log("%ws: VirtualProtect(lpAddress: %p, dwSize: %d, flNewProtect: %d, lpflOldProtect: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpAddress, dwSize, flNewProtect, *lpflOldProtect, result);

    return result;
}

SIZE_T WINAPI Hooks_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    SIZE_T result = VirtualQuery(lpAddress, lpBuffer, dwLength);

    Utils_log("%ws: VirtualQuery(lpAddress: %p, lpBuffer: %p, dwLength: %d) -> SIZE_T: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpAddress, lpBuffer, dwLength, result);

    return result;
}

SIZE_T WINAPI Hooks_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    SIZE_T result = VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    WCHAR moduleName[MAX_PATH] = { 0 };
    GetModuleFileNameExW(hProcess, lpBuffer->AllocationBase, moduleName, MAX_PATH);
    Utils_log("%ws: VirtualQueryEx(hProcess: %p, lpAddress: %p, lpBuffer: %p {BaseAddress: %p, AllocationBase: %p (%ws), AllocationProtect: %d, RegionSize: %d, State: %d, Protect: %d, Type: %d}, dwLength: %d) -> SIZE_T: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpAddress, lpBuffer, lpBuffer->BaseAddress, lpBuffer->AllocationBase, moduleName, lpBuffer->AllocationProtect, lpBuffer->RegionSize, lpBuffer->State, lpBuffer->Protect, lpBuffer->Type, dwLength, result);

    return result;
}

DWORD WINAPI Hooks_SuspendThread(HANDLE hThread)
{
    DWORD result = SuspendThread(hThread);

    Utils_log("%ws: SuspendThread(hThread: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hThread, result);

    return result;
}

BOOL WINAPI Hooks_SwitchToThread(VOID)
{
    BOOL result = SwitchToThread();

    Utils_log("%ws: SwitchToThread() -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), result);

    return result;
}

BOOLEAN WINAPI Hooks_Wow64EnableWow64FsRedirection(BOOLEAN Wow64FsEnableRedirection)
{
    BOOLEAN result = Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection);

    Utils_log("%ws: Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection: %d) -> BOOLEAN: %d\n",
        Utils_getModuleName(_ReturnAddress()), Wow64FsEnableRedirection, result);

    return result;
}

LONG WINAPI Hooks_WinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData)
{
    LONG result = WinVerifyTrust(hwnd, pgActionID, pWVTData);

    Utils_log("%ws: WinVerifyTrust(hwnd: %d, pgActionID: %p, pWVTData: %p) -> LONG: %ld\n",
        Utils_getModuleName(_ReturnAddress()), hwnd, pgActionID, pWVTData, result);

    return result;
}

VOID WINAPI Hooks_Sleep(DWORD dwMilliseconds)
{
    Sleep(dwMilliseconds);

    Utils_log("%ws: Sleep(dwMilliseconds: %d) -> VOID\n",
        Utils_getModuleName(_ReturnAddress()), dwMilliseconds);
}

HANDLE WINAPI Hooks_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)
{
    HANDLE result = CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

    Utils_log("%ws: CreateFileMappingW(hFile: %p, lpFileMappingAttributes: %p, flProtect: %d, dwMaximumSizeHigh: %d, dwMaximumSizeLow: %d, lpName: %ws) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, result);

    return result;
}

BOOL WINAPI Hooks_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
{
    BOOL result = OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);

    Utils_log("%ws: OpenProcessToken(ProcessHandle: %p, DesiredAccess: %d, TokenHandle %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), ProcessHandle, DesiredAccess, TokenHandle, result);

    return result;
}

BOOL WINAPI Hooks_EnumServicesStatusA(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSA lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle)
{
    BOOL result = EnumServicesStatusA(hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

    Utils_log("%ws: EnumServicesStatusA(hSCManager: %p, dwServiceType: %d, dwServiceState: %d, lpServices: %p, cbBufSize: %d, pcbBytesNeeded: %p, lpServicesReturned: %p, lpResumeHandle: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, result);

    return result;
}

BOOL WINAPI Hooks_EnumServicesStatusW(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSW lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle)
{
    BOOL result = EnumServicesStatusW(hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

    Utils_log("%ws: EnumServicesStatusW(hSCManager: %p, dwServiceType: %d, dwServiceState: %d, lpServices: %p, cbBufSize: %d, pcbBytesNeeded: %p, lpServicesReturned: %p, lpResumeHandle: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, result);

    return result;
}

HANDLE WINAPI Hooks_FindFirstVolumeW(LPWSTR lpszVolumeName, DWORD cchBufferLength)
{
    HANDLE result = FindFirstVolumeW(lpszVolumeName, cchBufferLength);

    Utils_log("%ws: FindFirstVolumeW(lpszVolumeName: %ws, cchBufferLength: %d) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), lpszVolumeName, cchBufferLength, result);

    return result;
}

BOOL WINAPI Hooks_FindNextVolumeW(HANDLE hFindVolume, LPWSTR lpszVolumeName, DWORD cchBufferLength)
{
    BOOL result = FindNextVolumeW(hFindVolume, lpszVolumeName, cchBufferLength);

    Utils_log("%ws: FindNextVolumeW(hFindVolume: %p, lpszVolumeName: %ws, cchBufferLength: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFindVolume, lpszVolumeName, cchBufferLength, result);

    return result;
}

BOOL WINAPI Hooks_FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
{
    BOOL result = FlushInstructionCache(hProcess, lpBaseAddress, dwSize);

    Utils_log("%ws: FlushInstructionCache(hProcess: %p, lpBaseAddress: %p, dwSize: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpBaseAddress, dwSize, result);

    return result;
}

BOOL WINAPI Hooks_GetVolumePathNamesForVolumeNameW(LPCWSTR lpszVolumeName, LPWCH lpszVolumePathNames, DWORD cchBufferLength, PDWORD lpcchReturnLength)
{
    BOOL result = GetVolumePathNamesForVolumeNameW(lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength);

    Utils_log("%ws: GetVolumePathNamesForVolumeNameW(lpszVolumeName: %ws, lpszVolumePathNames: %ws, cchBufferLength: %d, lpcchReturnLength: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength, result);

    return result;
}

DWORD WINAPI Hooks_GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId)
{
    DWORD result = GetWindowThreadProcessId(hWnd, lpdwProcessId);

    Utils_log("%ws: GetWindowThreadProcessId(hWnd: %p, lpdwProcessId: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hWnd, lpdwProcessId, result);

    return result;
}

BOOL WINAPI Hooks_Heap32First(LPHEAPENTRY32 lphe, DWORD th32ProcessID, ULONG_PTR th32HeapID)
{
    BOOL result = Heap32First(lphe, th32ProcessID, th32HeapID);

    Utils_log("%ws: Heap32First(lphe: %p, th32ProcessID: %d, th32HeapID: %lu) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lphe, th32ProcessID, th32HeapID, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS result = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    Utils_log("%ws: NtQuerySystemInformation(SystemInformationClass: %d, SystemInformation: %p, SystemInformationLength: %lu, ReturnLength: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength, result);

    return result;
}

BOOL NTAPI Hooks_ConvertSidToStringSidA(PSID Sid, LPSTR* StringSid)
{
    BOOL result = ConvertSidToStringSidA(Sid, StringSid);

    Utils_log("%ws: ConvertSidToStringSidA(Sid: %p, StringSid: %s) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), Sid, *StringSid, result);

    return result;
}

BOOL WINAPI Hooks_CryptMsgGetParam(HCRYPTMSG hCryptMsg, DWORD dwParamType, DWORD dwIndex, void* pvData, DWORD* pcbData)
{
    BOOL result = CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData);

    Utils_log("%ws: CryptMsgGetParam(hCryptMsg: %p, dwParamType: %d, dwIndex: %d, pvData: %p, pcbData: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hCryptMsg, dwParamType, dwIndex, pvData, pcbData, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    NTSTATUS result = NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    Utils_log("%ws: NtQueryInformationProcess(ProcessHandle: %p, ProcessInformationClass: %d, ProcessInformation: %p, ProcessInformationLength: %lu, ReturnLength: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength, result);

    return result;
}

PVOID WINAPI Hooks_EncodePointer(PVOID Ptr)
{
    PVOID result = EncodePointer(Ptr);

    Utils_log("%ws: EncodePointer(Ptr: %p) -> PVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), Ptr, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
    NTSTATUS result = NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

    Utils_log("%ws: NtQueryInformationThread(ThreadHandle: %p, ThreadInformationClass: %d, ThreadInformation: %p, ThreadInformationLength: %lu, ReturnLength: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength, result);

    return result;
}

SC_HANDLE WINAPI Hooks_OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess)
{
    SC_HANDLE result = OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess);

    Utils_log("%ws: OpenSCManagerA(lpMachineName: %s, lpDatabaseName: %s, dwDesiredAccess: %d) -> SC_HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), SAFE_STR(lpMachineName, ""), SAFE_STR(lpDatabaseName, ""), dwDesiredAccess, result);

    return result;
}

HANDLE WINAPI Hooks_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
    HANDLE result = OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);

    Utils_log("%ws: OpenThread(dwDesiredAccess: %d, bInheritHandle: %d, dwThreadId: %d) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), dwDesiredAccess, bInheritHandle, dwThreadId, result);

    return result;
}

BOOL WINAPI Hooks_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL result = Process32FirstW(hSnapshot, lppe);

    Utils_log("%ws: Process32FirstW(hSnapshot: %p, lppe: %p {th32ProcessID: %d}) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSnapshot, lppe, lppe->th32ProcessID, result);

    return result;
}

BOOL WINAPI Hooks_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL result = Process32NextW(hSnapshot, lppe);

    Utils_log("%ws: Process32NextW(hSnapshot: %p, lppe: %p {th32ProcessID: %d}) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSnapshot, lppe, lppe->th32ProcessID, result);

    return result;
}

BOOL WINAPI Hooks_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    BOOL result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

    Utils_log("%ws: WriteFile(hFile: %p, lpBuffer: %p, nNumberOfBytesToWrite: %d, lpNumberOfBytesWritten: %p, lpOverlapped: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, DWORD MemoryInformationClass, PVOID Buffer, ULONG Length, PULONG ResultLength)
{
    extern NTSTATUS(NTAPI NtQueryVirtualMemory)(HANDLE, PVOID, DWORD, PVOID, ULONG, PULONG);
    NTSTATUS result = NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength);

    if (!MemoryInformationClass) {
        WCHAR moduleName[MAX_PATH] = { 0 };
        MEMORY_BASIC_INFORMATION* mbi = Buffer;
        GetModuleFileNameExW(ProcessHandle, mbi->AllocationBase, moduleName, MAX_PATH);

        Utils_log("%ws: NtQueryVirtualMemory(ProcessHandle: %p, BaseAddress: %p, MemoryInformationClass: %d, Buffer: %p {BaseAddress: %p, AllocationBase: %p (%ws), AllocationProtect: %d, RegionSize: %d, State: %d, Protect: %d, Type: %d}, Length: %lu, ResultLength: %p) -> NTSTATUS: 0x%lx\n",
            Utils_getModuleName(_ReturnAddress()), ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, mbi->BaseAddress, mbi->AllocationBase, moduleName, mbi->AllocationProtect, mbi->RegionSize, mbi->State, mbi->Protect, mbi->Type, Length, ResultLength, result);
    } else {
        Utils_log("%ws: NtQueryVirtualMemory(ProcessHandle: %p, BaseAddress: %p, MemoryInformationClass: %d, Buffer: %p, Length: %lu, ResultLength: %p) -> NTSTATUS: 0x%lx\n",
            Utils_getModuleName(_ReturnAddress()), ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength, result);
    }
    return result;
}

VOID WINAPI Hooks_SetLastError(DWORD dwErrCode)
{
    SetLastError(dwErrCode);

    Utils_log("%ws: SetLastError(dwErrCode: %d) -> VOID\n",
        Utils_getModuleName(_ReturnAddress()), dwErrCode);
}

DWORD_PTR WINAPI Hooks_SetThreadAffinityMask(HANDLE hThread, DWORD_PTR dwThreadAffinityMask)
{
    DWORD_PTR result = SetThreadAffinityMask(hThread, dwThreadAffinityMask);

    Utils_log("%ws: SetThreadAffinityMask(hThread: %p, dwThreadAffinityMask: %lu) -> DWORD_PTR: %lu\n",
        Utils_getModuleName(_ReturnAddress()), hThread, dwThreadAffinityMask, result);

    return result;
}

BOOL WINAPI Hooks_Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
    BOOL result = Thread32First(hSnapshot, lpte);

    Utils_log("%ws: Thread32First(hSnapshot: %p, lpte: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSnapshot, lpte, result);

    return result;
}

BOOL WINAPI Hooks_Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
    BOOL result = Thread32Next(hSnapshot, lpte);

    Utils_log("%ws: Thread32Next(hSnapshot: %p, lpte: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSnapshot, lpte, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
    NTSTATUS result = NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    Utils_log("%ws: NtQueryObject(Handle: %p, ObjectInformationClass: %d, ObjectInformation: %p, ObjectInformationLength: %lu, ReturnLength: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
    extern NTSTATUS(NTAPI NtFsControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
    NTSTATUS result = NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

    Utils_log("%ws: NtFsControlFile(FileHandle: %p, Event: %p, ApcRoutine: %p, ApcContext: %p, IoStatusBlock: %p, FsControlCode: %lu, InputBuffer: %p, InputBufferLength: %lu, OutputBuffer: %p, OutputBufferLength: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, result);

    return result;
}

BOOL WINAPI Hooks_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    BOOL result = GetThreadContext(hThread, lpContext);

    Utils_log("%ws: GetThreadContext(hThread: %p, lpContext: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hThread, lpContext, result);

    return result;
}

BOOL WINAPI Hooks_GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength)
{
    BOOL result = GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength);

    Utils_log("%ws: GetTokenInformation(TokenHandle: %p, TokenInformationClass: %d, TokenInformation: %p, TokenInformationLength: %d, ReturnLength: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength, result);

    return result;
}

BOOL WINAPI Hooks_GetUserProfileDirectoryA(HANDLE hToken, LPSTR lpProfileDir, LPDWORD lpcchSize)
{
    BOOL result = GetUserProfileDirectoryA(hToken, lpProfileDir, lpcchSize);

    Utils_log("%ws: GetUserProfileDirectoryA(hToken: %p, lpProfileDir: %s, lpcchSize: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hToken, SAFE_STR(lpProfileDir, ""), lpcchSize, result);

    return result;
}

BOOL WINAPI Hooks_GetUserProfileDirectoryW(HANDLE hToken, LPWSTR lpProfileDir, LPDWORD lpcchSize)
{
    BOOL result = GetUserProfileDirectoryW(hToken, lpProfileDir, lpcchSize);

    Utils_log("%ws: GetUserProfileDirectoryW(hToken: %p, lpProfileDir: %ws, lpcchSize: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hToken, SAFE_STR(lpProfileDir, L""), lpcchSize, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtDuplicateObject(HANDLE SourceProcessHandle, PHANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, BOOLEAN InheritHandle, ULONG Options)
{
    extern NTSTATUS(NTAPI NtDuplicateObject)(HANDLE, PHANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, ULONG);
    NTSTATUS result = NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, InheritHandle, Options);

    Utils_log("%ws: NtDuplicateObject(SourceProcessHandle: %p, SourceHandle: %p, TargetProcessHandle: %p, TargetHandle: %p, DesiredAccess: %d, InheritHandle: %d, Options: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, InheritHandle, Options, result);

    return result;
}

HANDLE WINAPI Hooks_OpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    HANDLE result = OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName);

    Utils_log("%ws: OpenFileMappingW(dwDesiredAccess: %d, bInheritHandle: %d, lpName: %ws) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), dwDesiredAccess, bInheritHandle, lpName, result);

    return result;
}

NTSTATUS NTAPI Hooks_RtlDecompressBufferEx(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize, PVOID WorkSpace)
{
    extern NTSTATUS(NTAPI RtlDecompressBufferEx)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
    NTSTATUS result = RtlDecompressBufferEx(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace);

    Utils_log("%ws: RtlDecompressBufferEx(CompressionFormat: %u, UncompressedBuffer: %p, UncompressedBufferSize: %lu, CompressedBuffer: %p, CompressedBufferSize: %lu, FinalUncompressedSize: %p, WorkSpace: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace, result);

    return result;
}

ULONG WINAPI Hooks_GetTcpTable(PMIB_TCPTABLE TcpTable, PULONG SizePointer, BOOL Order)
{
    ULONG result = GetTcpTable(TcpTable, SizePointer, Order);

    Utils_log("%ws: GetTcpTable(TcpTable: %p { dwNumEntries: %d }, SizePointer: %p, Order: %d) -> ULONG: %lu\n",
        Utils_getModuleName(_ReturnAddress()), TcpTable, TcpTable->dwNumEntries, SizePointer, Order, result);

    return result;
}

BOOL WINAPI Hooks_CloseHandle(HANDLE hObject)
{
    BOOL result = CloseHandle(hObject);

    Utils_log("%ws: CloseHandle(hObject: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hObject, result);

    return result;
}

DWORD WINAPI Hooks_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    DWORD result = SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);

    Utils_log("%ws: SetFilePointer(hFile: %p, lDistanceToMove: %ld, lpDistanceToMoveHigh: %p, dwMoveMethod: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod, result);

    return result;
}

BOOL WINAPI Hooks_SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
{
    BOOL result = SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);

    Utils_log("%ws: SetFilePointerEx(hFile: %p, liDistanceToMove: %lld, lpNewFilePointer: %p, dwMoveMethod: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod, result);

    return result;
}

HANDLE WINAPI Hooks_OpenFileById(HANDLE hVolumeHint, LPFILE_ID_DESCRIPTOR lpFileId, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwFlagsAndAttributes)
{
    HANDLE result = OpenFileById(hVolumeHint, lpFileId, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwFlagsAndAttributes);

    Utils_log("%ws: OpenFileById(hVolumeHint: %p, lpFileId: %p, dwDesiredAccess: %d, dwShareMode: %d, lpSecurityAttributes: %p, dwFlagsAndAttributes: %d) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), hVolumeHint, lpFileId, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwFlagsAndAttributes, result);

    return result;
}

DWORD WINAPI Hooks_GetMappedFileNameA(HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize)
{
    DWORD result = GetMappedFileNameA(hProcess, lpv, lpFilename, nSize);

    Utils_log("%ws: GetMappedFileNameA(hProcess: %p, lpv: %p, lpFilename: %s, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpv, lpFilename, nSize, result);

    return result;
}

DWORD WINAPI Hooks_GetMappedFileNameW(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize)
{
    DWORD result = GetMappedFileNameW(hProcess, lpv, lpFilename, nSize);

    Utils_log("%ws: GetMappedFileNameW(hProcess: %p, lpv: %p, lpFilename: %ws, nSize: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lpv, lpFilename, nSize, result);

    return result;
}

DWORD WINAPI Hooks_ResumeThread(HANDLE hThread)
{
    DWORD result = ResumeThread(hThread);

    Utils_log("%ws: ResumeThread(hThread: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), hThread, result);

    return result;
}

DWORD64 WINAPI Hooks_SymGetModuleBase64(HANDLE hProcess, DWORD64 qwAddr)
{
    DWORD64 result = SymGetModuleBase64(hProcess, qwAddr);

    Utils_log("%ws: SymGetModuleBase64(hProcess, qwAddr) -> DWORD64: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, qwAddr, result);

    return result;
}

DWORD WINAPI Hooks_GetProcessId(HANDLE Process)
{
    DWORD result = GetProcessId(Process);

    Utils_log("%ws: GetProcessId(Process: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), Process, result);

    return result;
}

BOOL WINAPI Hooks_IsBadReadPtr(CONST VOID* lp, UINT_PTR ucb)
{
    BOOL result = IsBadReadPtr(lp, ucb);

    Utils_log("%ws: IsBadReadPtr(lp: %p, ucb: %u) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lp, ucb, result);

    return result;
}

BOOL WINAPI Hooks_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    BOOL result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

    Utils_log("%ws: ReadFile(hFile: %p, lpBuffer: %p, nNumberOfBytesToRead: %d, lpNumberOfBytesRead: %p (%d), lpOverlapped: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, SAFE_PTR(lpNumberOfBytesRead, 0), lpOverlapped, result);

    return result;
}

DWORD WINAPI Hooks_GetThreadId(HANDLE Thread)
{
    DWORD result = GetThreadId(Thread);

    Utils_log("%ws: GetThreadId(Thread: %p) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), Thread, result);

    return result;
}

HLOCAL WINAPI Hooks_LocalAlloc(UINT uFlags, SIZE_T uBytes)
{
    HLOCAL result = LocalAlloc(uFlags, uBytes);

    Utils_log("%ws: LocalAlloc(uFlags: %u, uBytes: %lu) -> HLOCAL: %p\n",
        Utils_getModuleName(_ReturnAddress()), uFlags, uBytes, result);

    return result;
}

BOOL WINAPI Hooks_GetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb)
{
    BOOL result = GetModuleInformation(hProcess, hModule, lpmodinfo, cb);

    Utils_log("%ws: GetModuleInformation(hProcess: %p, hModule: %p, lpmodinfo: %p, cb: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, hModule, lpmodinfo, cb, result);

    return result;
}

BOOL WINAPI Hooks_IsWow64Process(HANDLE hProcess, PBOOL Wow64Process)
{
    BOOL result = IsWow64Process(hProcess, Wow64Process);

#if !LOG_FILTER
    Utils_log("%ws: IsWow64Process(hProcess: %p, Wow64Process: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, *Wow64Process, result);
#endif

    return result;
}

UINT WINAPI Hooks_GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize)
{
    UINT result = GetSystemDirectoryA(lpBuffer, uSize);

    Utils_log("%ws: GetSystemDirectoryA(lpBuffer: %s, uSize: %u) -> UINT: %u\n",
        Utils_getModuleName(_ReturnAddress()), lpBuffer, uSize, result);

    return result;
}

UINT WINAPI Hooks_GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize)
{
    UINT result = GetSystemDirectoryW(lpBuffer, uSize);

    Utils_log("%ws: GetSystemDirectoryW(lpBuffer: %ws, uSize: %u) -> UINT: %u\n",
        Utils_getModuleName(_ReturnAddress()), lpBuffer, uSize, result);

    return result;
}

HANDLE WINAPI Hooks_GetProcessHeap(VOID)
{
    HANDLE result = GetProcessHeap();

#if !LOG_FILTER
    Utils_log("%ws: GetProcessHeap() -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), result);
#endif

    return result;
}

LPVOID WINAPI Hooks_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    LPVOID result = MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

    Utils_log("%ws: MapViewOfFile(hFileMappingObject: %p, dwDesiredAccess: %d, dwFileOffsetHigh: %d, dwFileOffsetLow: %d, dwNumberOfBytesToMap: %lu) -> LPVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, result);

    return result;
}

BOOL WINAPI Hooks_UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    BOOL result = UnmapViewOfFile(lpBaseAddress);

    Utils_log("%ws: UnmapViewOfFile(lpBaseAddress: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpBaseAddress, result);

    return result;
}

BOOL WINAPI Hooks_GetVolumeInformationByHandleW(HANDLE hFile, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    BOOL result = GetVolumeInformationByHandleW(hFile, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);

    Utils_log("%ws: GetVolumeInformationByHandleW(hFile: %p, lpVolumeNameBuffer: %ws, nVolumeNameSize: %d, lpVolumeSerialNumber: %d, lpMaximumComponentLength: %d, lpFileSystemFlags: %d, lpFileSystemNameBuffer: %ws, nFileSystemNameSize: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, SAFE_STR(lpVolumeNameBuffer, L""), nVolumeNameSize, SAFE_PTR(lpVolumeSerialNumber, 0), SAFE_PTR(lpMaximumComponentLength, 0), SAFE_PTR(lpFileSystemFlags, 0), SAFE_STR(lpFileSystemNameBuffer, L""), nFileSystemNameSize, result);

    return result;
}

BOOL WINAPI Hooks_EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded)
{
    BOOL result = EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);

    Utils_log("%ws: EnumProcessModules(hProcess: %p, lphModule: %p, cb: %d, lpcbNeeded: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, lphModule, cb, SAFE_PTR(lpcbNeeded, 0), result);

    return result;
}

DWORD WINAPI Hooks_GetTickCount(VOID)
{
    DWORD result = GetTickCount();

    Utils_log("%ws: GetTickCount() -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), result);

    return result;
}

HDEVINFO WINAPI Hooks_SetupDiGetClassDevsA(const GUID* ClassGuid, PCSTR Enumerator, HWND hwndParent, DWORD Flags)
{
    HDEVINFO result = SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags);

    Utils_log("%ws: SetupDiGetClassDevsA(ClassGuid: %p, Enumerator: %s, hwndParent: %p, Flags: %d) -> HDEVINFO: %p\n",
        Utils_getModuleName(_ReturnAddress()), ClassGuid, SAFE_STR(Enumerator, ""), hwndParent, Flags, result);

    return result;
}

BOOL WINAPI Hooks_SetupDiEnumDeviceInfo(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData)
{
    BOOL result = SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);

    Utils_log("%ws: SetupDiEnumDeviceInfo(DeviceInfoSet: %p, MemberIndex: %d, DeviceInfoData: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), DeviceInfoSet, MemberIndex, DeviceInfoData, result);

    return result;
}

LPVOID WINAPI Hooks_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    LPVOID result = HeapAlloc(hHeap, dwFlags, dwBytes);

    Utils_log("%ws: HeapAlloc(hHeap: %p, dwFlags: %d, dwBytes: %lu) -> LPVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), hHeap, dwFlags, dwBytes, result);

    return result;
}

BOOL WINAPI Hooks_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    BOOL result = HeapFree(hHeap, dwFlags, lpMem);

    Utils_log("%ws: HeapFree(hHeap: %p, dwFlags: %d, lpMem: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hHeap, dwFlags, lpMem, result);

    return result;
}

BOOL WINAPI Hooks_FindVolumeClose(HANDLE hFindVolume)
{
    BOOL result = FindVolumeClose(hFindVolume);

    Utils_log("%ws: FindVolumeClose(hFindVolume: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFindVolume, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead)
{
    extern NTSTATUS(NTAPI NtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
    NTSTATUS result = NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

    Utils_log("%ws: NtReadVirtualMemory(ProcessHandle: %p, BaseAddress: %p, Buffer: %p, NumberOfBytesToRead: %lu, NumberOfBytesRead: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, SAFE_PTR(NumberOfBytesRead, 0), result);

    return result;
}

NTSTATUS NTAPI Hooks_NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    extern NTSTATUS(NTAPI NtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    NTSTATUS result = NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);

    Utils_log("%ws: NtOpenDirectoryObject(DirectoryHandle: %p, DesiredAccess: %d, ObjectAttributes: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), DirectoryHandle, DesiredAccess, ObjectAttributes, result);

    return result;
}

HLOCAL WINAPI Hooks_LocalFree(HLOCAL hMem)
{
    HLOCAL result = LocalFree(hMem);

    Utils_log("%ws: LocalFree(hMem: %p) -> HLOCAL: %p\n",
        Utils_getModuleName(_ReturnAddress()), hMem, result);

    return result;
}

SC_HANDLE WINAPI Hooks_OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess)
{
    SC_HANDLE result = OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);

    Utils_log("%ws: OpenServiceA(hSCManager: %p, lpServiceName: %s, dwDesiredAccess: %d) -> SC_HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), hSCManager, lpServiceName, dwDesiredAccess, result);

    return result;
}

SC_HANDLE WINAPI Hooks_OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess)
{
    SC_HANDLE result = OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);

    Utils_log("%ws: OpenServiceW(hSCManager: %p, lpServiceName: %ws, dwDesiredAccess: %d) -> SC_HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), hSCManager, lpServiceName, dwDesiredAccess, result);

    return result;
}

VOID WINAPI Hooks_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
    GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);

    Utils_log("%ws: GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: %p) -> VOID\n",
        Utils_getModuleName(_ReturnAddress()), lpSystemTimeAsFileTime);
}

HANDLE WINAPI Hooks_OpenEventLogA(LPCSTR lpUNCServerName, LPCSTR lpSourceName)
{
    HANDLE result = OpenEventLogA(lpUNCServerName, lpSourceName);

    Utils_log("%ws: OpenEventLogA(lpUNCServerName: %s, lpSourceName: %s) -> HANDLE: %p\n",
        Utils_getModuleName(_ReturnAddress()), SAFE_STR(lpUNCServerName, ""), SAFE_STR(lpSourceName, ""), result);

    return result;
}

BOOL WINAPI Hooks_ReadEventLogA(HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, DWORD* pnBytesRead, DWORD* pnMinNumberOfBytesNeeded)
{
    BOOL result = ReadEventLogA(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded);

    Utils_log("%ws: ReadEventLogA(hEventLog: %p, dwReadFlags: %d, dwRecordOffset: %d, lpBuffer: %p, nNumberOfBytesToRead: %d, pnBytesRead: %d, pnMinNumberOfBytesNeeded: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, SAFE_PTR(pnBytesRead, 0), SAFE_PTR(pnMinNumberOfBytesNeeded, 0), result);

    return result;
}

BOOL WINAPI Hooks_CloseEventLog(HANDLE hEventLog)
{
    BOOL result = CloseEventLog(hEventLog);

    Utils_log("%ws: CloseEventLog(hEventLog: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hEventLog, result);

    return result;
}

DWORD WINAPI Hooks_QueryDosDeviceA(LPCSTR lpDeviceName, LPSTR lpTargetPath, DWORD ucchMax)
{
    DWORD result = QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax);

    Utils_log("%ws: QueryDosDeviceA(lpDeviceName: %s, lpTargetPath: %s, ucchMax: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), SAFE_STR(lpDeviceName, ""), SAFE_STR(lpTargetPath, ""), ucchMax, result);

    return result;
}

DWORD WINAPI Hooks_QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax)
{
    DWORD result = QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax);

    Utils_log("%ws: QueryDosDeviceW(lpDeviceName: %ws, lpTargetPath: %ws, ucchMax: %d) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), SAFE_STR(lpDeviceName, L""), SAFE_STR(lpTargetPath, L""), ucchMax, result);

    return result;
}

DWORD WINAPI Hooks_GetLastError(VOID)
{
    DWORD result = GetLastError();

    Utils_log("%ws: GetLastError() -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), result);

    return result;
}

BOOL WINAPI Hooks_GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    BOOL result = GetFileInformationByHandle(hFile, lpFileInformation);

    Utils_log("%ws: GetFileInformationByHandle(hFile: %p, lpFileInformation: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, lpFileInformation, result);

    return result;
}

BOOL WINAPI Hooks_GetFileInformationByHandleEx(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize)
{
    BOOL result = GetFileInformationByHandleEx(hFile, FileInformationClass, lpFileInformation, dwBufferSize);

    Utils_log("%ws: GetFileInformationByHandleEx(hFile: %p, FileInformationClass: %d, lpFileInformation: %p, dwBufferSize: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hFile, FileInformationClass, lpFileInformation, dwBufferSize, result);

    return result;
}

BOOL WINAPI Hooks_CloseServiceHandle(SC_HANDLE hSCObject)
{
    BOOL result = CloseServiceHandle(hSCObject);

    Utils_log("%ws: CloseServiceHandle(hSCObject: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSCObject, result);

    return result;
}

BOOL WINAPI Hooks_QueryServiceConfigA(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    BOOL result = QueryServiceConfigA(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);

    Utils_log("%ws: QueryServiceConfigA(hService: %p, lpServiceConfig: %p, cbBufSize: %d, pcbBytesNeeded: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hService, lpServiceConfig, cbBufSize, SAFE_PTR(pcbBytesNeeded, 0), result);

    return result;
}

BOOL WINAPI Hooks_QueryServiceConfigW(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    BOOL result = QueryServiceConfigW(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);

    Utils_log("%ws: QueryServiceConfigW(hService: %p, lpServiceConfig: %p, cbBufSize: %d, pcbBytesNeeded: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hService, lpServiceConfig, cbBufSize, SAFE_PTR(pcbBytesNeeded, 0), result);

    return result;
}

HRESULT WINAPI Hooks_WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData)
{
    HRESULT result = WinVerifyTrustEx(hwnd, pgActionID, pWinTrustData);

    Utils_log("%ws: WinVerifyTrustEx(hwnd: %p, pgActionID: %p, pWinTrustData: %p) -> HRESULT: %ld\n",
        Utils_getModuleName(_ReturnAddress()), hwnd, pgActionID, pWinTrustData, result);

    return result;
}

HMODULE WINAPI Hooks_LoadLibraryA(LPCSTR lpLibFileName)
{
    HMODULE result = LoadLibraryA(lpLibFileName);

    Utils_log("%ws: LoadLibraryA(lpLibFileName: %s) -> HMODULE: %p\n",
        Utils_getModuleName(_ReturnAddress()), lpLibFileName, result);

    return result;
}

BOOL WINAPI Hooks_GetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    BOOL result = GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);

    Utils_log("%ws: GetVolumeInformationW(lpRootPathName: %ws, lpVolumeNameBuffer: %ws, nVolumeNameSize: %d, lpVolumeSerialNumber: %d, lpMaximumComponentLength: %d, lpFileSystemFlags: %d, lpFileSystemNameBuffer: %ws, nFileSystemNameSize: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), SAFE_STR(lpRootPathName, L""), SAFE_STR(lpVolumeNameBuffer, L""), nVolumeNameSize, SAFE_PTR(lpVolumeSerialNumber, 0), SAFE_PTR(lpMaximumComponentLength, 0), SAFE_PTR(lpFileSystemFlags, 0), SAFE_STR(lpFileSystemNameBuffer, L""), nFileSystemNameSize, result);

    return result;
}

HMODULE WINAPI Hooks_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE result = LoadLibraryExA(lpLibFileName, hFile, dwFlags);

#if !LOG_FILTER
    Utils_log("%ws: LoadLibraryExA(lpLibFileName: %s, hFile: %p, dwFlags: %d) -> HMODULE: %p\n",
        Utils_getModuleName(_ReturnAddress()), lpLibFileName, hFile, dwFlags, result);
#endif

    return result;
}

BOOL WINAPI Hooks_FreeLibrary(HMODULE hLibModule)
{
    BOOL result = FreeLibrary(hLibModule);

#if !LOG_FILTER
    Utils_log("%ws: FreeLibrary(hLibModule: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hLibModule, result);
#endif

    return result;
}

NTSTATUS NTAPI Hooks_NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    extern NTSTATUS(NTAPI NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    NTSTATUS result = NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);

    Utils_log("%ws: NtOpenSection(SectionHandle: %p, DesiredAccess: %d, ObjectAttributes: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), SectionHandle, DesiredAccess, ObjectAttributes, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQuerySection(HANDLE SectionHandle, DWORD InformationClass, PVOID InformationBuffer, ULONG InformationBufferSize, PULONG ResultLength)
{
    extern NTSTATUS(NTAPI NtQuerySection)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    NTSTATUS result = NtQuerySection(SectionHandle, InformationClass, InformationBuffer, InformationBufferSize, ResultLength);

    Utils_log("%ws: NtQuerySection(SectionHandle: %p, InformationClass: %d, InformationBuffer: %p, InformationBufferSize: %lu, ResultLength: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), SectionHandle, InformationClass, InformationBuffer, InformationBufferSize, SAFE_PTR(ResultLength, 0), result);

    return result;
}

DWORD WINAPI Hooks_GetLogicalDriveStringsA(DWORD nBufferLength, LPSTR lpBuffer)
{
    DWORD result = GetLogicalDriveStringsA(nBufferLength, lpBuffer);

    Utils_log("%ws: GetLogicalDriveStringsA(nBufferLength: %d, lpBuffer: %s) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), nBufferLength, lpBuffer, result);

    return result;
}

DWORD WINAPI Hooks_GetLogicalDriveStringsW(DWORD nBufferLength, LPWSTR lpBuffer)
{
    DWORD result = GetLogicalDriveStringsW(nBufferLength, lpBuffer);

    Utils_log("%ws: GetLogicalDriveStringsW(nBufferLength: %d, lpBuffer: %ws) -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), nBufferLength, lpBuffer, result);

    return result;
}

BOOL WINAPI Hooks_GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule)
{
    BOOL result = GetModuleHandleExA(dwFlags, lpModuleName, phModule);

    Utils_log("%ws: GetModuleHandleExA(dwFlags: %d, lpModuleName: %s, phModule: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), dwFlags, lpModuleName, phModule, result);

    return result;
}

BOOL WINAPI Hooks_Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
{
    BOOL result = Module32FirstW(hSnapshot, lpme);

    Utils_log("%ws: Module32FirstW(hSnapshot: %p, lpme: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSnapshot, lpme, result);

    return result;
}

BOOL WINAPI Hooks_Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
{
    BOOL result = Module32NextW(hSnapshot, lpme);

    Utils_log("%ws: Module32NextW(hSnapshot: %p, lpme: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hSnapshot, lpme, result);

    return result;
}

BOOL WINAPI Hooks_SetupDiDestroyDeviceInfoList(HDEVINFO DeviceInfoSet)
{
    BOOL result = SetupDiDestroyDeviceInfoList(DeviceInfoSet);

    Utils_log("%ws: SetupDiDestroyDeviceInfoList(DeviceInfoSet: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), DeviceInfoSet, result);

    return result;
}

PVOID WINAPI Hooks_SymFunctionTableAccess64(HANDLE hProcess, DWORD64 AddrBase)
{
    PVOID result = SymFunctionTableAccess64(hProcess, AddrBase);

    Utils_log("%ws: SymFunctionTableAccess64(hProcess: %p, AddrBase: %llu) -> PVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), hProcess, AddrBase, result);

    return result;
}

ULONG WINAPI Hooks_GetUdpTable(PMIB_UDPTABLE UdpTable, PULONG SizePointer, BOOL Order)
{
    ULONG result = GetUdpTable(UdpTable, SizePointer, Order);

    Utils_log("%ws: GetUdpTable(UdpTable: %p, SizePointer: %lu, Order: %d) -> ULONG: %lu\n",
        Utils_getModuleName(_ReturnAddress()), UdpTable, SAFE_PTR(SizePointer, 0), Order, result);

    return result;
}

BOOL WINAPI Hooks_CryptDecodeObject(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, void* pvStructInfo, DWORD* pcbStructInfo)
{
    BOOL result = CryptDecodeObject(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo);

    Utils_log("%ws: CryptDecodeObject(dwCertEncodingType: %d, lpszStructType: %s, pbEncoded: %d, cbEncoded: %d, dwFlags: %d, pvStructInfo: %p, pcbStructInfo: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), dwCertEncodingType, SAFE_STR(lpszStructType, ""), SAFE_PTR(pbEncoded, 0), cbEncoded, dwFlags, pvStructInfo, SAFE_PTR(pcbStructInfo, 0), result);

    return result;
}

BOOL WINAPI Hooks_CryptMsgClose(HCRYPTMSG hCryptMsg)
{
    BOOL result = CryptMsgClose(hCryptMsg);

    Utils_log("%ws: CryptMsgClose(hCryptMsg: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hCryptMsg, result);

    return result;
}

PCCERT_CONTEXT WINAPI Hooks_CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void* pvFindPara, PCCERT_CONTEXT pPrevCertContext)
{
    PCCERT_CONTEXT result = CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext);

    Utils_log("%ws: CertFindCertificateInStore(hCertStore: %p, dwCertEncodingType: %d, dwFindFlags: %d, dwFindType: %d, pvFindPara: %p, pPrevCertContext: %p) -> PCCERT_CONTEXT: %p\n",
        Utils_getModuleName(_ReturnAddress()), hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext, result);

    return result;
}

BOOL WINAPI Hooks_CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags)
{
    BOOL result = CertCloseStore(hCertStore, dwFlags);

    Utils_log("%ws: CertCloseStore(hCertStore: %p, dwFlags: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hCertStore, dwFlags, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Protect)
{
    extern NTSTATUS(NTAPI NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG, ULONG, PLARGE_INTEGER, PULONG, DWORD, ULONG, ULONG);
    NTSTATUS result = NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);

    Utils_log("%ws: NtMapViewOfSection(SectionHandle: %p, ProcessHandle: %p, BaseAddress: %p, ZeroBits: %lu, CommitSize: %lu, SectionOffset: %p, ViewSize: %p, InheritDisposition: %d, AllocationType: %lu, Protect: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect, result);

    return result;
}

BOOL APIENTRY Hooks_VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen)
{
    BOOL result = VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);

    Utils_log("%ws: VerQueryValueA(pBlock: %p, lpSubBlock: %s, lplpBuffer: %p, puLen: %u) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), pBlock, SAFE_STR(lpSubBlock, ""), lplpBuffer, SAFE_PTR(puLen, 0), result);

    return result;
}

BOOL APIENTRY Hooks_VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen)
{
    BOOL result = VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);

    Utils_log("%ws: VerQueryValueW(pBlock: %p, lpSubBlock: %ws, lplpBuffer: %p, puLen: %u) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), pBlock, SAFE_STR(lpSubBlock, L""), lplpBuffer, SAFE_PTR(puLen, 0), result);

    return result;
}

BOOL WINAPI Hooks_CryptQueryObject(DWORD dwObjectType, const void* pvObject, DWORD dwExpectedContentTypeFlags, DWORD dwExpectedFormatTypeFlags, DWORD dwFlags, DWORD* pdwMsgAndCertEncodingType, DWORD* pdwContentType, DWORD* pdwFormatType, HCERTSTORE* phCertStore, HCRYPTMSG* phMsg, const void** ppvContext)
{
    BOOL result = CryptQueryObject(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext);

    Utils_log("%ws: CryptQueryObject(dwObjectType: %d, pvObject: %p, dwExpectedContentTypeFlags: %d, dwExpectedFormatTypeFlags: %d, dwFlags: %d, pdwMsgAndCertEncodingType: %d, pdwContentType: %d, pdwFormatType: %d, phCertStore: %p, phMsg: %p, ppvContext: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, SAFE_PTR(pdwMsgAndCertEncodingType, 0), SAFE_PTR(pdwContentType, 0), SAFE_PTR(pdwFormatType, 0), SAFE_PTR(phCertStore, NULL), SAFE_PTR(phMsg, NULL), SAFE_PTR(ppvContext, NULL), result);

    return result;
}

BOOL WINAPI Hooks_LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid)
{
    BOOL result = LookupPrivilegeValueA(lpSystemName, lpName, lpLuid);

    Utils_log("%ws: LookupPrivilegeValueA(lpSystemName: %s, lpName: %s, lpLuid: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), SAFE_STR(lpSystemName, ""), SAFE_STR(lpName, ""), lpLuid, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtClose(HANDLE Handle)
{
    NTSTATUS result = NtClose(Handle);

    Utils_log("%ws: NtClose(Handle: %p) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), Handle, result);

    return result;
}

int WINAPI Hooks_CompareStringW(LCID Locale, DWORD dwCmpFlags, PCNZWCH lpString1, int cchCount1, PCNZWCH lpString2, int cchCount2)
{
    int result = CompareStringW(Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);

    Utils_log("%ws: CompareStringW(Locale: %d, dwCmpFlags: %d, lpString1: %ws, cchCount1: %d, lpString2: %ws, cchCount2: %d) -> int: %d\n",
        Utils_getModuleName(_ReturnAddress()), Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2, result);

    return result;
}

BOOL WINAPI Hooks_StackWalk64(DWORD MachineType, HANDLE hProcess, HANDLE hThread, LPSTACKFRAME64 StackFrame, PVOID ContextRecord, PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine, PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine, PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine, PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress)
{
    BOOL result = StackWalk64(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress);

    Utils_log("%ws: StackWalk64(MachineType: %d, hProcess: %p, hThread: %p, StackFrame: %p, ContextRecord: %p, ReadMemoryRoutine: %p, FunctionTableAccessRoutine: %p, GetModuleBaseRoutine: %p, TranslateAddress: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress, result);

    return result;
}

int WINAPI Hooks_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    int result = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

    Utils_log("%ws: WideCharToMultiByte(CodePage: %u, dwFlags: %d, lpWideCharStr: %ws, cchWideChar: %d, lpMultiByteStr: %s, cbMultiByte: %d, lpDefaultChar: %s, lpUsedDefaultChar: %d) -> int: %d\n",
        Utils_getModuleName(_ReturnAddress()), CodePage, dwFlags, SAFE_STR(lpWideCharStr, L""), cchWideChar, SAFE_STR(lpMultiByteStr, ""), cbMultiByte, SAFE_STR(lpDefaultChar, ""), SAFE_PTR(lpUsedDefaultChar, 0), result);

    return result;
}

BOOL WINAPI Hooks_GetVersionExA(LPOSVERSIONINFOEXA lpVersionInformation)
{
    extern BOOL(WINAPI GetVersionExA)(LPOSVERSIONINFOA);
    BOOL result = GetVersionExA((LPOSVERSIONINFOA)lpVersionInformation);

    Utils_log("%ws: GetVersionExA(lpVersionInformation: %p {dwOSVersionInfoSize: %d, dwMajorVersion : %d, dwMinorVersion: %d, dwBuildNumber: %d, dwPlatformId :%d, wServicePackMajor: %u, wServicePackMinor: %u, wSuiteMask: %u, wProductType: %u}) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpVersionInformation, lpVersionInformation->dwOSVersionInfoSize, lpVersionInformation->dwMajorVersion, lpVersionInformation->dwMinorVersion, lpVersionInformation->dwBuildNumber, lpVersionInformation->dwPlatformId, lpVersionInformation->wServicePackMajor, lpVersionInformation->wServicePackMinor, lpVersionInformation->wSuiteMask, lpVersionInformation->wProductType, result);

    return result;
}

BOOL WINAPI Hooks_GetVersionExW(LPOSVERSIONINFOEXW lpVersionInformation)
{
    extern BOOL(WINAPI GetVersionExW)(LPOSVERSIONINFOW);
    BOOL result = GetVersionExW((LPOSVERSIONINFOW)lpVersionInformation);

    Utils_log("%ws: GetVersionExW(lpVersionInformation: %p {dwOSVersionInfoSize: %d, dwMajorVersion : %d, dwMinorVersion: %d, dwBuildNumber: %d, dwPlatformId :%d, wServicePackMajor: %u, wServicePackMinor: %u, wSuiteMask: %u, wProductType: %u}) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpVersionInformation, lpVersionInformation->dwOSVersionInfoSize, lpVersionInformation->dwMajorVersion, lpVersionInformation->dwMinorVersion, lpVersionInformation->dwBuildNumber, lpVersionInformation->dwPlatformId, lpVersionInformation->wServicePackMajor, lpVersionInformation->wServicePackMinor, lpVersionInformation->wSuiteMask, lpVersionInformation->wProductType, result);

    return result;
}

BOOL WINAPI Hooks_SetupDiGetDeviceRegistryPropertyA(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
{
    BOOL result = SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

    Utils_log("%ws: SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet: %p, DeviceInfoData: %p, Property: %d, PropertyRegDataType: %d, PropertyBuffer: %p, PropertyBufferSize: %d, RequiredSize: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), DeviceInfoSet, DeviceInfoData, Property, SAFE_PTR(PropertyRegDataType, 0), PropertyBuffer, PropertyBufferSize, SAFE_PTR(RequiredSize, 0), result);

    return result;
}

BOOL WINAPI Hooks_CryptHashCertificate(HCRYPTPROV_LEGACY hCryptProv, ALG_ID Algid, DWORD dwFlags, const BYTE* pbEncoded, DWORD cbEncoded, BYTE* pbComputedHash, DWORD* pcbComputedHash)
{
    BOOL result = CryptHashCertificate(hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, pcbComputedHash);

    Utils_log("%ws: CryptHashCertificate(hCryptProv: %lu, Algid: %u, dwFlags: %d, pbEncoded: %p, cbEncoded: %d, pbComputedHash: %p, pcbComputedHash: %d) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, SAFE_PTR(pcbComputedHash, 0), result);

    return result;
}

BOOL WINAPI Hooks_CertFreeCertificateContext(PCCERT_CONTEXT pCertContext)
{
    BOOL result = CertFreeCertificateContext(pCertContext);

    Utils_log("%ws: CertFreeCertificateContext(pCertContext: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), pCertContext, result);

    return result;
}

VOID WINAPI Hooks_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    GetSystemInfo(lpSystemInfo);

    Utils_log("%ws: GetSystemInfo(lpSystemInfo: %p) -> VOID\n",
        Utils_getModuleName(_ReturnAddress()), lpSystemInfo);
}

NTSTATUS NTAPI Hooks_NtQueryDirectoryObject(HANDLE DirectoryObjectHandle, PVOID DirObjInformation, ULONG BufferLength, BOOLEAN GetNextIndex, BOOLEAN IgnoreInputIndex, PULONG ObjectIndex, PULONG DataWritten)
{
    extern NTSTATUS(NTAPI NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
    NTSTATUS result = NtQueryDirectoryObject(DirectoryObjectHandle, DirObjInformation, BufferLength, GetNextIndex, IgnoreInputIndex, ObjectIndex, DataWritten);

    Utils_log("%ws: NtQueryDirectoryObject(DirectoryObjectHandle: %p, DirObjInformation: %p, BufferLength: %lu, GetNextIndex: %d, IgnoreInputIndex: %d, ObjectIndex: %lu, DataWritten: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), DirectoryObjectHandle, DirObjInformation, BufferLength, GetNextIndex, IgnoreInputIndex, SAFE_PTR(ObjectIndex, 0), SAFE_PTR(DataWritten, 0), result);

    return result;
}

NTSTATUS NTAPI Hooks_RtlGetCompressionWorkSpaceSize(ULONG CompressionFormat, PULONG pNeededBufferSize, PULONG pUnknown)
{
    extern NTSTATUS(NTAPI RtlGetCompressionWorkSpaceSize)(ULONG, PULONG, PULONG);
    NTSTATUS result = RtlGetCompressionWorkSpaceSize(CompressionFormat, pNeededBufferSize, pUnknown);

    Utils_log("%ws: RtlGetCompressionWorkSpaceSize(CompressionFormat: %lu, pNeededBufferSize: %lu, pUnknown: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), CompressionFormat, SAFE_PTR(pNeededBufferSize, 0), SAFE_PTR(pUnknown, 0), result);

    return result;
}

int WINAPI Hooks_lstrlenW(LPCWSTR lpString)
{
    int result = lstrlenW(lpString);

    Utils_log("%ws: lstrlenW(lpString: %ws) -> int: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpString, result);

    return result;
}

LPWSTR WINAPI Hooks_lstrcatW(LPWSTR lpString1, LPCWSTR lpString2)
{
    LPWSTR result = lstrcatW(lpString1, lpString2);

    Utils_log("%ws: lstrcatW(lpString1: %ws, lpString2: %ws) -> LPWSTR: %ws\n",
        Utils_getModuleName(_ReturnAddress()), lpString1, lpString2, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtWow64QueryVirtualMemory64(HANDLE ProcessHandle, PVOID64 BaseAddress, DWORD MemoryInformationClass, PVOID Buffer, ULONG64 Length, PULONG64 ResultLength)
{
    NTSTATUS(NTAPI* NtWow64QueryVirtualMemory64)(HANDLE, PVOID64, DWORD, PVOID, ULONG64, PULONG64) = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtWow64QueryVirtualMemory64");
    NTSTATUS result = NtWow64QueryVirtualMemory64(ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength);

    if (!MemoryInformationClass) {
        WCHAR moduleName[MAX_PATH] = { 0 };
        MEMORY_BASIC_INFORMATION64* mbi = Buffer;
        GetModuleFileNameExW(ProcessHandle, (HMODULE)mbi->AllocationBase, moduleName, MAX_PATH);

        Utils_log("%ws: NtWow64QueryVirtualMemory64(ProcessHandle: %p, BaseAddress: %llu, MemoryInformationClass: %d, Buffer: %p {BaseAddress: %llu, AllocationBase: %llu (%ws), AllocationProtect: %d, RegionSize: %llu, State: %d, Protect: %d, Type: %d}, Length: %llu, ResultLength: %p) -> NTSTATUS: 0x%lx\n",
            Utils_getModuleName(_ReturnAddress()), ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, mbi->BaseAddress, mbi->AllocationBase, moduleName, mbi->AllocationProtect, mbi->RegionSize, mbi->State, mbi->Protect, mbi->Type, Length, ResultLength, result);
    } else {
        Utils_log("%ws: NtWow64QueryVirtualMemory64(ProcessHandle: %p, BaseAddress: %llu, MemoryInformationClass: %d, Buffer: %p, Length: %llu, ResultLength: %p) -> NTSTATUS: 0x%lx\n",
            Utils_getModuleName(_ReturnAddress()), ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength, result);
    }
    return result;
}

NTSTATUS NTAPI Hooks_NtWow64ReadVirtualMemory64(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 Size, PULONG64 NumberOfBytesRead)
{
    NTSTATUS(NTAPI* NtWow64ReadVirtualMemory64)(HANDLE, PVOID64, PVOID, ULONG64, PULONG64) = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtWow64ReadVirtualMemory64");
    NTSTATUS result = NtWow64ReadVirtualMemory64(ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesRead);

    Utils_log("%ws: NtWow64ReadVirtualMemory64(ProcessHandle: %p, BaseAddress: %llu, Buffer: %p, Size: %llu, NumberOfBytesRead: %llu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), ProcessHandle, BaseAddress, Buffer, Size, SAFE_PTR(NumberOfBytesRead, 0), result);

    return result;
}

NTSTATUS NTAPI Hooks_NtWow64QueryInformationProcess64(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    NTSTATUS(NTAPI* NtWow64QueryInformationProcess64)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG) = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtWow64QueryInformationProcess64");
    NTSTATUS result = NtWow64QueryInformationProcess64(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    Utils_log("%ws: NtWow64QueryInformationProcess64(ProcessHandle: %p, ProcessInformationClass: %d, ProcessInformation: %p, ProcessInformationLength: %lu, ReturnLength: %lu) -> NTSTATUS: 0x%lx\n",
        Utils_getModuleName(_ReturnAddress()), ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, SAFE_PTR(ReturnLength, 0), result);

    return result;
}

ULONG WINAPI Hooks_GetTcp6Table(PMIB_TCP6TABLE TcpTable, PULONG SizePointer, BOOL Order)
{
    ULONG result = GetTcp6Table(TcpTable, SizePointer, Order);

    Utils_log("%ws: GetTcp6Table(TcpTable: %p, SizePointer: %lu, Order: %d) -> ULONG: %lu\n",
        Utils_getModuleName(_ReturnAddress()), TcpTable, SAFE_PTR(SizePointer, 0), Order, result);

    return result;
}

ULONG WINAPI Hooks_GetUdp6Table(PMIB_UDP6TABLE Udp6Table, PULONG SizePointer, BOOL Order)
{
    ULONG result = GetUdp6Table(Udp6Table, SizePointer, Order);

    Utils_log("%ws: GetUdp6Table(Udp6Table: %p, SizePointer: %lu, Order: %d) -> ULONG: %lu\n",
        Utils_getModuleName(_ReturnAddress()), Udp6Table, SAFE_PTR(SizePointer, 0), Order, result);

    return result;
}

DWORD WINAPI Hooks_GetVersion(VOID)
{
    extern DWORD(WINAPI GetVersion)(VOID);
    DWORD result = GetVersion();

    Utils_log("%ws: GetVersion() -> DWORD: %d\n",
        Utils_getModuleName(_ReturnAddress()), result);

    return result;
}

VOID WINAPI Hooks_GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    GetNativeSystemInfo(lpSystemInfo);

    Utils_log("%ws: GetNativeSystemInfo(lpSystemInfo: %p) -> VOID\n",
        Utils_getModuleName(_ReturnAddress()), lpSystemInfo);
}

BOOL WINAPI Hooks_SnmpExtensionInit(DWORD dwUptimeReference, HANDLE* phSubagentTrapEvent, AsnObjectIdentifier* pFirstSupportedRegion)
{
    BOOL(WINAPI* SnmpExtensionInit)(DWORD, HANDLE*, AsnObjectIdentifier*) = (PVOID)GetProcAddress(GetModuleHandleW(L"inetmib1"), "SnmpExtensionInit");
    
    BOOL result = SnmpExtensionInit(dwUptimeReference, phSubagentTrapEvent, pFirstSupportedRegion);

    Utils_log("%ws: SnmpExtensionInit(dwUptimeReference: %d, phSubagentTrapEvent: %p, pFirstSupportedRegion: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), dwUptimeReference, phSubagentTrapEvent, pFirstSupportedRegion, result);

    return result;
}

BOOL WINAPI Hooks_SnmpExtensionQuery(BYTE bPduType, SnmpVarBindList* pVarBindList, AsnInteger32* pErrorStatus, AsnInteger32* pErrorIndex)
{
    BOOL(WINAPI* SnmpExtensionQuery)(BYTE, SnmpVarBindList*, AsnInteger32*, AsnInteger32*) = (PVOID)GetProcAddress(GetModuleHandleW(L"inetmib1"), "SnmpExtensionQuery");

    BOOL result = SnmpExtensionQuery(bPduType, pVarBindList, pErrorStatus, pErrorIndex);

    Utils_log("%ws: SnmpExtensionQuery(bPduType: %d, pVarBindList: %p {asnType: %d, asnValue: %d}, pErrorStatus: %p, pErrorIndex: %p) -> BOOL: %d\n",
        Utils_getModuleName(_ReturnAddress()), bPduType, pVarBindList, pVarBindList->list->value.asnType, pVarBindList->list->value.asnValue.number, pErrorStatus, pErrorIndex, result);

    return result;
}

LPVOID WINAPI Hooks_SnmpUtilMemAlloc(UINT nBytes)
{
    LPVOID(WINAPI* SnmpUtilMemAlloc)(UINT) = (PVOID)GetProcAddress(GetModuleHandleW(L"snmpapi"), "SnmpUtilMemAlloc");

    LPVOID result = SnmpUtilMemAlloc(nBytes);

    Utils_log("%ws: SnmpUtilMemAlloc(nBytes: %u) -> LPVOID: %p\n",
        Utils_getModuleName(_ReturnAddress()), nBytes, result);

    return result;
}

VOID WINAPI Hooks_SnmpUtilVarBindFree(SnmpVarBind* pVb)
{
    VOID(WINAPI* SnmpUtilVarBindFree)(SnmpVarBind*) = (PVOID)GetProcAddress(GetModuleHandleW(L"snmpapi"), "SnmpUtilVarBindFree");

    SnmpUtilVarBindFree(pVb);

    Utils_log("%ws: SnmpUtilVarBindFree(pVb: %p) -> VOID\n",
        Utils_getModuleName(_ReturnAddress()), pVb);
}

VOID WINAPI Hooks_SnmpExtensionClose(VOID)
{
    VOID(WINAPI* SnmpExtensionClose)(VOID) = (PVOID)GetProcAddress(GetModuleHandleW(L"inetmib1"), "SnmpExtensionClose");

    SnmpExtensionClose();

    Utils_log("%ws: SnmpExtensionClose() -> VOID\n",
        Utils_getModuleName(_ReturnAddress()));
}

LPWSTR WINAPI Hooks_CharUpperW(LPWSTR lpsz)
{
    LPWSTR result = CharUpperW(lpsz);

    if (HIWORD(result)) {
        Utils_log("%ws: CharUpperW(lpsz: %ws) -> LPWSTR: %ws\n",
            Utils_getModuleName(_ReturnAddress()), lpsz, result);
    } else {
        Utils_log("%ws: CharUpperW(lpsz: %ws) -> LPWSTR: %wc\n",
            Utils_getModuleName(_ReturnAddress()), lpsz, result);
    }

    return result;
}

int WINAPI Hooks_lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2)
{
    int result = lstrcmpiW(lpString1, lpString2);

    Utils_log("%ws: lstrcmpiW(lpString1: %ws, lpString2: %ws) -> int: %d\n",
        Utils_getModuleName(_ReturnAddress()), lpString1, lpString2, result);

    return result;
}

int WINAPIV Hooks_wsprintfW(LPWSTR buffer, LPCWSTR format, ...)
{
    va_list args;
    va_start(args, format);
    int result = wvsprintfW(buffer, format, args);
    va_end(args);

    Utils_log("%ws: wsprintfW(buffer: %ws, format: %ws) -> int: %d\n",
        Utils_getModuleName(_ReturnAddress()), buffer, format, result);

    return result;
}
