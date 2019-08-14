#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <sddl.h>
#include <SoftPub.h>
#include <TlHelp32.h>

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
    else if (!strcmp(lpProcName, "GetProcessImageFileNameW"))
        return (FARPROC)Hooks_GetProcessImageFileNameW;
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
    else if (!strcmp(lpProcName, "WriteProcessMemory"))
        return (FARPROC)Hooks_WriteProcessMemory;
    else if (!strcmp(lpProcName, "MultiByteToWideChar"))
        return (FARPROC)Hooks_MultiByteToWideChar;
    else if (!strcmp(lpProcName, "GetUserNameExW"))
        return (FARPROC)Hooks_GetUserNameExW;
    else if (!strcmp(lpProcName, "GetDriveTypeW"))
        return (FARPROC)Hooks_GetDriveTypeW;
    else if (!strcmp(lpProcName, "RegEnumKeyExA"))
        return (FARPROC)Hooks_RegEnumKeyExA;
    else if (!strcmp(lpProcName, "RegOpenKeyExA"))
        return (FARPROC)Hooks_RegOpenKeyExA;
    else if (!strcmp(lpProcName, "RegCloseKey"))
        return (FARPROC)Hooks_RegCloseKey;
    else if (!strcmp(lpProcName, "RegQueryInfoKeyA"))
        return (FARPROC)Hooks_RegQueryInfoKeyA;
    else if (!strcmp(lpProcName, "RegQueryValueExA"))
        return (FARPROC)Hooks_RegQueryValueExA;
    else if (!strcmp(lpProcName, "OutputDebugStringA"))
        return (FARPROC)Hooks_OutputDebugStringA;
    else if (!strcmp(lpProcName, "GetFileVersionInfoA"))
        return (FARPROC)Hooks_GetFileVersionInfoA;
    else if (!strcmp(lpProcName, "GetFileVersionInfoSizeA"))
        return (FARPROC)Hooks_GetFileVersionInfoSizeA;
    else if (!strcmp(lpProcName, "GetFileVersionInfoSizeW"))
        return (FARPROC)Hooks_GetFileVersionInfoSizeW;
    else if (!strcmp(lpProcName, "GetFileSize"))
        return (FARPROC)Hooks_GetFileSize;
    else if (!strcmp(lpProcName, "GetFileSizeEx"))
        return (FARPROC)Hooks_GetFileSizeEx;
    else if (!strcmp(lpProcName, "GetWindowInfo"))
        return (FARPROC)Hooks_GetWindowInfo;
    else if (!strcmp(lpProcName, "GetWindowsDirectoryA"))
        return (FARPROC)Hooks_GetWindowsDirectoryA;
    else if (!strcmp(lpProcName, "GetWindowsDirectoryW"))
        return (FARPROC)Hooks_GetWindowsDirectoryW;
    else if (!strcmp(lpProcName, "GetModuleHandleA"))
        return (FARPROC)Hooks_GetModuleHandleA;
    else if (!strcmp(lpProcName, "AddVectoredExceptionHandler"))
        return (FARPROC)Hooks_AddVectoredExceptionHandler;
    else if (!strcmp(lpProcName, "AdjustTokenPrivileges"))
        return (FARPROC)Hooks_AdjustTokenPrivileges;
    else if (!strcmp(lpProcName, "CertGetNameStringW"))
        return (FARPROC)Hooks_CertGetNameStringW;
    else if (!strcmp(lpProcName, "CreateFileA"))
        return (FARPROC)Hooks_CreateFileA;
    else if (!strcmp(lpProcName, "CreateFileW"))
        return (FARPROC)Hooks_CreateFileW;
    else if (!strcmp(lpProcName, "GetCurrentProcess"))
        return (FARPROC)Hooks_GetCurrentProcess;
    else if (!strcmp(lpProcName, "GetCurrentProcessId"))
        return (FARPROC)Hooks_GetCurrentProcessId;
    else if (!strcmp(lpProcName, "GetCurrentThread"))
        return (FARPROC)Hooks_GetCurrentThread;
    else if (!strcmp(lpProcName, "GetCurrentThreadId"))
        return (FARPROC)Hooks_GetCurrentThreadId;
    else if (!strcmp(lpProcName, "CreateToolhelp32Snapshot"))
        return (FARPROC)Hooks_CreateToolhelp32Snapshot;
    else if (!strcmp(lpProcName, "EnumChildWindows"))
        return (FARPROC)Hooks_EnumChildWindows;
    else if (!strcmp(lpProcName, "EnumProcesses"))
        return (FARPROC)Hooks_EnumProcesses;
    else if (!strcmp(lpProcName, "EnumWindows"))
        return (FARPROC)Hooks_EnumWindows;
    else if (!strcmp(lpProcName, "GetProcessTimes"))
        return (FARPROC)Hooks_GetProcessTimes;
    else if (!strcmp(lpProcName, "WaitForSingleObject"))
        return (FARPROC)Hooks_WaitForSingleObject;
    else if (!strcmp(lpProcName, "VirtualAlloc"))
        return (FARPROC)Hooks_VirtualAlloc;
    else if (!strcmp(lpProcName, "VirtualAllocEx"))
        return (FARPROC)Hooks_VirtualAllocEx;
    else if (!strcmp(lpProcName, "VirtualFree"))
        return (FARPROC)Hooks_VirtualFree;
    else if (!strcmp(lpProcName, "VirtualFreeEx"))
        return (FARPROC)Hooks_VirtualFreeEx;
    else if (!strcmp(lpProcName, "VirtualProtect"))
        return (FARPROC)Hooks_VirtualProtect;
    else if (!strcmp(lpProcName, "VirtualQuery"))
        return (FARPROC)Hooks_VirtualQuery;
    else if (!strcmp(lpProcName, "VirtualQueryEx"))
        return (FARPROC)Hooks_VirtualQueryEx;
    else if (!strcmp(lpProcName, "SuspendThread"))
        return (FARPROC)Hooks_SuspendThread;
    else if (!strcmp(lpProcName, "SwitchToThread"))
        return (FARPROC)Hooks_SwitchToThread;
    else if (!strcmp(lpProcName, "Wow64EnableWow64FsRedirection"))
        return (FARPROC)Hooks_Wow64EnableWow64FsRedirection;
    else if (!strcmp(lpProcName, "WinVerifyTrust"))
        return (FARPROC)Hooks_WinVerifyTrust;
    else if (!strcmp(lpProcName, "Sleep"))
        return (FARPROC)Hooks_Sleep;
    else if (!strcmp(lpProcName, "CreateFileMappingW"))
        return (FARPROC)Hooks_CreateFileMappingW;
    else if (!strcmp(lpProcName, "OpenProcessToken"))
        return (FARPROC)Hooks_OpenProcessToken;
    else if (!strcmp(lpProcName, "EnumServicesStatusA"))
        return (FARPROC)Hooks_EnumServicesStatusA;
    else if (!strcmp(lpProcName, "EnumServicesStatusW"))
        return (FARPROC)Hooks_EnumServicesStatusW;
    else if (!strcmp(lpProcName, "FindFirstVolumeW"))
        return (FARPROC)Hooks_FindFirstVolumeW;
    else if (!strcmp(lpProcName, "FindNextVolumeW"))
        return (FARPROC)Hooks_FindNextVolumeW;
    else if (!strcmp(lpProcName, "FlushInstructionCache"))
        return (FARPROC)Hooks_FlushInstructionCache;
    else if (!strcmp(lpProcName, "GetVolumePathNamesForVolumeNameW"))
        return (FARPROC)Hooks_GetVolumePathNamesForVolumeNameW;
    else if (!strcmp(lpProcName, "GetWindowThreadProcessId"))
        return (FARPROC)Hooks_GetWindowThreadProcessId;
    else if (!strcmp(lpProcName, "Heap32First"))
        return (FARPROC)Hooks_Heap32First;
    else if (!strcmp(lpProcName, "NtQuerySystemInformation"))
        return (FARPROC)Hooks_NtQuerySystemInformation;
    else if (!strcmp(lpProcName, "ConvertSidToStringSidA"))
        return (FARPROC)Hooks_ConvertSidToStringSidA;
    else if (!strcmp(lpProcName, "CryptMsgGetParam"))
        return (FARPROC)Hooks_CryptMsgGetParam;
    else if (!strcmp(lpProcName, "NtQueryInformationProcess"))
        return (FARPROC)Hooks_NtQueryInformationProcess;
    else if (!strcmp(lpProcName, "EncodePointer"))
        return (FARPROC)Hooks_EncodePointer;
    else if (!strcmp(lpProcName, "NtQueryInformationThread"))
        return (FARPROC)Hooks_NtQueryInformationThread;
    else if (!strcmp(lpProcName, "OpenSCManagerA"))
        return (FARPROC)Hooks_OpenSCManagerA;
    else if (!strcmp(lpProcName, "OpenThread"))
        return (FARPROC)Hooks_OpenThread;
    else if (!strcmp(lpProcName, "Process32FirstW"))
        return (FARPROC)Hooks_Process32FirstW;
    else if (!strcmp(lpProcName, "Process32NextW"))
        return (FARPROC)Hooks_Process32NextW;
    else if (!strcmp(lpProcName, "WriteFile"))
        return (FARPROC)Hooks_WriteFile;
        
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

DWORD WINAPI Hooks_GetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize)
{
    DWORD result = GetProcessImageFileNameW(hProcess, lpImageFileName, nSize);

    Utils_log("GetProcessImageFileNameW(hProcess: %p, lpImageFileName: %ws, nSize: %d) -> DWORD: %d\n", hProcess, lpImageFileName, nSize, result);

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

    Utils_log("NtOpenProcess(ProcessHandle: %p, DesiredAccess: %d, ObjectAttributes: %p, ClientId: %p) -> NTSTATUS: %ld\n", ProcessHandle, DesiredAccess, ObjectAttributes, ClientId, result);

    return result;
}

BOOL WINAPI Hooks_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    BOOL result = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    Utils_log("ReadProcessMemory(hProcess: %p, lpBaseAddress: %p, lpBuffer: %p, nSize: %d, lpNumberOfBytesRead: %p) -> BOOL: %d\n", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead, result);

    return result;
}

BOOL WINAPI Hooks_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    BOOL result = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    Utils_log("WriteProcessMemory(hProcess: %p, lpBaseAddress: %p, lpBuffer: %p, nSize: %d, lpNumberOfBytesWritten: %p) -> BOOL: %d\n", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten, result);

    return result;
}

int WINAPI Hooks_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
{
    int result = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);

    Utils_log("MultiByteToWideChar(CodePage: %u, dwFlags: %d, lpMultiByteStr: %s, cbMultiByte: %d, lpWideCharStr: %ws, cchWideChar: %d) -> int: %d\n", CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar, result);

    return result;
}

BOOLEAN SEC_ENTRY Hooks_GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize)
{
    BOOLEAN result = GetUserNameExW(NameFormat, lpNameBuffer, nSize);

    Utils_log("GetUserNameExW(NameFormat: %d, lpNameBuffer: %ws, nSize: %lu) -> BOOLEAN: %d\n", NameFormat, lpNameBuffer, *nSize, result);

    return result;
}

UINT WINAPI Hooks_GetDriveTypeW(LPCWSTR lpRootPathName)
{
    UINT result = GetDriveTypeW(lpRootPathName);

    Utils_log("GetDriveTypeW(lpRootPathName: %ws) -> UINT: %u\n", lpRootPathName, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
{
    LSTATUS result = RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);

    Utils_log("RegEnumKeyExA(hKey: %p, dwIndex: %d, lpName: %s, lpcchName: %d, lpReserved: %p, lpClass: %p, lpcchClass: %p, lpftLastWriteTime: %p) -> LSTATUS: %ld\n", hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    LSTATUS result = RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    Utils_log("RegOpenKeyExA(hKey: %p, lpSubKey: %s, ulOptions: %d, samDesired: %d, phkResult: %p) -> LSTATUS: %ld\n", hKey, SAFE_STR(lpSubKey, ""), ulOptions, samDesired, phkResult, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegCloseKey(HKEY hKey)
{
    LSTATUS result = RegCloseKey(hKey);

    Utils_log("RegCloseKey(hKey: %p) -> LSTATUS: %ld\n", hKey, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime)
{
    LSTATUS result = RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);

    Utils_log("RegQueryInfoKeyA(hKey: %p, lpClass: %s, lpcchClass: %p, lpReserved: %p, lpcSubKeys: %p, lpcbMaxSubKeyLen: %p, lpcbMaxClassLen: %p, lpcValues: %p, lpcbMaxValueNameLen: %p, lpcbMaxValueLen: %p, lpcbSecurityDescriptor: %p, lpftLastWriteTime: %p) -> LSTATUS: %ld\n", hKey, SAFE_STR(lpClass, ""), lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime, result);

    return result;
}

LSTATUS APIENTRY Hooks_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LSTATUS result = RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    Utils_log("RegQueryValueExA(hKey: %p, lpValueName: %s, lpcchClass: %p, lpReserved: %p, lpType: %p, lpData: %p, lpcbData: %p) -> LSTATUS: %ld\n", hKey, SAFE_STR(lpValueName, ""), lpReserved, lpType, lpData, lpcbData, result);

    return result;
}

VOID WINAPI Hooks_OutputDebugStringA(LPCSTR lpOutputString)
{
    OutputDebugStringA(lpOutputString);

    Utils_log("OutputDebugStringA(lpOutputString: %s) -> VOID\n", lpOutputString);
}

BOOL APIENTRY Hooks_GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    BOOL result = GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);

    Utils_log("GetFileVersionInfoA(lptstrFilename: %s, dwHandle: %d, dwLen: %d, lpData: %p) -> BOOL: %d\n", lptstrFilename, dwHandle, dwLen, lpData, result);

    return result;
}

BOOL APIENTRY Hooks_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    BOOL result = GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);

    Utils_log("GetFileVersionInfoW(lptstrFilename: %ws, dwHandle: %d, dwLen: %d, lpData: %p) -> BOOL: %d\n", lptstrFilename, dwHandle, dwLen, lpData, result);

    return result;
}

DWORD APIENTRY Hooks_GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle)
{
    DWORD result = GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);

    Utils_log("GetFileVersionInfoSizeA(lptstrFilename: %s, lpdwHandle: %p) -> DWORD: %d\n", lptstrFilename, lpdwHandle, result);

    return result;
}

DWORD APIENTRY Hooks_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
    DWORD result = GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);

    Utils_log("GetFileVersionInfoSizeW(lptstrFilename: %ws, lpdwHandle: %p) -> DWORD: %d\n", lptstrFilename, lpdwHandle, result);

    return result;
}

DWORD WINAPI Hooks_GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
{
    DWORD result = GetFileSize(hFile, lpFileSizeHigh);
    WCHAR filename[MAX_PATH];

    Utils_log("GetFileSize(hFile: %p (%ws), lpFileSizeHigh: %p) -> DWORD: %d\n", hFile, GetFinalPathNameByHandleW(hFile, filename, MAX_PATH, 0) ? filename : L"", lpFileSizeHigh, result);

    return result;
}

BOOL WINAPI Hooks_GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
    BOOL result = GetFileSizeEx(hFile, lpFileSize);
    WCHAR filename[MAX_PATH];

    Utils_log("GetFileSizeEx(hFile: %p (%ws), lpFileSize: %p) -> BOOL: %d\n", hFile, GetFinalPathNameByHandleW(hFile, filename, MAX_PATH, 0) ? filename : L"", lpFileSize, result);

    return result;
}

BOOL WINAPI Hooks_GetWindowInfo(HWND hwnd, PWINDOWINFO pwi)
{
    BOOL result = GetWindowInfo(hwnd, pwi);

    Utils_log("GetWindowInfo(hwnd: %p, pwi: %p) -> BOOL: %d\n", hwnd, pwi, result);

    return result;
}

UINT WINAPI Hooks_GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize)
{
    UINT result = GetWindowsDirectoryA(lpBuffer, uSize);

    Utils_log("GetWindowsDirectoryA(lpBuffer: %s, uSize: %u) -> UINT: %u\n", lpBuffer, uSize, result);

    return result;
}

UINT WINAPI Hooks_GetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize)
{
    UINT result = GetWindowsDirectoryW(lpBuffer, uSize);

    Utils_log("GetWindowsDirectoryW(lpBuffer: %ws, uSize: %u) -> UINT: %u\n", lpBuffer, uSize, result);

    return result;
}

HMODULE WINAPI Hooks_GetModuleHandleA(LPCSTR lpModuleName)
{
    HMODULE result = GetModuleHandleA(lpModuleName);

    Utils_log("GetModuleHandleA(lpModuleName: %s) -> HMODULE: %p\n", SAFE_STR(lpModuleName, ""), result);

    return result;
}

PVOID WINAPI Hooks_AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
{
    PVOID result = AddVectoredExceptionHandler(First, Handler);

    Utils_log("AddVectoredExceptionHandler(First: %lu, Handler: %p) -> PVOID: %p\n", First, Handler, result);

    return result;
}

BOOL WINAPI Hooks_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
{
    BOOL result = AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);

    Utils_log("AdjustTokenPrivileges(TokenHandle: %p, DisableAllPrivileges: %d, NewState: %p, BufferLength: %d, PreviousState: %p, ReturnLength: %p) -> BOOL: %d\n", TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength, result);

    return result;
}

DWORD WINAPI Hooks_CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void* pvTypePara, LPWSTR pszNameString, DWORD cchNameString)
{
    DWORD result = CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString);

    Utils_log("CertGetNameStringW(pCertContext: %p, dwType: %d, dwFlags: %p, pvTypePara: %p, pszNameString: %ws, cchNameString: %d) -> DWORD: %d\n", pCertContext, dwType, dwFlags, pvTypePara, SAFE_STR(pszNameString, L""), cchNameString, result);

    return result;
}

HANDLE WINAPI Hooks_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE result = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    Utils_log("CreateFileA(lpFileName: %s, dwDesiredAccess: %d, dwShareMode: %d, lpSecurityAttributes: %p, dwCreationDisposition: %d, dwFlagsAndAttributes: %d, hTemplateFile: %p) -> HANDLE: %p\n", lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, result);

    return result;
}

HANDLE WINAPI Hooks_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE result = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    Utils_log("CreateFileW(lpFileName: %ws, dwDesiredAccess: %d, dwShareMode: %d, lpSecurityAttributes: %p, dwCreationDisposition: %d, dwFlagsAndAttributes: %d, hTemplateFile: %p) -> HANDLE: %p\n", lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, result);

    return result;
}

HANDLE WINAPI Hooks_GetCurrentProcess(VOID)
{
    HANDLE result = GetCurrentProcess();

    Utils_log("GetCurrentProcess() -> HANDLE: %p\n", result);

    return result;;
}

DWORD WINAPI Hooks_GetCurrentProcessId(VOID)
{
    DWORD result = GetCurrentProcessId();

    Utils_log("GetCurrentProcessId() -> DWORD: %d\n", result);

    return result;;
}

HANDLE WINAPI Hooks_GetCurrentThread(VOID)
{
    HANDLE result = GetCurrentThread();

    Utils_log("GetCurrentThread() -> HANDLE: %p\n", result);

    return result;
}

DWORD WINAPI Hooks_GetCurrentThreadId(VOID)
{
    DWORD result = GetCurrentThreadId();

    Utils_log("GetCurrentThreadId() -> DWORD: %d\n", result);

    return result;
}

HANDLE WINAPI Hooks_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    HANDLE result = CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

    Utils_log("CreateToolhelp32Snapshot(dwFlags: %d, th32ProcessID: %d) -> HANDLE: %p\n", dwFlags, th32ProcessID, result);

    return result;
}

BOOL WINAPI Hooks_EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
    BOOL result = EnumChildWindows(hWndParent, lpEnumFunc, lParam);

    Utils_log("EnumChildWindows(hWndParent: %p, lpEnumFunc: %p, lParam: %ld) -> BOOL: %d\n", hWndParent, lpEnumFunc, lParam, result);

    return result;
}

BOOL WINAPI Hooks_EnumProcesses(DWORD* lpidProcess, DWORD cb, LPDWORD lpcbNeeded)
{
    BOOL result = EnumProcesses(lpidProcess, cb, lpcbNeeded);

    Utils_log("EnumProcesses(lpidProcess: %p, cb: %d, lpcbNeeded: %p) -> BOOL: %d\n", lpidProcess, cb, lpcbNeeded, result);

    return result;
}

BOOL WINAPI Hooks_EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
    BOOL result = EnumWindows(lpEnumFunc, lParam);

    Utils_log("EnumWindows(lpEnumFunc: %p, lParam: %ld) -> BOOL: %d\n", lpEnumFunc, lParam, result);

    return result;
}

BOOL WINAPI Hooks_GetProcessTimes(HANDLE hProcess, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime)
{
    BOOL result = GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);

    Utils_log("GetProcessTimes(hProcess: %p, lpCreationTime: %p, lpExitTime: %p, lpKernelTime: %p, lpUserTime: %p) -> BOOL: %d\n", hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime, result);

    return result;
}

DWORD WINAPI Hooks_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    DWORD result = WaitForSingleObject(hHandle, dwMilliseconds);

    Utils_log("WaitForSingleObject(hHandle: %p, dwMilliseconds: %d) -> DWORD: %d\n", hHandle, dwMilliseconds, result);

    return result;
}

LPVOID WINAPI Hooks_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID result = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    Utils_log("VirtualAlloc(lpAddress: %p, dwSize: %d, flAllocationType: %d, flProtect: %d) -> LPVOID: %p\n", lpAddress, dwSize, flAllocationType, flProtect, result);

    return result;
}

LPVOID WINAPI Hooks_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID result = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    Utils_log("VirtualAllocEx(hProcess: %p, lpAddress: %p, dwSize: %d, flAllocationType: %d, flProtect: %d) -> LPVOID: %p\n", hProcess, lpAddress, dwSize, flAllocationType, flProtect, result);

    return result;
}

BOOL WINAPI Hooks_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = VirtualFree(lpAddress, dwSize, dwFreeType);

    Utils_log("VirtualFree(lpAddress: %p, dwSize: %d, dwFreeType: %d) -> BOOL: %d\n", lpAddress, dwSize, dwFreeType, result);

    return result;
}

BOOL WINAPI Hooks_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);

    Utils_log("VirtualFreeEx(hProcess: %p, lpAddress: %p, dwSize: %d, dwFreeType: %d) -> BOOL: %d\n", hProcess, lpAddress, dwSize, dwFreeType, result);

    return result;
}

BOOL WINAPI Hooks_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    BOOL result = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    Utils_log("VirtualProtect(lpAddress: %p, dwSize: %d, flNewProtect: %d, lpflOldProtect: %d) -> BOOL: %d\n", lpAddress, dwSize, flNewProtect, *lpflOldProtect, result);

    return result;
}

SIZE_T WINAPI Hooks_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    SIZE_T result = VirtualQuery(lpAddress, lpBuffer, dwLength);

    Utils_log("VirtualQuery(lpAddress: %p, lpBuffer: %p, dwLength: %d) -> SIZE_T: %d\n", lpAddress, lpBuffer, dwLength, result);

    return result;
}

SIZE_T WINAPI Hooks_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    SIZE_T result = VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    WCHAR moduleName[MAX_PATH] = { 0 };
    GetModuleFileNameExW(hProcess, lpBuffer->AllocationBase, moduleName, MAX_PATH);
    Utils_log("VirtualQueryEx(hProcess: %p, lpAddress: %p, lpBuffer: %p (BaseAddress: %p, AllocationBase: %p (%ws), AllocationProtect: %d, RegionSize: %d, State: %d, Protect: %d, Type: %d), dwLength: %d) -> SIZE_T: %d\n", hProcess, lpAddress, lpBuffer, lpBuffer->BaseAddress, lpBuffer->AllocationBase, moduleName, lpBuffer->AllocationProtect, lpBuffer->RegionSize, lpBuffer->State, lpBuffer->Protect, lpBuffer->Type, dwLength, result);

    return result;
}

DWORD WINAPI Hooks_SuspendThread(HANDLE hThread)
{
    DWORD result = SuspendThread(hThread);

    Utils_log("SuspendThread(hThread: %p) -> DWORD: %d\n", hThread, result);

    return result;
}

BOOL WINAPI Hooks_SwitchToThread(VOID)
{
    BOOL result = SwitchToThread();

    Utils_log("SwitchToThread() -> BOOL: %d\n", result);

    return result;
}

BOOLEAN WINAPI Hooks_Wow64EnableWow64FsRedirection(BOOLEAN Wow64FsEnableRedirection)
{
    BOOLEAN result = Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection);

    Utils_log("Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection: %d) -> BOOLEAN: %d\n", Wow64FsEnableRedirection, result);

    return result;
}

LONG WINAPI Hooks_WinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData)
{
    LONG result = WinVerifyTrust(hwnd, pgActionID, pWVTData);

    Utils_log("WinVerifyTrust(hwnd: %d, pgActionID: %p, pWVTData: %p) -> LONG: %ld\n", hwnd, pgActionID, pWVTData, result);

    return result;
}

VOID WINAPI Hooks_Sleep(DWORD dwMilliseconds)
{
    Sleep(dwMilliseconds);

    Utils_log("Sleep(dwMilliseconds: %d) -> VOID\n", dwMilliseconds);
}

HANDLE WINAPI Hooks_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)
{
    HANDLE result = CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

    Utils_log("CreateFileMappingW(hFile: %p, lpFileMappingAttributes: %p, flProtect: %d, dwMaximumSizeHigh: %d, dwMaximumSizeLow: %d, lpName: %ws) -> HANDLE: %p\n", hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, result);

    return result;
}

BOOL WINAPI Hooks_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
{
    BOOL result = OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);

    Utils_log("OpenProcessToken(ProcessHandle: %p, DesiredAccess: %d, TokenHandle %p) -> BOOL: %d\n", ProcessHandle, DesiredAccess, TokenHandle, result);

    return result;
}

BOOL WINAPI Hooks_EnumServicesStatusA(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSA lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle)
{
    BOOL result = EnumServicesStatusA(hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

    Utils_log("EnumServicesStatusA(hSCManager: %p, dwServiceType: %d, dwServiceState: %d, lpServices: %p, cbBufSize: %d, pcbBytesNeeded: %p, lpServicesReturned: %p, lpResumeHandle: %p) -> BOOL: %d\n", hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, result);

    return result;
}

BOOL WINAPI Hooks_EnumServicesStatusW(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSW lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle)
{
    BOOL result = EnumServicesStatusW(hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

    Utils_log("EnumServicesStatusW(hSCManager: %p, dwServiceType: %d, dwServiceState: %d, lpServices: %p, cbBufSize: %d, pcbBytesNeeded: %p, lpServicesReturned: %p, lpResumeHandle: %p) -> BOOL: %d\n", hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, result);

    return result;
}

HANDLE WINAPI Hooks_FindFirstVolumeW(LPWSTR lpszVolumeName, DWORD cchBufferLength)
{
    HANDLE result = FindFirstVolumeW(lpszVolumeName, cchBufferLength);

    Utils_log("FindFirstVolumeW(lpszVolumeName: %ws, cchBufferLength: %d) -> HANDLE: %p\n", lpszVolumeName, cchBufferLength, result);

    return result;
}

BOOL WINAPI Hooks_FindNextVolumeW(HANDLE hFindVolume, LPWSTR lpszVolumeName, DWORD cchBufferLength)
{
    BOOL result = FindNextVolumeW(hFindVolume, lpszVolumeName, cchBufferLength);

    Utils_log("FindNextVolumeW(hFindVolume: %p, lpszVolumeName: %ws, cchBufferLength: %d) -> BOOL: %d\n", hFindVolume, lpszVolumeName, cchBufferLength, result);

    return result;
}

BOOL WINAPI Hooks_FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
{
    BOOL result = FlushInstructionCache(hProcess, lpBaseAddress, dwSize);

    Utils_log("FlushInstructionCache(hProcess: %p, lpBaseAddress: %p, dwSize: %d) -> BOOL: %d\n", hProcess, lpBaseAddress, dwSize, result);

    return result;
}

BOOL WINAPI Hooks_GetVolumePathNamesForVolumeNameW(LPCWSTR lpszVolumeName, LPWCH lpszVolumePathNames, DWORD cchBufferLength, PDWORD lpcchReturnLength)
{
    BOOL result = GetVolumePathNamesForVolumeNameW(lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength);

    Utils_log("GetVolumePathNamesForVolumeNameW(lpszVolumeName: %ws, lpszVolumePathNames: %ws, cchBufferLength: %d, lpcchReturnLength: %p) -> BOOL: %d\n", lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength, result);

    return result;
}

DWORD WINAPI Hooks_GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId)
{
    DWORD result = GetWindowThreadProcessId(hWnd, lpdwProcessId);

    Utils_log("GetWindowThreadProcessId(hWnd: %p, lpdwProcessId: %p) -> DWORD: %d\n", hWnd, lpdwProcessId, result);

    return result;
}

BOOL WINAPI Hooks_Heap32First(LPHEAPENTRY32 lphe, DWORD th32ProcessID, ULONG_PTR th32HeapID)
{
    BOOL result = Heap32First(lphe, th32ProcessID, th32HeapID);

    Utils_log("Heap32First(lphe: %p, th32ProcessID: %d, th32HeapID: %lu) -> BOOL: %d\n", lphe, th32ProcessID, th32HeapID, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS result = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    Utils_log("NtQuerySystemInformation(SystemInformationClass: %d, SystemInformation: %p, SystemInformationLength: %lu, ReturnLength: %p) -> NTSTATUS: 0x%lx\n", SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength, result);

    return result;
}

BOOL NTAPI Hooks_ConvertSidToStringSidA(PSID Sid, LPSTR* StringSid)
{
    BOOL result = ConvertSidToStringSidA(Sid, StringSid);

    Utils_log("ConvertSidToStringSidA(Sid: %p, StringSid: %s) -> BOOL: %d\n", Sid, *StringSid, result);

    return result;
}

BOOL WINAPI Hooks_CryptMsgGetParam(HCRYPTMSG hCryptMsg, DWORD dwParamType, DWORD dwIndex, void* pvData, DWORD* pcbData)
{
    BOOL result = CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData);

    Utils_log("CryptMsgGetParam(hCryptMsg: %p, dwParamType: %d, dwIndex: %d, pvData: %p, pcbData: %p) -> BOOL: %d\n", hCryptMsg, dwParamType, dwIndex, pvData, pcbData, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    NTSTATUS result = NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    Utils_log("NtQueryInformationProcess(ProcessHandle: %p, ProcessInformationClass: %d, ProcessInformation: %p, ProcessInformationLength: %lu, ReturnLength: %p) -> NTSTATUS: 0x%lx\n", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength, result);

    return result;
}

PVOID WINAPI Hooks_EncodePointer(PVOID Ptr)
{
    PVOID result = EncodePointer(Ptr);

    Utils_log("EncodePointer(Ptr: %p) -> PVOID: %p\n", Ptr, result);

    return result;
}

NTSTATUS NTAPI Hooks_NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
    NTSTATUS result = NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

    Utils_log("NtQueryInformationThread(ThreadHandle: %p, ThreadInformationClass: %d, ThreadInformation: %p, ThreadInformationLength: %lu, ReturnLength: %p) -> NTSTATUS: 0x%lx\n", ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength, result);

    return result;
}

SC_HANDLE WINAPI Hooks_OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess)
{
    SC_HANDLE result = OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess);

    Utils_log("OpenSCManagerA(lpMachineName: %s, lpDatabaseName: %s, dwDesiredAccess: %d) -> SC_HANDLE: %p\n", SAFE_STR(lpMachineName, ""), SAFE_STR(lpDatabaseName, ""), dwDesiredAccess, result);

    return result;
}

HANDLE WINAPI Hooks_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
    HANDLE result = OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);

    Utils_log("OpenThread(dwDesiredAccess: %d, bInheritHandle: %d, dwThreadId: %d) -> HANDLE: %p\n", dwDesiredAccess, bInheritHandle, dwThreadId, result);

    return result;
}

BOOL WINAPI Hooks_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL result = Process32FirstW(hSnapshot, lppe);

    Utils_log("Process32FirstW(hSnapshot: %p, lppe: %p) -> BOOL: %d\n", hSnapshot, lppe, result);

    return result;
}

BOOL WINAPI Hooks_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
    BOOL result = Process32NextW(hSnapshot, lppe);

    Utils_log("Process32NextW(hSnapshot: %p, lppe: %p) -> BOOL: %d\n", hSnapshot, lppe, result);

    return result;
}

BOOL WINAPI Hooks_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    BOOL result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

    Utils_log("WriteFile(hFile: %p, lpBuffer: %p, nNumberOfBytesToWrite: %d, lpNumberOfBytesWritten: %p, lpOverlapped: %p) -> BOOL: %d\n", hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped, result);

    return result;
}
