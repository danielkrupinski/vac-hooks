#include <shlwapi.h>
#include <stdbool.h>
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <time.h>

#include "Utils.h"

PVOID Utils_findPattern(PCWSTR module, PCSTR pattern, SIZE_T offset)
{
    MODULEINFO moduleInfo;
    HMODULE moduleHandle = GetModuleHandleW(module);

    if (moduleHandle && GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(moduleInfo))) {
        for (PCHAR c = moduleInfo.lpBaseOfDll; c != (PBYTE)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage; c++) {
            bool matched = true;

            for (PCSTR patternIt = pattern, it = c; *patternIt; patternIt++, it++) {
                if (*patternIt != '?' && *it != *patternIt) {
                    matched = false;
                    break;
                }
            }
            if (matched)
                return c + offset;
        }
    }
    return NULL;
}

VOID Utils_hookImport(PCWSTR moduleName, PCSTR importModuleName, PCSTR functionName, PVOID fun)
{
    PBYTE module = (PBYTE)GetModuleHandleW(moduleName);

    if (module) {
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)(module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        for (PIMAGE_IMPORT_DESCRIPTOR import = imports; import->Name; import++) {
            if (_strcmpi(module + import->Name, importModuleName))
                continue;

            for (PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)(module + import->OriginalFirstThunk), first_thunk = (PIMAGE_THUNK_DATA)(module + import->FirstThunk); original_first_thunk->u1.AddressOfData; original_first_thunk++, first_thunk++) {
                if (strcmp((PCSTR)((PIMAGE_IMPORT_BY_NAME)(module + original_first_thunk->u1.AddressOfData))->Name, functionName))
                    continue;

                PDWORD functionAddress = &first_thunk->u1.Function;

                DWORD old;
                if (VirtualProtect(functionAddress, sizeof(fun), PAGE_READWRITE, &old)) {
                    *functionAddress = (DWORD)fun;
                    VirtualProtect(functionAddress, sizeof(fun), old, &old);
                }
                break;
            }
            break;
        }
    }
}

#define LOG_FILENAME "vac-hooks.txt"
#define LOG_BUFFER_SIZE 500

VOID Utils_log(PCSTR format, ...)
{
    CHAR buf[LOG_BUFFER_SIZE];
    static CHAR lastLine[LOG_BUFFER_SIZE];

    va_list args;
    va_start(args, format);
    vsprintf_s(buf, sizeof(buf), format, args);
    va_end(args);

    if (strcmp(buf, lastLine)) {
        FILE* out;
        if (!fopen_s(&out, LOG_FILENAME, "a")) {
            fprintf(out, buf);
            fclose(out);
        }
        strcpy_s(lastLine, sizeof(lastLine), buf);
    }
}

PCWSTR Utils_getModuleName(PVOID address)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        static WCHAR fileName[MAX_PATH] = { 0 };

        if (GetModuleFileNameW(mbi.AllocationBase, fileName, sizeof(fileName) / sizeof(WCHAR))) {
            PathStripPathW(fileName);
            swprintf(fileName + lstrlenW(fileName), MAX_PATH - lstrlenW(fileName), L" + 0x%x", (DWORD)address - (DWORD)mbi.AllocationBase);
            return fileName;
        }
    }
    return L"?";
}

PCSTR Utils_getModuleTimestamp(PVOID module)
{
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
    PIMAGE_DEBUG_DIRECTORY debugDirectory = (PIMAGE_DEBUG_DIRECTORY)((PBYTE)module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

    time_t timestamp = debugDirectory->TimeDateStamp;
    struct tm time;
    if (!gmtime_s(&time, &timestamp)) {
        static CHAR timestampString[26];
        if (!asctime_s(timestampString, sizeof(timestampString), &time))
            return timestampString;
    }
    return NULL;
}

UINT Utils_hashRuntime(PCSTR str)
{
    UINT hash = 0;
    for (SIZE_T i = 0; i < strlen(str); i++)
        hash = 65599 * hash + str[i];
    return hash ^ (hash >> 16);
}
