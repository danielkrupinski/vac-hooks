#include <stdbool.h>
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

#include "Utils.h"

PVOID findPattern(PCWSTR module, PCSTR pattern, SIZE_T offset)
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
    WCHAR buf[100];
    swprintf(buf, sizeof(buf) / sizeof(WCHAR), L"Failed to find pattern in %s.dll!", module);
    MessageBoxW(NULL, buf, L"Error", MB_OK | MB_ICONERROR);
    exit(EXIT_FAILURE);
}
