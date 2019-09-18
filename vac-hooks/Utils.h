#pragma once

#include <Windows.h>

PVOID Utils_findPattern(PCWSTR, PCSTR, SIZE_T);
VOID Utils_hookImport(PCWSTR, PCSTR, PCSTR, PVOID);
VOID Utils_log(PCSTR, ...);
PCWSTR Utils_getModuleName(PVOID);
PCSTR Utils_getModuleTimestamp(PVOID);

#define UTILS_HASH_1(s, i, val) (val * 65599u + ((i) < strlen(s) ? s[strlen(s) - 1 - (i)] : 0))
#define UTILS_HASH_4(s, i, val) UTILS_HASH_1(s, i, UTILS_HASH_1(s, i + 1, UTILS_HASH_1(s, i + 2, UTILS_HASH_1(s, i + 3, val))))
#define UTILS_HASH_16(s, i, val) UTILS_HASH_4(s, i, UTILS_HASH_4(s, i + 4, UTILS_HASH_4(s, i + 8, UTILS_HASH_4(s, i + 12, val))))
#define UTILS_HASH_64(s, i, val) UTILS_HASH_16(s, i, UTILS_HASH_16(s, i + 16, UTILS_HASH_16(s, i + 32, UTILS_HASH_16(s, i + 48, val))))
#define UTILS_HASH_256(s, i, val) UTILS_HASH_64(s, i, UTILS_HASH_64(s, i + 64, UTILS_HASH_64(s, i + 128, UTILS_HASH_64(s, i + 192, val))))

#define UTILS_HASH(s) ((UINT)(UTILS_HASH_256(s, 0, 0) ^ UTILS_HASH_256(s, 0, 0) >> 16))

UINT Utils_hashRuntime(PCSTR);

#define SAFE_STR(s, fallback) (s ? s : fallback)
#define SAFE_PTR(p, fallback) (p ? *p : fallback)
