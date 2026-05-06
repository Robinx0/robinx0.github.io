---
title: "Sleep Obfuscation Deep Dive: Ekko, Zilean, and Foliage"
description: "Advanced sleep obfuscation techniques that encrypt implant memory during sleep cycles to evade EDR memory scanning - covering Ekko, Zilean, Foliage, and custom implementations."
date: 2026-03-29
difficulty: Hard
tags: [sleep-obfuscation, ekko, zilean, foliage, edr-evasion, opsec]
---

## Why Sleep Obfuscation Matters

Modern EDR products don't just hook API calls - they periodically scan process memory for known signatures. A Cobalt Strike beacon sitting in memory with its configuration and strings in plaintext is trivially detected, even during sleep. Sleep obfuscation solves this: before your implant sleeps, it encrypts its own memory. The EDR's periodic scan sees only encrypted noise. When the timer fires, the implant decrypts itself, executes its callback, re-encrypts, and goes back to sleep.

The challenge is that the code doing the encryption must itself remain executable - a chicken-and-egg problem each technique solves differently.

## Understanding the Threat Model

EDR memory scanning works two ways. **Periodic sweeps** walk through process virtual address space looking for byte patterns (YARA, signature hashes) every 30-120 seconds. **Event-triggered scans** fire when suspicious behavior occurs (e.g., a handle to LSASS). Sleep obfuscation defeats the first - your implant is decrypted only for milliseconds during execution, encrypted during seconds-to-minutes of sleep.

## Technique 1: Ekko

Ekko uses `RtlCreateTimer` to queue callbacks that execute during the sleep period. Three timer callbacks chain together:

```c
// Timer 1: Encrypt implant memory with RC4 (SystemFunction032)
USTRING key = { .Length = 16, .MaximumLength = 16, .Buffer = keyBytes };
USTRING data = { .Length = regionSize, .MaximumLength = regionSize, .Buffer = implantBase };
SystemFunction032(&data, &key);  // RC4 encrypt in place

// Timer 2 (after sleep duration): Decrypt with same key
SystemFunction032(&data, &key);  // RC4 is symmetric

// Timer 3: Signal main thread to wake
SetEvent(hSignal);
```

The timer callbacks execute in a **different thread context** than the main implant. The encryption code isn't in the implant's memory region - it's the timer queue's worker thread calling a legitimate ntdll function.

### Execution Flow

```
Main thread → Create timers → WaitForSingleObject(signal)
Timer 1 fires → Encrypt(memory) → Sleep(duration)
Timer 2 fires → Decrypt(memory)
Timer 3 fires → SetEvent(signal)
Main thread wakes → Continue execution
```

## Technique 2: Zilean

Zilean improves on Ekko by using `CreateThreadpoolTimer` instead of `RtlCreateTimer`. The Windows thread pool provides a cleaner execution environment.

### Why Thread Pool Timers Are Better

The callback executes from a Windows thread pool worker, making the call stack look completely normal. No timer queue kernel objects are created. Fewer unique API calls in the import table.

### Critical Improvement: Memory Protection Cycling

Zilean changes memory from RX to RW before encryption, back to RX after decryption. This prevents EDR from flagging RWX regions:

```c
VirtualProtect(implantBase, regionSize, PAGE_READWRITE, &oldProtect);
SystemFunction032(&data, &key);  // Encrypt while RW
// ... sleep ...
SystemFunction032(&data, &key);  // Decrypt
VirtualProtect(implantBase, regionSize, PAGE_EXECUTE_READ, &oldProtect);
```

## Technique 3: Foliage

Foliage uses **Asynchronous Procedure Calls (APCs)** queued to the main implant thread itself. When the thread enters alertable sleep (`SleepEx` with `bAlertable = TRUE`), APCs execute on that same thread - no cross-thread operations, no timer objects.

```c
// Queue encryption
QueueUserAPC((PAPCFUNC)VirtualProtect_RW, hThread, (ULONG_PTR)&args);
QueueUserAPC((PAPCFUNC)Encrypt, hThread, (ULONG_PTR)&encArgs);
SleepEx(duration, TRUE);  // APCs fire, then sleep with encrypted memory

// Woke up - queue decryption
QueueUserAPC((PAPCFUNC)Decrypt, hThread, (ULONG_PTR)&decArgs);
QueueUserAPC((PAPCFUNC)VirtualProtect_RX, hThread, (ULONG_PTR)&args);
SleepEx(0, TRUE);  // Flush decryption APCs
```

## Comparison

| Feature | Ekko | Zilean | Foliage |
|---------|------|--------|---------|
| Mechanism | Timer Queue | Thread Pool Timer | APCs |
| Thread Context | Worker thread | Pool worker | Same thread |
| Memory Prot Cycling | No | Yes | Yes |
| Call Stack Cleanliness | Medium | High | High |
| Kernel Objects Created | Timer + Queue | Pool Timer | None |

## Building Your Own

### Choosing Encryption

`SystemFunction032` (RC4) is a legitimate ntdll export. However, it's now a known IOC. Alternatives include `SystemFunction033`, custom XOR with per-session random key, or AES via BCrypt (looks like legitimate app crypto).

### Protecting the Key

Store it in a separate small allocation (too small for signature scanning), or derive it from a value available after waking (thread ID + timestamp hash).

### Don't Forget the Stack

The stack may contain decrypted strings, function arguments, and return addresses. Capture the stack pointer before encryption and include relevant stack pages in your encryption range.

## Detection

1. Periodic RX→RW→RX transitions on code regions
2. Timer/APC patterns calling crypto functions
3. Thread state analysis - sleeping thread with encrypted adjacent memory
4. Purpose-built tools like BeaconEye and Hunt-Sleeping-Beacons

> Sleep obfuscation is table stakes for modern implant development. Start with Ekko to understand the concepts, then graduate to Foliage for production use.
