---
title: "IIUC CyberCon 2022: CTF Challenge Solutions"
description: "Solutions for challenges from the IIUC CyberCon 2022 CTF organized by IIUC Cyber Analyst Team (CyberWiz) - covering web exploitation, forensics with Volatility, classic crypto on small-exponent RSA, and the broader event experience."
date: 2025-01-24
difficulty: Medium
tags: [ctf, iiuc, cybercon, forensics, web]
---

## About the Event

IIUC CyberCon 2022 was organized by the IIUC Cyber Analyst Team (CyberWiz), sponsored by KSRM. The on-site event at IIUC Campus featured challenges across web exploitation, forensics, reverse engineering, and cryptography.

The event format was the standard 8-hour Jeopardy CTF: problems unlocked from a board, point values scaled with difficulty, first-blood bonuses for the first solver in each category. CyberCon's challenges were tilted toward the introductory end relative to international circuits but covered the full classic CTF spectrum, which made it useful for both newcomers and seasoned players brushing up. The on-campus venue meant problems were paced for a single day with strict no-internet rules during the contest window - every solution had to come from on-board tooling and what we'd brought on USB.

## Web Challenge: Hidden Admin

The challenge presented a login form with client-side JavaScript validation. Inspecting the source revealed the admin credentials were hardcoded in an obfuscated JS file. De-obfuscating with CyberChef (From Hex → XOR → Base64 decode) revealed the password.

### Triage

The application was a single-page login form. Submitting any guess triggered a client-side function that compared a hash of the input against a hardcoded value before ever sending anything to the server. Two signals immediately suggested client-only enforcement:

1. The browser's network tab showed *no* request firing on a wrong-password submit.
2. The form's `onsubmit` handler invoked `validateAdmin()` defined in `/static/auth.js`.

When validation lives entirely client-side, the credential almost always lives in JS too - which it did, in obfuscated form.

### Identifying the Layer Stack

The obfuscated payload looked like:

```javascript
const _0x3a4f = '5468697320697320746865207365637265742070617373636f6465';
function validateAdmin(p) {
    const stage1 = _0x3a4f.match(/.{1,2}/g).map(b => parseInt(b, 16) ^ 0x42);
    const stage2 = btoa(String.fromCharCode(...stage1));
    const expected = atob('VGhpcyBpcyB0aGUgc2VjcmV0IHBhc3Njb2Rl');   // illustrative
    return p === expected;
}
```

The pattern is hex-encoded → XOR with 0x42 → base64 → string compare. CyberChef expresses each step natively; pasting the hex blob in and chaining recipe operations reproduced the password without manually running JS.

### The CyberChef Recipe

```
Input:  5468697320697320746865207365637265742070617373636f6465
Recipe: From Hex → XOR (key 0x42) → To Base64 → From Base64
Output: <admin password>
```

Worth noting that the *cleanest* solve here is to skip CyberChef entirely and run the JS directly in the browser console: `validateAdmin('any')` → patch its return value. But understanding the layer stack matters if the challenge author intentionally hides the comparison behind further indirection.

### Lesson

Client-side authentication is a textbook anti-pattern but persists because it's easy to ship. In an actual web pentest, this finding maps to **CWE-602 (Client-Side Enforcement of Server-Side Security)** and is reportable as a high-severity bug.

## Forensics Challenge: Memory Dump

A Windows memory dump required Volatility for analysis. Using `pslist`, `netscan`, and `filescan` plugins to identify a suspicious process communicating over an unusual port. Extracting the process memory revealed the flag in a decoded base64 string.

### The Volatility Workflow

```bash
# 1. Identify the OS profile
volatility -f memory.raw imageinfo
# Suggested Profile(s): Win10x64_19041

# 2. Process listing
volatility -f memory.raw --profile=Win10x64_19041 pslist | tee pslist.txt
volatility -f memory.raw --profile=Win10x64_19041 pstree | tee pstree.txt

# 3. Network connections
volatility -f memory.raw --profile=Win10x64_19041 netscan | tee netscan.txt
# Filter: anything to non-standard ports, anything from non-system processes

# 4. Suspicious process - say PID 4892, "svchost.exe" with a network connection
#    to 198.51.100.14:31337 (clearly unusual)

# 5. Extract its memory
volatility -f memory.raw --profile=Win10x64_19041 procdump -p 4892 -D out/

# 6. Strings + base64-decode hunting
strings out/executable.4892.exe | grep -E '^[A-Za-z0-9+/=]{20,}$' | head
# Pick the suspicious-looking blob, base64 -d → flag
```

### Why That Specific Plugin Set

- `pslist` + `pstree`: shape of the process tree. A "svchost.exe" parented by `explorer.exe` instead of `services.exe` is suspicious.
- `netscan`: shows TCP/UDP endpoints. Useful for spotting C2-like patterns even when no DNS is involved.
- `filescan` (not used here but worth noting): finds open file handles, useful when the malicious payload is a dropped file.
- `cmdline`, `dlllist`, `ldrmodules`: chase process injection. If a process has DLLs loaded that don't appear in its load order, it's been injected into.
- `malfind`: classifier-based hunting for injected code (private executable regions with PE-header-like content).

For the IIUC challenge, the flag was specifically in the network-talking process, so the chain compressed neatly into pslist → netscan → procdump → strings.

### Modern Note

Volatility 3 is the current major version with a different command set:

```bash
vol -f memory.raw windows.pslist
vol -f memory.raw windows.netscan
vol -f memory.raw windows.dumpfiles --pid 4892
```

The methodology is identical; only the commands differ.

## Crypto Challenge: RSA with Small e

Classic RSA with `e=3` and small plaintext. Since `m^3 < n`, the ciphertext was simply the cube of the message - take the cube root to recover the flag.

### The Maths

RSA encryption: `c ≡ m^e (mod n)`. The modular reduction is what makes RSA hard. But when:

- `e` is small (often 3),
- `m` is short (a few characters padded with deterministic padding, or worse, no padding at all),
- `m^e < n`,

then `c = m^e` exactly - the modular operation never kicks in. Recovering `m` is just `m = c^(1/e)`, an integer cube root in the e=3 case.

### The Solver

```python
from gmpy2 import iroot

c = 0xCAFEBABE...        # ciphertext from challenge
m, exact = iroot(c, 3)
if exact:
    print(bytes.fromhex(hex(m)[2:]))
```

`gmpy2.iroot` returns the integer root and a boolean indicating whether the result was exact. If exact, `m` is the plaintext. Decode as bytes.

### When the Padding Is Slightly Smarter

If the plaintext was padded but `m^e` is *almost* n (the message is long enough that cube exceeds n by a small amount), [Håstad's broadcast attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad's_broadcast_attack) reconstructs from multiple ciphertexts. If `m` has a known portion (e.g. a fixed prefix), [Coppersmith's method](https://en.wikipedia.org/wiki/Coppersmith%27s_attack) recovers it from a single ciphertext with structure. Both are SageMath one-liners - worth knowing for slightly-harder variants.

### Lesson

Textbook RSA without padding is broken in dozens of ways: small e, common modulus, partial key exposure, low-private-exponent (Wiener's attack), shared primes. Real-world libraries default to OAEP/PSS padding precisely to defeat these classes. CTF challenges intentionally remove that padding so the maths is visible.

## Other Challenges (Briefly)

- **Steganography**: an image with LSB-encoded bytes. `zsteg` immediately surfaced the payload; the result was a reversed-string flag.
- **Reverse engineering**: an x86 binary with anti-debug `IsDebuggerPresent` checks. Patched the check to `mov al, 0` and stepped through the password comparison loop in x64dbg.
- **OSINT**: a Twitter handle reverse-image-searched against the challenge image revealed a profile bio containing the flag.

Standard fare; nothing exotic, but reinforced the value of having a fast, repeatable toolchain - `zsteg`, `binwalk`, `exiftool`, `strings`, `hashid`, `CyberChef`, `John`, `hashcat` - preconfigured on a USB-bootable Kali drive when no internet is available.

## Takeaways

- **Web**: client-side trust is always a finding. Inspect the JS, follow the obfuscation chain, and your toolkit will reproduce the result without running the page.
- **Forensics**: Volatility's plugin set is small and well-known. Memorise the four-step workflow (`imageinfo` → `pslist` → `netscan` → `procdump`) and you'll triage 80% of memory challenges in under 10 minutes.
- **Crypto**: textbook RSA breaks have signature constants (`e=3`, common moduli, missing padding). Recognise the pattern, run the textbook attack, move on.
- **General**: speed and breadth beat depth in time-boxed Jeopardy. A team strong in one category but unable to score in three others rarely podiums; the winners typically clear the easy/medium of every category before tackling hard.

> These challenges reinforced the importance of broad skills in CTF competitions. Speed and methodology matter more than depth in any single category - and the muscle memory of running these workflows quickly is what carries over from CTF practice into real assessment work.
