---
title: "National Cyber Drill 2021: Reverse Engineering Challenges"
description: "Detailed writeups for the reverse engineering challenges from Bangladesh's National Cyber Drill 2021 organized by BGD e-GOV CIRT - binary analysis, GDB debugging, and flag extraction."
date: 2021-12-13
difficulty: Medium
tags: [cyberdrill, ctf, reverse-engineering, gdb, ghidra, bangladesh]
---

## Context

The National Cyber Drill is Bangladesh's premier cybersecurity competition organized by BGD e-GOV CIRT. In 2021, I competed and won the championship. The reverse engineering category was particularly well-designed - each challenge built on increasing complexity, from simple string analysis to multi-function binary analysis.

## Challenge 1: Reverse Engineering Up to Date

### Description

We received a `breakme.out` file and an `ip:port` for netcat access. The binary was an ELF 64-bit executable.

### Analysis

Running the binary and connecting via netcat both showed the same behavior: it asks for an input/passcode. Wrong input produces an error message; correct input reveals the flag.

```bash
$ file breakme.out
breakme.out: ELF 64-bit LSB executable, x86-64

$ ./breakme.out
Enter the passcode: test
Wrong! Try again.
```

### Static Analysis

Opening in Ghidra, the `main` function was straightforward:
1. Read user input via `scanf()`
2. Compare input against a hardcoded value
3. If match → print flag; else → print error

The comparison used a simple `strcmp()` against a string that was built character-by-character in the function's local variables. By reading the assignment operations in Ghidra's decompiler, the passcode could be reconstructed directly.

### Dynamic Approach

Alternatively, in GDB:

```bash
$ gdb ./breakme.out
(gdb) break strcmp
(gdb) run
Enter the passcode: anything
# Breakpoint hits at strcmp
(gdb) x/s $rdi   # First argument to strcmp (our input)
(gdb) x/s $rsi   # Second argument (the expected passcode)
```

The second argument to `strcmp` contains the expected passcode. Enter it, get the flag.

### Lessons

Even when a binary looks simple, practice both static and dynamic approaches. In a CTF, GDB's `break strcmp` trick solves 90% of simple password-check challenges in under a minute.

## Challenge 2: Multi-Function Analysis

### Description

A more complex binary with multiple functions and indirect comparisons. The flag wasn't checked with a simple `strcmp` - instead, the input was transformed through a series of operations and compared against an encoded byte array.

### Analysis

Ghidra revealed the transformation pipeline:
1. Input string → XOR each byte with a rotating key
2. XOR result → bit rotation (ROL 3)
3. Rotated result → compared against hardcoded byte array

### Solution

Since every operation is reversible, I wrote the inverse in Python:

```python
encoded = [...]  # Extracted from binary's .rodata section
key = [...]      # XOR key extracted from the function

flag = ""
for i, b in enumerate(encoded):
    # Reverse bit rotation (ROR 3)
    b = ((b >> 3) | (b << 5)) & 0xFF
    # Reverse XOR
    b ^= key[i % len(key)]
    flag += chr(b)

print(flag)
```

### Key Methodology

For any RE challenge with transformations:
1. Identify the transformation chain in the decompiler
2. Determine if each step is reversible
3. Extract the comparison target (encoded flag)
4. Implement the inverse operations
5. Apply to the encoded data → original flag

## Competition Reflection

The National Cyber Drill 2021 was a pivotal moment in my security career. Winning the championship validated years of self-study and CTF practice. The reverse engineering challenges specifically reinforced that methodology beats memorization - understanding the systematic approach to binary analysis is more valuable than knowing specific tools.

> The Cyber Drill championship opened doors to the security community in Bangladesh and motivated me to pursue offensive security professionally. Every big journey starts somewhere.
