---
title: "BlueHens UDCTF 2023: Hardware & Reverse Engineering Writeups"
description: "Solutions for the Locked Circuit hardware challenge and ElectroNes reverse engineering challenge from the BlueHens UDCTF 2023 competition."
date: 2023-10-30
difficulty: Medium
tags: [udctf, bluehens, ctf, hardware, reverse-engineering, nes]
---

## Part 1: Locked Circuit - Hardware Challenge

### Challenge Description

Two files were provided: `k8_AntiSat_DTLAND0_c432.bench` and `c432.bench`. The challenge was categorized under "Hardware" with a hint: "trick hidden in the output."

### Initial Analysis

Opening the `.bench` files revealed logic gate descriptions - AND, OR, NOT gates with numbered inputs and outputs. My first instinct was to find a logic gate simulator, but none of the simulators I tried could parse the specific format correctly.

The hint about the "trick hidden in the output" redirected my approach. Instead of simulating the circuit, I focused on analyzing the output gate definitions directly.

### Solution Approach

Comparing the two files, the `k8_AntiSat_DTLAND0` version had additional gates inserted - these are "AntiSAT" gates, a hardware security technique designed to prevent reverse engineering of circuit functionality by inserting decoy logic.

The key insight was that the output signals of the original `c432.bench` circuit, when traced through the AntiSAT modifications, spelled out the flag in binary. By extracting the output gate identifiers and converting them to ASCII, the flag was revealed.

### Takeaways

Hardware CTF challenges often don't require actual circuit simulation. They test your ability to recognize file formats, identify the security mechanism (AntiSAT in this case), and find the hidden data through analytical comparison rather than brute-force simulation.

## Part 2: ElectroNes - Reverse Engineering Challenge

### Challenge Description

This was particularly interesting for me because I'd never reverse-engineered a NES game in a CTF before. We received a `.nes` ROM file and needed to extract the flag.

### NES Fundamentals

The Nintendo Entertainment System uses a 6502-based CPU (Ricoh 2A03). NES ROMs contain:
- **PRG-ROM** - Program code (CPU-addressable)
- **CHR-ROM** - Graphics/tile data (PPU-addressable)
- **iNES header** - 16 bytes describing the ROM layout

### Analysis Approach

**Step 1: Run the ROM**

Loading the ROM in an emulator (FCEUX) showed a simple game screen. The flag wasn't immediately visible - it wasn't displayed as text on screen.

**Step 2: Inspect CHR-ROM (Graphics Tiles)**

NES games store all their graphics as 8x8 pixel tiles in CHR-ROM. Using a tile viewer tool, I dumped all the graphical tiles. Among the game's normal sprites and background tiles, I found tiles that formed flag characters - they existed in the ROM's graphics data but weren't being rendered on screen during normal gameplay.

**Step 3: Extract and Assemble**

By extracting the relevant tile indices and mapping them to the NES's character encoding, the hidden tiles spelled out the flag.

### Alternative Approach: Memory Inspection

FCEUX has a powerful debugger. Setting breakpoints on PPU writes and stepping through the game's initialization code could reveal where the flag tiles are loaded but never displayed - suggesting they're part of an unused or hidden game state.

### Takeaways

NES reverse engineering is a niche but fascinating area. The key tools are:
- **FCEUX** - Best NES emulator with debugging capabilities
- **YY-CHR** - Tile editor for viewing NES graphics data
- **Ghidra with NES loader** - For disassembling 6502 code
- **Mesen** - Another excellent NES debugger

> CTFs constantly push you into unfamiliar territory. I'd never touched NES internals before this challenge, but the fundamental reverse engineering methodology - understand the format, inspect the data, identify anomalies - applies regardless of the platform.
