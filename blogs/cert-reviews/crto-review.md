---
title: "My CRTO Exam Review: Cobalt Strike, Malleable Profiles, and Adversary Simulation"
date: 2025-12-10
description: "Honest review of Zero-Point Security's Certified Red Team Operator certification - the course content, malleable C2 profile development, AV evasion techniques, and the lateral-movement wall I hit on the exam."
difficulty: Hard
tags: [crto, zero-point-security, cobalt-strike, red-team, certification, exam-review]
---

## Overview

On 3 December 2025 I sat the Zero-Point Security Certified Red Team Operator (CRTO) exam. I had earned my CPTS six months earlier, and CRTO felt like the natural next step - taking the penetration testing methodology I had built and applying it through a real C2 framework with the full operational security mindset that comes with adversary simulation rather than ordinary pentesting.

I bought the full course bundle (course + 40 hours of lab time + one exam attempt). For anyone who doesn't already have Cobalt Strike licensed at work, this is the only sensible path: the lab instance is what lets you actually drive the operator UI, run the entire kill chain end-to-end, and rehearse the muscle memory you will need on exam day.

This is my honest review.

## What is CRTO

CRTO is run by Daniel Duggan (RastaMouse) and focuses on red team operations using Cobalt Strike. The course covers approximately 30 modules taking the operator from initial access all the way through to multi-domain forest compromise. The exam is 24 hours against a multi-domain Active Directory environment, completed in one continuous sitting - the timer does not pause, and you have to plan the whole engagement around that single window.

What makes CRTO distinct from CPTS or OSCP is the lens. CPTS asks "can you compromise the network and report on it". CRTO asks "can you operate inside a managed environment without being burned, while exercising the full tradecraft of an adversary simulation". OPSEC is not a side topic - it is the entire course.

## Background Going In

Before CRTO, my certification stack was eJPT, eCPPT, eWPTX, and CPTS. From a hands-on perspective I had cleared three HTB Pro Labs (Dante, Rastalabs, Ascension) and rooted 70+ machines on HTB. Rastalabs in particular paid forward into CRTO because the EDR evasion mindset transfers directly.

What I did not have at this point was deep Cobalt Strike experience. I had used it briefly during Rastalabs, but the operator workflow, the malleable C2 system, and the in-process tradecraft were all new territory. CRTO is where I actually learned Cobalt Strike properly.

## Preparation

### Trust the Course - It Is Enough

This is the most honest thing I can say about CRTO: if you study the course content carefully, it is enough to pass the exam. I did not need third-party prep, I did not need additional labs beyond what the course provides, and I did not need to chase blog posts in parallel. The exam strictly tests what the course teaches.

This is unusual for certifications and worth highlighting. With CPTS you are expected to supplement with Pro Labs. With OSCP you are expected to grind PG Practice and HTB. With CRTO the course modules and lab environment are sized exactly to the exam.

That said, "enough if studied carefully" is the operative phrase. The depth required is real.

### How I Worked the Modules

For each module I would:

1. Watch the video and read the supporting notes
2. Replicate every technique inside the lab environment without copy-paste
3. Take notes in Obsidian, focusing on the why and the OPSEC consequences of each action, not just the commands
4. Re-do the technique from memory the next day

The "re-do from memory" loop is what made the difference. Cobalt Strike has dozens of small operator commands and you do not want to be searching documentation during the exam.

### Lab Time Discipline

40 hours of lab time sounds like a lot. It is not. I burned through my first 10 hours faster than I expected because I treated the lab as a playground rather than a structured environment. After that I started timeboxing every session: 90 minutes per module replication, no aimless wandering.

If you run out of lab time before the exam, you can buy more in 40-hour blocks. I did not need to, but plan your time accordingly.

### Malleable C2 Profile Development

This was the single most rewarding part of the course for me. I had read about malleable profiles for years and never understood them properly. The course walks you through writing your own profile from scratch - HTTP request and response transforms, beacon metadata placement, jitter and sleep configuration, certificate selection, and host headers.

By the end I had built a profile that mimicked a specific SaaS API and understood every line of it. That is a skill I now use in real engagements, not just exam prep.

### AV Evasion

The evasion modules cover signature-based detection, AMSI, ETW, sleep obfuscation, in-memory module patching, and shellcode loaders. The course does not hand you ready-made bypasses - it walks through how each detection works and how to defeat it conceptually, then lets you build the loaders yourself.

What I valued most: the course is honest about the cat-and-mouse nature of EDR. Nothing in the modules is presented as "use this and you are invisible forever". Everything is contextual, version-dependent, and requires understanding rather than copying.

## The Exam Experience

I cannot share specifics about the exam network for obvious reasons, but I can describe how my 24 hours unfolded in shape.

### The 24-Hour Window

You have one continuous run. No pausing, no breaks where the clock stops. That changes how you plan everything - sleep, meals, even when to step away from the keyboard. Going in I had decided that I would not try to push straight through 24 hours of focused operating. I planned for one short rest break around the midpoint and short stretches every couple of hours to keep my head clear.

### Early Hours - Initial Access and Foothold

Connected to the exam VPN, oriented myself in the environment, used the provided initial access path to land my first beacon, and ran careful post-exploitation enumeration. The first few flags came in this phase. The temptation early on is to rush - I deliberately slowed myself down here because operator mistakes early in the chain are the ones that kill you later.

### Middle Stretch - Escalation and Domain Compromise

Local privilege escalation on the foothold host, credential extraction, BloodHound enumeration through the beacon, mapping the AD environment. Found my path to the first domain controller. Several more flags fell during this stretch and momentum felt good.

This is also where the OPSEC mindset earns its keep. Every command goes through a "what does this look like to a defender" filter. Slower, more deliberate operating, but no surprises.

### Late Hours - The Lateral Movement Wall

This is where I got stuck.

The transition from the first domain to the next required a specific lateral movement technique that I had not internalised properly during prep. I knew the theory, I had done the lab equivalent, but under exam pressure - and with the clock now visibly working against me - I kept making small operator mistakes. Wrong session, wrong target, missing a step in the chain. I burned about six hours on this one transition.

What pulled me through was going back to my Obsidian notes from the relevant module and re-reading them slowly. The information was all there. I had just been trying to muscle through from memory under stress, and the missing detail was sitting in my notes from three months earlier. Lesson learned: trust your notes, do not improvise red team tradecraft on exam day, especially not when the clock is the one driving you.

After that one bottleneck cleared, the rest of the chain opened up.

### Final Push and Submission

Cleared the remaining flags, double-checked everything against the flag list, submitted with time to spare. The relief at the end of a 24-hour single-sitting exam is a particular kind of relief - earned, exhausted, slightly delirious.

## What I Learned

### Malleable C2 Profile Development

I went into CRTO knowing what malleable profiles were. I came out able to write one from a blank file. That is a real skill differential.

### Modern AV Evasion

The course's evasion content is current and covers techniques I had not seen explained well anywhere else - sleep mask implementations, indirect syscalls in the context of an actual operator workflow, the specific things modern EDR products look for, and the tradeoffs of each evasion technique against detection.

### OPSEC as a First-Class Concern

Every CRTO lesson is framed in terms of "what will this look like to a defender". That mindset shift is the most valuable thing the course delivers. After CRTO I cannot run a tool without first thinking about its telemetry footprint, and that is exactly what red team operations require.

### Cobalt Strike Operator Fluency

I now know Cobalt Strike. The Aggressor scripting model, the BOF interface, the way the operator UI exposes the agent's capabilities, the malleable C2 hooks - all of it is muscle memory now. That is genuinely valuable for any red team work, paid or otherwise.

## Tools I Used

| Tool | Usage |
|------|-------|
| Cobalt Strike | Primary C2, the entire operator workflow |
| BloodHound | AD attack path mapping (run through beacon) |
| Rubeus | Kerberos abuse from inside the beacon context |
| SharpHound (BOF) | Domain enumeration without spawning processes |
| Mimikatz | Credential extraction (in-memory via beacon) |
| ProxyChains | Pivoted access to internal subnets |
| Obsidian | Notes and exam-day reference |
| SysReptor | Report-friendly templating (not required for CRTO but I used it) |

The list is shorter than my CPTS list because Cobalt Strike absorbs the role of many separate tools. That is part of the point of operating through a C2.

## Tips for Aspiring CRTO Holders

1. **Buy the course, not just the exam.** The lab time is where you build the muscle memory.
2. **Replicate every module by hand.** Do not copy-paste. Type the commands, watch the beacon respond, develop a feel for the tool.
3. **Build your own malleable profile.** Do not just modify the example. Write one from scratch. You will understand the system properly only by doing this.
4. **Take OPSEC notes for every module.** Each technique has detection signals. Capture them in your notes - the exam tests whether you can chain techniques without making noise.
5. **Practise lateral movement until it is boring.** This is where I struggled and where many candidates struggle. Repetition is the only fix.
6. **Trust your notes on exam day.** When you get stuck, do not improvise - go back to what you wrote during prep. The information is there.
7. **Time-box the lab.** 40 hours sounds like enough until you waste 10 of them exploring.
8. **Run a malleable profile during the exam.** Not just the default. The course teaches you why.
9. **Plan the 24-hour window before you start.** When will you eat, when will you take a short break, when will you step away from the keyboard for ten minutes to clear your head. Decide this in advance - operator decisions made when tired are the worst kind.

## Comparison with My Other Certifications

| Aspect | CRTO | CPTS | eCPPTv2 |
|--------|------|------|---------|
| Focus | Adversary simulation | Penetration testing | Network pentest with pivoting |
| Tooling | Cobalt Strike-centric | Open-source toolchain | Mixed (mostly OSS) |
| AD depth | Very High | Very High | Medium |
| EDR/AV evasion | Heavy | Light | None |
| OPSEC focus | Central | Some | Minimal |
| Report required | No (flag-based) | Yes (commercial-grade) | Yes (commercial-grade) |
| Exam window | 24 hours, single sitting | 10 days | 14+7 days |
| Course required | Effectively yes | Yes (Academy) | Yes (PTS) |

CRTO is the most narrow of the three in topic coverage, but it goes deeper into red team tradecraft than either CPTS or eCPPTv2. They complement each other - if you have CPTS, CRTO fills in the adversary-simulation half of the picture.

## Final Thoughts

CRTO did exactly what I hoped it would. It taught me Cobalt Strike properly, gave me a real understanding of malleable C2 profiles, and shifted my mental model from "pentester finds bugs" to "operator runs a campaign". The lateral movement struggle on day 3 was frustrating in the moment but in hindsight it taught me the most valuable lesson of the engagement: under pressure, trust your notes.

If you have already done CPTS or OSCP and you want to step into red team work, CRTO is the right next certification. The course is well-structured, the lab is sized appropriately, and the exam tests what you actually need to know without artificial difficulty.

> CPTS taught me to be a pentester. CRTO taught me to be an operator. The difference is in the discipline - every command considered, every technique chosen with intent, every step measured against what the defender will see.
