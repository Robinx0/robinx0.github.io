---
title: "My eCPPTv2 Exam Review: Pivoting Through the Pain"
description: "Comprehensive review of the INE Security eCPPTv2 certification exam - preparation approach, pivoting challenges, buffer overflow section, report writing, and honest tips for passing."
date: 2024-04-09
difficulty: Medium
tags: [ecpptv2, ine-security, certification, pivoting, penetration-testing]
---

## Overview

In February 2024, I purchased the eCPPTv2 exam voucher during a sale - $200 instead of the normal $400 for the exam-only voucher. The eCPPT (Certified Professional Penetration Tester) from INE Security is a practical certification focused on network penetration testing, with a heavy emphasis on pivoting through segmented networks.

The exam format: 14 days to conduct a full penetration test against a multi-subnet network, followed by 7 days to write and submit a professional report. That's 21 days total - far more generous than OSCP's 24 hours, but the network is significantly more complex.

## What Makes eCPPT Different

Unlike OSCP or even CPTS, the eCPPT's defining characteristic is **network pivoting**. The target environment isn't a flat network where every host is directly reachable. Instead, you start with access to one subnet and must compromise hosts to pivot deeper into additional network segments.

I'm talking about double-pivoting and sometimes triple-pivoting scenarios. You need to set up port forwards, route traffic through compromised hosts, and maintain stable tunnel connections while running your tools against targets you can't directly reach.

This is exactly what internal penetration tests look like in the real world. Corporate networks are segmented - the DMZ, the user VLAN, the server VLAN, the management network. Getting from one to another requires pivoting skills that most certifications don't test deeply.

## Preparation

### INE's PTS Course

The official Penetration Testing Student (PTS) course covers the fundamentals. I found the network pivoting module particularly valuable. However, I supplemented heavily with hands-on practice.

### Building a Pivoting Lab

I set up a multi-VM lab on my own machine to practice different pivoting scenarios:
- Kali (attacker) → Ubuntu (first pivot) → Windows (second pivot) → Target
- Practiced with Metasploit's autoroute, manual SSH tunnels, chisel, and ligolo-ng
- Tested running Nmap, CrackMapExec, and Burp Suite through pivot chains

### Buffer Overflow Practice

The exam includes a buffer overflow component. It's straightforward x86 stack-based overflow - find the offset, overwrite EIP, jump to shellcode. I practiced with:
- Buffer overflow prep rooms on TryHackMe
- Brainpan and similar VulnHub machines
- Writing my own fuzzer and exploit scripts in Python

The BO section isn't designed to be extremely difficult, but you need to be comfortable with the process: fuzzing → finding offset → bad character analysis → finding JMP ESP → generating shellcode → exploitation.

## The Exam

### Network Topology

Without revealing specific details, the exam presents a network with multiple subnets separated by firewalls. You start with access to the initial subnet and must:

1. Enumerate and exploit hosts on the first subnet
2. Identify hosts that bridge to the next subnet
3. Set up pivoting through compromised hosts
4. Repeat the process for deeper subnets
5. Complete the buffer overflow challenge

### My Approach

I drew the network topology on paper as I discovered it. This was essential - without a clear diagram, you lose track of which hosts you've compromised, which subnets you can reach, and where your tunnels go.

My workflow for each new subnet:
1. Set up pivoting through the latest compromised host
2. Run a full port scan through the pivot
3. Enumerate discovered services
4. Exploit vulnerabilities
5. Establish persistence on new hosts
6. Look for routes to the next subnet

### Pivoting Challenges

The hardest part was maintaining stable connections through multiple pivot points while enumerating the deepest subnet. My experience:

- **Metasploit autoroute** was good for initial pivoting but became unreliable through multiple hops
- **SSH dynamic port forwarding** (`ssh -D 1080`) with proxychains was more reliable for running tools
- **chisel** was my most reliable option for long-running tunnels
- When everything else failed, **manual port forwards** (`ssh -L`) for specific services worked

### Time Spent

- Days 1-3: First subnet - full exploitation
- Days 4-7: Second subnet - pivoting setup + exploitation
- Days 8-10: Deeper subnets + buffer overflow
- Days 11-14: Report writing

I didn't need all 14 days for testing - I finished exploitation by day 10. But I'm glad I had the buffer for report writing.

## The Report

The report requirement is professional-grade. INE expects:

1. **Executive Summary** - Non-technical overview for management
2. **Technical Findings** - Each vulnerability with evidence, impact assessment, and remediation
3. **Network Diagram** - Your discovered topology with compromised hosts marked
4. **Attack Narrative** - Step-by-step description of your attack path
5. **Remediation Priorities** - Ranked recommendations

I spent 3 full days on the report. My advice: start writing the report while testing. Every time you compromise a host or discover a vulnerability, document it immediately with screenshots and commands. Don't leave it all for the end.

## Tips for Success

### Pivoting-Specific
- Practice pivoting in a lab before the exam - don't learn during the test
- Have at least 3 pivoting methods ready (SSH, chisel, Metasploit)
- Draw your network topology in real-time
- Test your pivoting setup by running Nmap through it before trying complex tools
- Keep notes on every port forward - you'll lose track otherwise

### General
- Take screenshots of everything - you can't easily go back through pivots
- The buffer overflow is standard x86 - practice it until it's routine
- Enumerate thoroughly before exploiting - I found credentials in unexpected places
- Don't neglect web applications on internal hosts
- Keep your VPN connection stable - if it drops, your pivots break

### Report Writing
- Use a template - don't start from scratch
- Include your network diagram in the executive summary
- Screenshot every exploitation step with timestamps
- Write remediation recommendations that are specific, not generic
- Proofread - professionalism matters

## Who Should Take eCPPT

The eCPPT is ideal if you want to:
- Learn network pivoting properly before moving to harder certs
- Build a foundation for internal penetration testing
- Practice professional report writing
- Get a certification that focuses on practical skills over theory

It's a natural stepping stone: eJPT → eCPPT → CPTS/CRTO/OSCP.

## Comparison with Other Certs

| Aspect | eCPPT | CPTS | OSCP |
|--------|-------|------|------|
| Pivoting depth | Very High | High | Medium |
| AD focus | Low | Very High | Medium |
| Web attacks | Medium | High | Medium |
| Report required | Yes (7 days) | Yes (included in 10) | Yes (24 hours) |
| Exam duration | 14+7 days | 10 days | 23h 45m |
| Buffer overflow | Required | Not required | Required |
| Difficulty | Medium | Hard | Medium-Hard |

## Final Thoughts

eCPPTv2 taught me more about network pivoting than any other resource. The skills directly transfer to real internal penetration tests. Maintaining shells through multiple pivot points while enumerating deep network segments - that's exactly what you'll do in a corporate assessment.

The exam is generous with time, the topics are well-defined, and the learning value is high. If you're building your certification portfolio, eCPPT belongs in it.

> The pivoting skills I built during eCPPT preparation became the foundation for everything I do in internal assessments today. No other cert tests this skill as thoroughly.
