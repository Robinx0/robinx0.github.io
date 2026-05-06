---
title: "Forged in Fortresses: My Complete HackTheBox CPTS Journey"
description: "A deep dive into my preparation, strategy, and lessons learned earning the HackTheBox Certified Penetration Testing Specialist certification - the most challenging hands-on exam I've attempted."
date: 2025-06-04
difficulty: Medium
tags: [cpts, hackthebox, certification, penetration-testing, exam-review]
---

## Introduction

After what felt like a significant chapter of dedicated learning and hands-on practice - truly a marathon - I earned the HackTheBox Certified Penetration Testing Specialist (CPTS) certification. This wasn't just another exam checkbox. It was a culmination of countless hours on the HTB platform, and I want to share my complete journey with everyone who's preparing for it.

## What is CPTS

The CPTS is the final test after completing the 28-module "Penetration Tester" job role path on HackTheBox Academy. These modules cover comprehensive topics: reconnaissance, web application exploitation, Active Directory attacks, network pivoting, privilege escalation on both Linux and Windows, and detailed professional reporting.

The exam itself is a multi-day engagement against a full enterprise network. No multiple choice. No hints. No lab walkthroughs. Just you versus an infrastructure that simulates a real corporate environment. You need at least 12 out of 14 flags plus a commercial-grade penetration testing report.

## My Background Going In

Before CPTS, I had solid experience on the HackTheBox platform - 70+ machines rooted, 70+ challenges solved, and three Pro Labs completed (Dante, Rastalabs, Ascension). I also held the eCPPT and eWPTX certifications. But the structured Academy lessons provided clarity and professional methodology that my prior ad-hoc learning hadn't covered.

My certifications at the time: eJPT, eCPPT, eWPTX. After CPTS, I went on to earn CRTO for Cobalt Strike-focused adversary simulation.

## Preparation Strategy

Here's what became the core of my approach:

### 1. Thoroughly Study the Academy Modules

This is the bedrock. The 28 modules are your primary resource, and the exam strictly adheres to this curriculum. Don't skim - live in them. The goal isn't memorization but deep comprehension.

I took notes in Obsidian, rephrasing concepts in my own words rather than copying screenshots. For each module, I would:
- Read the entire module once without doing exercises
- Go back and complete every exercise, taking notes on the methodology
- Attempt the skills assessment completely blind
- If I got stuck, review only the relevant section, then try again

### 2. Pro Labs as Force Multipliers

This is where real exam readiness is built. Each Pro Lab teaches different engagement patterns:

**Dante** - My favorite and most impactful. A 14-host network requiring chained exploitation and deep pivoting across segmented subnets. I learned how to manage multiple tunnels simultaneously while maintaining stable connections. The pivoting skills from Dante directly transferred to the exam.

**Rastalabs** - AD-focused with EDR evasion components. Taught me to think about attacking Active Directory across forest trusts while fighting detection. Custom binary reverse engineering was required for several hosts.

**Ascension** - Compact but incredibly dense. Every single step requires chaining vulnerabilities - there are no easy wins. Web attacks flowing into AD exploitation flowing into privilege escalation. If you can complete Ascension, you can handle the exam's multi-step chains.

### 3. The Attacking Enterprise Networks Module

The final module in the path (AEN) is essentially a scaled-down version of the exam. My strongest recommendation: **attempt AEN completely blind** after finishing all other modules. Don't look at any walkthrough. Treat it exactly like the exam - enumerate from scratch, document everything, write a report.

This was the single most valuable preparation exercise. It exposed gaps in my methodology that I didn't know existed.

### 4. Active Directory Deep Dive

AD is heavily tested. I supplemented the Academy modules with:
- BloodHound - learned every edge type and what they mean practically
- Kerberos attacks - Kerberoasting, AS-REP roasting, constrained/unconstrained delegation, RBCD
- ACL abuse - GenericAll, GenericWrite, WriteDacl, ForceChangePassword
- ADCS - ESC1 through ESC8 attack paths

I practiced these on HackTheBox machines filtered for Active Directory. IppSec's videos were invaluable for seeing different approaches to the same problems.

### 5. Pivoting Mastery

The exam network is segmented. You will need to pivot through multiple subnets. Tools I practiced with:
- **chisel** - My primary tunneling tool. Reliable, fast, cross-platform
- **ligolo-ng** - Excellent for creating transparent tunnels that feel like VPN connections
- **SSH tunneling** - Dynamic port forwarding with proxychains for tool access
- **Metasploit's autoroute** - Useful but I found manual tunnels more reliable

Practice maintaining 2-3 concurrent tunnels while running tools through them. This is a skill that only comes from repetition.

## The Exam Experience

I can't share specific details about the exam network, but I can share my approach:

### Time Management

I allocated my 10 days as follows:
- Days 1-2: Full enumeration of the external attack surface
- Days 3-6: Exploitation, lateral movement, flag collection
- Days 7-8: Revisiting missed hosts and flags
- Days 9-10: Report writing and review

### Documentation During Testing

I documented every step in real-time using Obsidian. Every command, every output, every screenshot. This made report writing dramatically easier. I've seen people fail not because they couldn't hack the network, but because they couldn't reconstruct what they did for the report.

### The Report

The report requirement is commercial-grade. Executive summary, detailed findings with evidence, risk ratings, CVSS scores, remediation recommendations, and attack narratives. I spent two full days on the report alone.

My report structure:
1. Executive Summary (1 page)
2. Scope and Methodology
3. Attack Narrative (chronological story of the engagement)
4. Detailed Findings (each vulnerability with evidence, impact, remediation)
5. Appendices (tool outputs, full screenshots)

## Key Lessons

### What I'd Do Differently

- Start taking Obsidian notes from module 1, not halfway through
- Practice report writing during Pro Labs, not just during the exam
- Spend more time on web application attacks - they're heavily tested
- Don't underestimate enumeration - thoroughness beats speed

### What Worked Well

- Doing Pro Labs after the modules, not during
- Attempting AEN blind as exam simulation
- Using a consistent note-taking template across all modules
- Taking breaks - I studied for 4-5 hours daily, not 12-hour marathons

## Tools I Relied On

| Tool | Usage |
|------|-------|
| Nmap | Initial enumeration, service detection |
| CrackMapExec | AD enumeration, spray, share hunting |
| BloodHound | AD attack path visualization |
| Burp Suite | Web application testing |
| chisel | Tunneling and pivoting |
| Impacket | AD exploitation (secretsdump, psexec, GetUserSPNs) |
| Rubeus | Kerberos attacks from Windows |
| Obsidian | Note-taking and documentation |
| SysReptor | Report generation |

## Advice for Aspiring CPTS Holders

1. **Complete every module thoroughly** - the exam doesn't test topics outside the curriculum
2. **Do all three recommended Pro Labs** - they teach engagement methodology, not just exploitation
3. **Master pivoting** - you cannot pass without it
4. **Write reports as you go** - documenting is 50% of the exam
5. **Don't rush** - 10 days is plenty if you work methodically
6. **Enumerate broadly before exploiting deeply** - scan everything first

## Final Thoughts

CPTS was the most rewarding certification I've earned. It simulates a real penetration testing engagement better than any other certification on the market. The combination of technical depth, practical application, and professional reporting makes it genuinely valuable - not just as a credential, but as a learning experience that made me a significantly better pentester.

If you're considering CPTS, commit fully. It's demanding but absolutely achievable with consistent, structured preparation.

> The exam doesn't test if you can hack - it tests if you can conduct a professional penetration test. There's a big difference.
