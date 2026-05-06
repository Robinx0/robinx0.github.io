---
title: "Intercepting Flutter App Traffic with Frida"
description: "Bypassing Flutter's custom TLS stack to intercept HTTPS traffic that ignores system proxy settings and certificate stores - a deep look at why Flutter is harder than native, plus reFlutter, Frida, and iptables-based interception strategies."
date: 2026-02-10
difficulty: Hard
tags: [flutter, frida, ssl-pinning, traffic-interception]
---

## Why Flutter is Different

Flutter apps use Dart's own HTTP stack (BoringSSL), which ignores the system proxy settings and the Android certificate store. Setting a proxy in Wi-Fi settings and installing Burp's CA does nothing.

This is the single fact that surprises every assessor on their first Flutter app. With a native Android app you install Burp's CA, set the device proxy, and traffic flows. With Flutter, the same setup yields zero captured requests, no error in the proxy log, and the app continues to work fine - because it's reaching its servers directly with its own statically-linked TLS stack, ignoring everything the OS provides.

### The Architecture Behind the Pain

A native Android app uses one of:

- `java.net.HttpURLConnection` (default OS HTTP, respects system proxy + system CAs)
- `OkHttp` (Square's library, also respects system proxy/CAs by default)
- `Volley`, `Retrofit` (built on top of OkHttp)
- `WebView` (uses system CAs)

A Flutter app uses **`package:http`**, **`package:dio`**, or directly **`dart:io`'s `HttpClient`**, all of which sit on top of the Dart runtime's native sockets. The Dart runtime - `libflutter.so` on Android, `Flutter.framework` on iOS - bundles its own copy of **BoringSSL** (Google's fork of OpenSSL) and uses it for *all* TLS. There is no JNI hop into Java networking, no callout to `system_security` for trust anchors, no `ProxySelector` consultation.

Concretely:

| What you set | Native app | Flutter app |
|---|---|---|
| Wi-Fi → Manual proxy | Honoured | Ignored |
| User CA in System CAs | Honoured | Ignored |
| Network Security Config | Honoured | Ignored (largely - Flutter uses its own anchors) |
| `usesCleartextTraffic="false"` | Enforced | Irrelevant - Flutter doesn't ask the OS |
| Burp's CA via `mitmproxy --ca-cert-passthrough` | Trusted by JVM | Not in Flutter's anchor list |

The fix is to **either** patch Flutter to trust your CA, **or** patch Flutter to skip the verification step entirely, **or** force traffic through your proxy at a layer below Flutter's awareness.

## Approach 1: reFlutter

Patch the Flutter engine to trust all certificates:

```bash
reflutter target.apk  # Patches libflutter.so
# Install patched APK, route traffic through Burp
```

[reFlutter](https://github.com/Impact-I/reFlutter) is the cleanest single-command solution. Internally it:

1. Identifies the Flutter version embedded in `libflutter.so` (via a small constant table that reFlutter has reverse-engineered for every Flutter release).
2. Locates the `ssl_verify_peer_cert` (or equivalent) function inside the bundled BoringSSL.
3. Patches its first instructions to immediately return success.
4. Rebuilds and re-signs the APK.

Strengths:

- Zero runtime overhead - no Frida required, the patched APK runs on stock devices, including non-rooted ones if you use `apksigner` with your own key.
- Works across Flutter versions because reFlutter maintains a version-keyed offset database.
- Proxy support added (reFlutter writes `Dart_Initialize` arguments so the runtime points to your proxy).

Weaknesses:

- Each Flutter release ships a slightly different `libflutter.so`. If reFlutter doesn't yet support the version, the patch fails. Check the [supported versions list](https://github.com/Impact-I/reFlutter#supported-versions) before depending on it.
- For obfuscated builds (`flutter build apk --obfuscate --split-debug-info=...`), the symbol layout changes; reFlutter may need a newer signature.
- iOS support exists but is more fiddly (requires re-signing the IPA with a development certificate).

### Manual Patch Equivalent

If reFlutter doesn't support your version, do it by hand:

```bash
# Extract the engine
apktool d target.apk -o work/
ls work/lib/arm64-v8a/libflutter.so

# Find the cert-verify function. Multiple candidate names depending on Flutter version:
nm -D --defined-only work/lib/arm64-v8a/libflutter.so | grep -E 'verify_cert|SSL_verify'

# In Ghidra/IDA, locate ssl_verify_peer_cert
# Typical signature (BoringSSL):
#   enum ssl_verify_result_t ssl_verify_peer_cert(SSL *ssl, uint8_t *out_alert)
# Patched to:
#   return ssl_verify_ok = 0
```

The minimal AArch64 patch:

```
00 00 80 D2     mov  x0, #0          ; return value 0 (ssl_verify_ok)
C0 03 5F D6     ret
```

Replace the first 8 bytes of `ssl_verify_peer_cert` with these two instructions. Re-pack with apktool, sign with apksigner, install.

## Approach 2: Frida + ssl_pinning_bypass

Hook BoringSSL's `ssl_verify_peer_cert` to always return success:

```javascript
// Hook BoringSSL's verify function
var verify = Module.findExportByName("libflutter.so", "ssl_crypto_x509_session_verify_cert_chain");
if (verify) {
    Interceptor.replace(verify, new NativeCallback(function() { return 0; }, 'int', []));
}
```

Frida-based bypasses are the right choice when you can't (or don't want to) modify the APK. The trick is that `ssl_verify_peer_cert` is **not exported** in newer Flutter builds - it's an internal function. You have to find it by signature scanning.

### Pattern Scanning Approach

Community scripts like [disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) maintain per-architecture, per-Flutter-version byte-pattern signatures. The script:

1. Loads `libflutter.so`.
2. Scans for the byte pattern that uniquely identifies `ssl_verify_peer_cert`'s prologue.
3. Hooks the matched function, replacing it with a stub that returns `ssl_verify_ok` (0).

Sample skeleton:

```javascript
function hookFlutterSSLVerify() {
    var libflutter = Process.findModuleByName("libflutter.so");
    if (!libflutter) {
        console.log("[!] libflutter.so not loaded yet - retrying via Module.load");
        return;
    }

    // Pattern is per-architecture; this is an example for arm64
    var pattern_arm64 = "FF 03 03 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 ?? ?? ?? ?? F4 03 02 AA F6 03 01 AA F8 03 00 AA";

    Memory.scan(libflutter.base, libflutter.size, pattern_arm64, {
        onMatch: function (address, size) {
            console.log("[+] ssl_verify_peer_cert found at " + address);
            Interceptor.replace(address, new NativeCallback(function () {
                return 0;   // ssl_verify_ok
            }, 'int', ['pointer', 'pointer']));
            return 'stop';
        },
        onError: function (reason) { console.log("[!] " + reason); },
        onComplete: function () {}
    });
}

setTimeout(hookFlutterSSLVerify, 500);   // give libflutter.so time to load
```

If the pattern doesn't match (different Flutter version), the community repo has updated patterns - pull and try again.

### Frida Caveats

- The hook must run **after** `libflutter.so` is loaded. Either wait (as above) or use `Module.load`/`dlopen` interception to hook on load.
- Newer Frida-detection libraries (`Promon Shield`, `Appdome`, `DexGuard`) inspect `/proc/self/maps` for `frida-agent` and abort. Use `frida-magisk-gadget`, randomise the agent name, or use a non-Frida instrumentation tool like LSPosed + Yahfa.
- On split APKs (Play Store delivers split APKs per architecture), make sure you're hooking the architecture matching the device.

## Approach 3: ProxyDroid + iptables

Force all traffic through your proxy at the network level:

```bash
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
```

This approach sidesteps Flutter's proxy-ignorance entirely. The OS forces every outbound TCP/443 packet through your local listener, regardless of what the app intended.

### Why This Alone Isn't Enough

Even with iptables redirect, Flutter still validates the TLS certificate. Your local proxy presents *your* certificate (Burp's, mitmproxy's), Flutter's bundled BoringSSL doesn't trust it, and TLS handshake fails - you see the connection but no cleartext.

That's why iptables is **paired** with one of the previous approaches: redirect ensures the traffic arrives at your proxy, and the cert-verify patch ensures Flutter accepts your cert.

### Practical iptables Setup

```bash
# Redirect HTTPS to local Burp on port 8080
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080'

# Same for HTTP
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080'

# Plus DNS (some Flutter apps use DoH which needs to be bypassed)
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 853 -j REDIRECT --to-port 8080'

# Verify
adb shell su -c 'iptables -t nat -L OUTPUT -n -v'
```

[ProxyDroid](https://github.com/madeye/proxydroid) wraps the same iptables logic in a Magisk-friendly UI and handles per-app rules.

### Burp Configuration for Invisible Proxying

Because the redirected traffic doesn't include `CONNECT` or proxy headers, Burp must run in **invisible** mode:

1. Burp → Proxy → Listeners → Add → Port 8080.
2. Listener → Edit → "Support invisible proxying" ✓.
3. Listener → "Redirect to host" empty (use original-host SNI).
4. TLS → Self-signed certificate (default).

In mitmproxy:

```bash
mitmproxy --mode transparent --showhost
```

## Putting It Together: a Real Assessment Setup

A configuration that works against ~95% of Flutter apps:

1. **Rooted device or emulator** with Magisk installed.
2. **Frida server** running on the device matching the host's frida tools.
3. **reFlutter-patched APK** (or original APK + Frida pattern hook).
4. **iptables redirect** to local proxy.
5. **Burp Suite** in invisible-transparent mode on 8080.
6. (Optional) **mitmproxy** alongside Burp for raw flow logging and scripting.

The first time it works the relief is immense - you go from "no traffic captured at all" to a fully proxied Flutter app with all routes visible.

## When None of This Works

A small but growing set of Flutter apps actively defend against interception:

- **Custom certificate pinning at the Dart layer** - the app explicitly trusts only its server's certificate via Dart code (`SecurityContext.setTrustedCertificatesBytes`). Even a verified-cert handshake fails because the chain isn't pinned. Patch the Dart logic via reFlutter or hook the relevant `dart_::SecurityContext` method.
- **Mutual TLS (mTLS)** - the server demands a client certificate. Extract the client cert from the APK (often in `assets/`) and configure Burp's "Client SSL Certificates" to present it.
- **Anti-Frida + anti-tamper RASP** - detects mounted Magisk modules, renamed frida-server, hooked `libc::dlsym`. Counter with [Magisk Hide → Shamiko → Zygisk-based hiding](https://github.com/LSPosed/LSPosed.github.io/wiki/How-to-install-LSPosed) and a stripped-down Frida server.
- **Custom HTTP/2 over QUIC (HTTP/3)** - UDP/443 instead of TCP/443. iptables redirect for TCP doesn't catch this; you need UDP redirection or to disable QUIC on the device. Some apps allow easy disabling via experimental flags; others fall back to TCP if UDP is blocked.

## Setting Up the Proxy

1. Run Burp with invisible proxy on 8080
2. Enable support for TLS client connections without Client Hello SNI
3. Redirect traffic via iptables or ProxyDroid
4. Apply Frida script to bypass cert verification

### Pre-Flight Checklist

Before claiming "the proxy isn't working", verify in this order:

1. The proxy listener is active and reachable from the device (`adb shell curl -kv https://your-listener:8080`).
2. The device's iptables rules are in place (`iptables -t nat -L OUTPUT`).
3. Frida server is running and a basic `frida -U -f com.victim` returns a session.
4. The cert-verify hook is loaded and pattern-matched (script logs the address).
5. After all of the above, *now* launch the app and watch Burp.

The most common failure is **#3 missing**, with the second most common being **#5 launched before #4** - Frida never had a chance to hook because `libflutter.so` was already loaded and verifying.

> Flutter apps are the biggest pain point in mobile security testing today. Combining reFlutter patching with Frida hooks gives the most reliable interception. Once the workflow is set up once, every subsequent Flutter app reduces to running the same scripts in the same order - and the time delta from "first launch" to "every API call captured" drops from days to minutes.
