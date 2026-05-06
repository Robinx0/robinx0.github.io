---
title: "The Complete Guide to Android SSL Pinning Bypass"
description: "Every technique for bypassing SSL certificate pinning on Android - from network_security_config to OkHttp, TrustManager, Flutter, React Native, Xamarin, and native C++ implementations."
date: 2026-02-05
difficulty: Hard
tags: [android, ssl-pinning, frida, certificate, traffic-interception]
---

## Why Apps Pin Certificates

SSL/TLS ensures the server is who it claims to be via the certificate chain. But if an attacker installs their CA on the device (which is required for traffic interception), they can MitM any connection. Certificate pinning is the app's defense - it hardcodes which certificates or public keys it trusts, ignoring the device's trust store.

For security testers, bypassing pinning is the first step to intercepting an app's traffic.

## Setup: Burp + Android Emulator

```bash
# 1. Export Burp's CA as DER
curl -o burp.der http://burp/cert

# 2. Convert to PEM with correct filename for Android system store
openssl x509 -inform DER -in burp.der -out burp.pem
hash=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
cp burp.pem /system/etc/security/cacerts/${hash}.0

# 3. Or use Magisk module for non-rooted devices
# Install "MagiskTrustUserCerts" module
```

## Level 1: network_security_config.xml

Android 7+ respects a per-app security config. Many apps trust only system CAs in production:

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
            <!-- No "user" = ignores user-installed certs -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

### Bypass

Decompile with apktool, modify the config to trust user CAs, rebuild:

```xml
<trust-anchors>
    <certificates src="system" />
    <certificates src="user" />  <!-- Added -->
</trust-anchors>
```

```bash
apktool d target.apk -o target/
# Edit res/xml/network_security_config.xml
apktool b target/ -o patched.apk
apksigner sign --ks key.jks patched.apk
adb install patched.apk
```

## Level 2: OkHttp CertificatePinner

The most common pinning implementation in Android apps:

```java
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.target.com", "sha256/AAAAAAAAAAAAAAAA=")
    .build();
client = new OkHttpClient.Builder().certificatePinner(pinner).build();
```

### Bypass with Frida

```javascript
Java.perform(function() {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCerts) {
        console.log("[*] OkHttp CertificatePinner.check bypassed for: " + hostname);
        return;  // Do nothing - skip the check
    };
    // Also handle the other overload
    CertPinner.check$okhttp.implementation = function(hostname, peerFn) {
        console.log("[*] OkHttp check$okhttp bypassed for: " + hostname);
        return;
    };
});
```

## Level 3: Custom TrustManager

Some apps implement their own `X509TrustManager` to validate certificates:

```javascript
Java.perform(function() {
    // Hook all TrustManager implementations
    var X509TM = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    // Create a TrustManager that trusts everything
    var TrustAllManager = Java.registerClass({
        name: "com.bypass.TrustAll",
        implements: [X509TM],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    // Replace the SSL context's TrustManager
    var tm = Java.array("javax.net.ssl.TrustManager", [TrustAllManager.$new()]);
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, tm, null);
    SSLContext.setDefault(ctx);
});
```

## Level 4: Flutter (BoringSSL)

Flutter apps use Dart's HTTP stack with BoringSSL. They completely ignore the system proxy and certificate store.

### Approach A: reFlutter Patching

```bash
pip install reflutter
reflutter target.apk
# Patches libflutter.so to disable cert verification
# Also adds proxy support
```

### Approach B: Frida + libflutter.so

Hook BoringSSL's verification function directly in the native library:

```javascript
var lib = Module.findBaseAddress("libflutter.so");
// Pattern scan for ssl_crypto_x509_session_verify_cert_chain
var pattern = "FF 43 01 D1 F8 5B 03 A9 F6 53 04 A9";
var matches = Memory.scan(lib, Process.findModuleByName("libflutter.so").size, pattern);
// Patch the function to return 0 (success)
```

## Level 5: React Native

React Native uses the platform's OkHttp on Android. The standard OkHttp bypass usually works. However, some apps use `react-native-ssl-pinning` or `TrustKit`:

```javascript
Java.perform(function() {
    // TrustKit bypass
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        TrustKit.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; };
    } catch(e) {}
    
    // react-native-ssl-pinning bypass
    try {
        var RNSSLPinning = Java.use("com.toyberman.RNSslPinningModule");
        // Hook the fetch method to remove pinning config
    } catch(e) {}
});
```

## Level 6: Native C/C++ (NDK)

The hardest to bypass. Pinning is implemented in native code using OpenSSL/BoringSSL directly. No Java hooks will work.

```javascript
// Hook the native SSL_CTX_set_verify callback
Interceptor.attach(Module.findExportByName("libssl.so", "SSL_CTX_set_verify"), {
    onEnter: function(args) {
        // Force mode to SSL_VERIFY_NONE
        args[1] = ptr(0);
    }
});

// Or hook the verification callback directly
Interceptor.attach(Module.findExportByName("libssl.so", "SSL_set_verify"), {
    onEnter: function(args) {
        args[1] = ptr(0);  // SSL_VERIFY_NONE
        args[2] = ptr(0);  // No callback
    }
});
```

## Universal Bypass Script

For quick testing, use objection's `android sslpinning disable` or Frida's universal bypass scripts that hook all known pinning libraries simultaneously.

```bash
# Objection (wraps multiple Frida hooks)
objection -g com.target.app explore
> android sslpinning disable

# Or use Frida with a universal script
frida -U -f com.target.app -l universal_ssl_bypass.js --no-pause
```

## Troubleshooting

| Problem | Solution |
|---|---|
| App crashes on hook | Check Frida version compatibility, try spawn vs attach |
| Traffic still not visible | App may use non-HTTP protocol (gRPC, WebSocket, custom TCP) |
| Proxy not receiving traffic | Flutter/Xamarin ignore system proxy - use iptables redirect |
| Certificate errors persist | Make sure Burp CA is in system store, not just user store |
| App detects Frida | Use frida-gadget injected via apktool, or use Magisk Hide |

> Start with objection's universal bypass. If that fails, identify the specific pinning implementation via static analysis (jadx), then write targeted Frida hooks. Save native-level BoringSSL hooking for last - it's the hardest and most error-prone approach.
