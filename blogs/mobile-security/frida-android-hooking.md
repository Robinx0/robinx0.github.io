---
title: "Android Runtime Hooking with Frida"
description: "Using Frida to bypass SSL pinning, defeat root detection, intercept crypto operations, and hook JNI native functions - complete coverage of Java-side and native-side instrumentation, the universal hook patterns, and modern anti-Frida defeat techniques."
date: 2026-03-08
difficulty: Medium
tags: [frida, android, hooking, ssl-pinning, root-detection]
---

## Why Frida Anchors Mobile Assessment Tooling

Static analysis (jadx, apktool) tells you what the app *contains*. Frida tells you what the app *does* the moment it does it. For mobile assessments, Frida fills the gap between "I read the decompiled code and think I know what would happen" and "I just watched it happen with arguments and return values printed". Every assessment uses Frida to:

1. Bypass defensive checks (root, debugger, integrity, pinning) so the rest of testing can proceed.
2. Watch the cryptographic and authentication primitives in real time to extract keys and tokens.
3. Capture the JNI boundary so native code becomes greppable instead of opaque.
4. Test fixes before re-engaging the dev team - proving an issue is exploitable beats arguing about a static finding.

Setup is one-time and well-documented; the per-app value compounds quickly because every script you write becomes part of a personal toolkit.

## Setup, Briefly

```bash
# Host
pip install frida-tools

# Device - push frida-server matching the host's frida version
wget https://github.com/frida/frida/releases/download/<ver>/frida-server-<ver>-android-arm64.xz
unxz frida-server-*.xz
adb push frida-server-* /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"

# Verify
frida-ps -U | head
# Output: process list from device → connection works
```

For **non-rooted** devices, use the [Frida Gadget](https://frida.re/docs/gadget/) - repackage the APK with `libfrida-gadget.so` so the runtime hosts an embedded Frida server. [Objection's `objection patchapk`](https://github.com/sensepost/objection) automates this.

## SSL Pinning Bypass

Hook `OkHttp3.CertificatePinner.check()`, `TrustManagerImpl.verifyChain()`, and `WebViewClient.onReceivedSslError()` to accept any certificate chain.

Apps pin certificates in many places. A single hook never covers them all. The reliable approach is to layer hooks across every common pinning library and let whichever applies kick in.

### Universal SSL-Bypass Script

```javascript
Java.perform(function () {
    // ── OkHttp3 ─────────────────────────────────────
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (h, p) {
            console.log('[+] OkHttp CertificatePinner.check(' + h + ') bypassed');
            return;
        };
    } catch (_) {}

    // ── TrustManagerImpl (Android 7+ default) ──────
    try {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMI.verifyChain.implementation = function (untrusted, trustAnchorChain, host, verifyPinning, ocsp, tls) {
            console.log('[+] TrustManagerImpl.verifyChain(' + host + ') bypassed');
            return untrusted;
        };
        TMI.checkTrustedRecursive.implementation = function (cert, ocsp, tls, host, clientAuth, untrusted, trustAnchorChain) {
            return Java.use('java.util.ArrayList').$new();
        };
    } catch (_) {}

    // ── WebView SSL errors ─────────────────────────
    try {
        var WVC = Java.use('android.webkit.WebViewClient');
        WVC.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[+] WebViewClient.onReceivedSslError → proceed');
            handler.proceed();
        };
    } catch (_) {}

    // ── HttpsURLConnection ─────────────────────────
    try {
        var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
        HUC.setDefaultHostnameVerifier.implementation = function (v) {
            console.log('[+] setDefaultHostnameVerifier neutralised');
        };
    } catch (_) {}

    // ── Custom X509TrustManager implementations ────
    var X509 = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [X509],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });
    var TMArray = [TrustManager.$new()];

    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
    ).implementation = function (km, tm, sr) {
        console.log('[+] SSLContext.init() - replacing TrustManagers');
        this.init(km, TMArray, sr);
    };
});
```

Worth keeping the [HTTPToolkit's JS-injection-based unpinning script](https://github.com/httptoolkit/frida-android-unpinning) bookmarked - it's maintained, covers an even wider variety of pinning libraries, and just works for most apps in a single command.

### When Pinning Is in Native Code

Apps using OpenSSL/BoringSSL pinning at the JNI boundary need a native hook. See the Flutter post for the BoringSSL `ssl_verify_peer_cert` pattern; the same approach generalises to any native library that wraps OpenSSL/BoringSSL.

## Root Detection Bypass

Hook `File.exists()` to return false for root indicators (`/system/xbin/su`, etc.) and `Runtime.exec()` to block `which su` checks.

Modern RASP toolkits chain dozens of root checks. A working bypass intercepts every path systematically.

### Comprehensive Root Bypass

```javascript
Java.perform(function () {
    var rootIndicators = [
        '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
        '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
        '/su/bin/su', '/system/bin/.ext/.su', '/system/etc/init.d/99SuperSUDaemon',
        '/dev/com.koushikdutta.superuser.daemon/', '/system/xbin/daemonsu',
        '/system/etc/.has_su_daemon', '/system/etc/.installed_su_daemon',
        '/dev/com.koushikdutta.superuser.daemon/'
    ];

    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (rootIndicators.indexOf(path) !== -1 || path.indexOf('magisk') !== -1) {
            console.log('[+] File.exists(' + path + ') → false');
            return false;
        }
        return this.exists();
    };

    // Runtime.exec("which su" / "su -c id" etc.)
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd.indexOf('su') !== -1 || cmd === 'mount' || cmd === 'getprop') {
            console.log('[+] Runtime.exec(' + cmd + ') blocked');
            throw Java.use('java.io.IOException').$new('cmd not found');
        }
        return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
        if (cmd[0].indexOf('su') !== -1) {
            console.log('[+] Runtime.exec([' + cmd.join(',') + ']) blocked');
            throw Java.use('java.io.IOException').$new('cmd not found');
        }
        return this.exec(cmd);
    };

    // PackageManager.getInstalledApplications - root manager apps
    var PM = Java.use('android.app.ApplicationPackageManager');
    var rootPackages = ['com.topjohnwu.magisk', 'com.koushikdutta.superuser', 'com.thirdparty.superuser', 'eu.chainfire.supersu', 'com.noshufou.android.su'];
    PM.getInstalledApplications.overload('int').implementation = function (flags) {
        var apps = this.getInstalledApplications(flags);
        var iter = apps.iterator();
        var filtered = Java.use('java.util.ArrayList').$new();
        while (iter.hasNext()) {
            var app = Java.cast(iter.next(), Java.use('android.content.pm.ApplicationInfo'));
            if (rootPackages.indexOf(app.packageName.value) === -1) filtered.add(app);
        }
        return filtered;
    };

    // System.getProperty("ro.debuggable") / getprop checks
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (k) {
        if (k === 'ro.debuggable' || k === 'ro.secure') {
            console.log('[+] System.getProperty(' + k + ') → safe value');
            return k === 'ro.debuggable' ? '0' : '1';
        }
        return this.getProperty(k);
    };
});
```

For commercial RASP toolkits ([Promon Shield](https://promon.io/), [Appdome](https://www.appdome.com/), [DexGuard](https://www.guardsquare.com/dexguard)), additional checks include:

- Reading `/proc/self/maps` for mounted Magisk modules.
- Native `stat()` on root binary paths via JNI (Java-side `File.exists` hook misses these).
- Memory inspection of `linker64`'s loaded module list.
- Inotify watches on `/system` / `/data/local/tmp`.

The native-side checks need to be defeated with `Interceptor.attach` on `libc`'s `stat`, `access`, `open`:

```javascript
var stat = Module.findExportByName('libc.so', 'stat');
Interceptor.attach(stat, {
    onEnter: function (args) {
        var path = Memory.readUtf8String(args[0]);
        if (rootIndicators.indexOf(path) !== -1) {
            this.fakeMiss = true;
            args[0] = Memory.allocUtf8String('/dev/null/nope');
        }
    }
});
```

## Intercepting Encryption

Hook `javax.crypto.Cipher.doFinal()` to log plaintext inputs and outputs alongside the cipher mode. Captures encryption keys in real time.

This single hook is the highest-yield primitive in mobile assessment. Every app that does any cryptography routes through `Cipher`.

### Universal Crypto Sniffer

```javascript
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
        var algo = key.getAlgorithm();
        var enc  = key.getEncoded ? key.getEncoded() : null;
        var hex  = enc ? bytesToHex(enc) : '<opaque>';
        console.log('[Cipher.init] algo=' + algo + ' mode=' + mode + ' key=' + hex);
        return this.init(mode, key);
    };

    Cipher.doFinal.overload('[B').implementation = function (input) {
        var inHex  = bytesToHex(input);
        var output = this.doFinal(input);
        var outHex = bytesToHex(output);
        console.log('[Cipher.doFinal] mode=' + this.getAlgorithm() +
                    ' in=' + inHex + ' out=' + outHex);
        return output;
    };

    function bytesToHex(arr) {
        if (!arr) return '';
        var hex = '';
        for (var i = 0; i < arr.length; i++) {
            var b = arr[i] & 0xFF;
            hex += (b < 16 ? '0' : '') + b.toString(16);
        }
        return hex;
    }

    // PBKDF2 / KDF inputs
    var PBE = Java.use('javax.crypto.spec.PBEKeySpec');
    PBE.$init.overload('[C', '[B', 'int', 'int').implementation = function (pwd, salt, iter, keyLen) {
        console.log('[PBEKeySpec] password="' + pwd.join('') + '" salt=' + bytesToHex(salt) + ' iters=' + iter);
        return this.$init(pwd, salt, iter, keyLen);
    };

    // MessageDigest
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload().implementation = function () {
        var out = this.digest();
        console.log('[MD.digest] algo=' + this.getAlgorithm() + ' out=' + bytesToHex(out));
        return out;
    };
});
```

Run this on any app and within seconds you'll see every encryption operation, with keys, IVs, plaintext, and ciphertext. Combine with traffic capture and you have the complete cryptographic kill chain.

### Mac and HMAC Capture

```javascript
var Mac = Java.use('javax.crypto.Mac');
Mac.init.overload('java.security.Key').implementation = function (k) {
    console.log('[Mac.init] algo=' + this.getAlgorithm() + ' key=' + bytesToHex(k.getEncoded()));
    return this.init(k);
};
Mac.doFinal.overload('[B').implementation = function (input) {
    var out = this.doFinal(input);
    console.log('[Mac.doFinal] in=' + bytesToHex(input) + ' out=' + bytesToHex(out));
    return out;
};
```

## JNI / Native Hooking

For native libraries, use `Interceptor.attach()` on exported functions to capture arguments and return values from native code.

When the Java side is a thin shim and all interesting logic lives in `lib/*.so`, Frida's native-side API kicks in.

### Hooking JNI Exports by Name

JNI methods follow the naming convention `Java_<package>_<class>_<method>`:

```javascript
var lib = Module.findBaseAddress('libnative.so');
var func = Module.findExportByName('libnative.so', 'Java_com_example_NativeLib_decryptKey');

Interceptor.attach(func, {
    onEnter: function (args) {
        // args[0] = JNIEnv*, args[1] = jobject this, args[2..] = Java args
        // For jstring arguments, convert via JNIEnv->GetStringUTFChars
        this.env = args[0];
        var env = this.env.readPointer();
        var GetStringUTFChars = new NativeFunction(
            env.add(0x29A).readPointer(),    // offset depends on JNIEnv version
            'pointer', ['pointer','pointer','pointer']);
        // simpler: use Java.vm.getEnv() helpers
        console.log('[decryptKey] arg2=' + args[2]);
    },
    onLeave: function (retval) {
        console.log('[decryptKey] returned ' + retval);
    }
});
```

### Hooking Internal (Non-Exported) Functions

Use byte-pattern matching:

```javascript
var lib = Process.findModuleByName('libnative.so');
Memory.scan(lib.base, lib.size, '?? ?? ?? ?? FF 03 03 D1 ...', {
    onMatch: function (addr, size) {
        Interceptor.attach(addr, {
            onEnter: function (args) { console.log('hit ' + addr); }
        });
        return 'stop';
    }
});
```

### Memory Reads and Writes

```javascript
// Read a struct
var ptr_data = ptr('0x7f1234abc0');
var len = ptr_data.readU32();
var bytes = ptr_data.add(4).readByteArray(len);
console.log(hexdump(bytes, { length: len, ansi: true }));

// Write
ptr_data.writeU32(0xdeadbeef);
```

### Hooking C++ Methods (Mangled Names)

C++ symbols are name-mangled. Demangle first:

```bash
nm -D --defined-only libnative.so | c++filt | grep MyClass
```

Then attach by the mangled name (Frida doesn't demangle for you):

```javascript
var sym = '_ZN7MyClass5myFunEi';   // _MyClass::myFun(int)
Interceptor.attach(Module.findExportByName('libnative.so', sym), { ... });
```

## Anti-Frida Counter-Measures

Modern hardened apps actively detect Frida. The detections you'll meet:

1. **Process listing** - checking `/proc/self/maps` for `frida-agent-*`, `frida-gadget`, or any `*.so` not in expected paths.
2. **Port scan** - `connect()` to localhost:27042 succeeds → frida-server is running.
3. **Thread name inspection** - `gum-js-loop`, `gmain`, `gdbus` are characteristic Frida-injected threads visible via `/proc/self/task/*/comm`.
4. **Function prologue check** - read the first 16 bytes of a frequently-hooked function (e.g. `dlopen`) and compare against expected; Frida's trampoline replaces the prologue.
5. **`gum_dispatcher_*` symbol lookup** in loaded modules.
6. **`PtraceProtect` / `prctl(PR_SET_DUMPABLE, 0)`** to deny attachment.

### Defeating Anti-Frida

- **Rename `frida-server`** binary on disk and inject by other means.
- **Random port**: `frida-server -l 0.0.0.0:<random>` and `frida -H 127.0.0.1:<random>`.
- **`frida-magisk-gadget`** Magisk module - gadget is loaded via Zygisk, less detectable.
- **[Strongr Frida](https://github.com/hzzheyang/strongR-frida-android)** - patched frida-server with detection-defeating modifications.
- **Hide `/proc` entries** by hooking `open("/proc/self/maps", ...)` and filtering Frida lines from the returned content. Tools like [`fridanti`](https://github.com/AeonLucid/AndroidNativeEmu) automate this.
- **For final-tier RASP** (Promon Shield, Appdome, DexGuard), drop Frida entirely and use [LSPosed](https://github.com/LSPosed/LSPosed) + [Yahfa](https://github.com/PAGalaxyLab/YAHFA) for ART-level hooks that don't trip Frida-specific checks.

## Workflow

A repeatable per-app workflow that I run:

```
1. apktool d, jadx-gui - static review for surface area
2. Frida server up (renamed if app is hardened)
3. Inject SSL bypass + root bypass at app start
4. Run the app through every flow - login, transactions, settings
5. Crypto sniffer always running - capture every key/cipher call
6. Burp captures all HTTPS - review request/response pairs
7. Identify each defensive check that fired (logs / errors)
8. Targeted hooks for each - patch and re-run
9. JNI hooks for native logic, if Java side is thin
10. Document findings: scripts + reproduction steps + impact
```

> Start broad (SSL bypass + root bypass), then narrow your hooks based on what you discover in the traffic. The universal scripts above unblock the assessment in minutes; the per-app hooks you write afterwards are where the real findings come from.
