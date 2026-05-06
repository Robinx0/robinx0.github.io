---
title: "Android APK Reverse Engineering: From APK to Source"
description: "Complete guide to decompiling, analyzing, and patching Android applications using jadx, apktool, and smali - covering APK structure, native libraries, manifest analysis, common security flaws, and the full patch-rebuild-resign workflow."
date: 2026-02-15
difficulty: Medium
tags: [android, reverse-engineering, jadx, apktool, smali]
---

## What's Actually Inside an APK

An APK is just a ZIP archive (with a slightly stricter signing structure than ordinary ZIPs). Before any tooling runs, knowing the layout helps you target the right artefact:

```
target.apk
├── AndroidManifest.xml      ← binary XML - needs apktool to decode
├── classes.dex              ← Dalvik bytecode - primary application code
├── classes2.dex, ...        ← MultiDex split files
├── resources.arsc           ← compiled resources
├── res/
│   ├── drawable*/           ← images
│   ├── layout/              ← UI layouts (binary XML)
│   ├── raw/                 ← misc files (configs, certs, models)
│   └── values*/             ← strings, styles, colors
├── assets/                  ← raw bundled files (Flutter snapshots, ML models)
├── lib/
│   ├── armeabi-v7a/*.so     ← native code per ABI
│   ├── arm64-v8a/*.so
│   ├── x86/, x86_64/
├── META-INF/
│   ├── MANIFEST.MF, *.SF    ← v1 (JAR) signing
│   ├── *.RSA / *.DSA / *.EC ← signing certificate
│   └── (v2/v3 sig blocks live in APK Signing Block, not META-INF)
└── stamp-cert-sha256        ← Play Store metadata
```

Every assessment touches multiple layers - Java source from DEX, native code from `lib/`, configuration from `res/raw` and `assets/`, and authorisation logic from the manifest. Skipping any layer means missing findings.

## Step 1: Decompile with jadx

```bash
jadx -d output/ target.apk
```

jadx decompiles DEX bytecode to readable Java source. Search for: API endpoints, hardcoded credentials, encryption keys, certificate pinning implementations, and root detection logic.

### jadx Practical Flags

```bash
# Continue past errors instead of aborting on the first failed class
jadx --no-debug-info --show-bad-code -d output/ target.apk

# GUI version, much better for navigation and dynamic search
jadx-gui target.apk

# Deobfuscate Proguard-renamed identifiers (heuristic, but catches many)
jadx --deobf --deobf-min 3 --deobf-rewrite-cfg -d output/ target.apk

# Limit decompilation to specific package - much faster on huge apps
jadx --classes-only -d output/ target.apk
```

### What to Search For First

Open jadx-gui, hit Search (Ctrl+Shift+F), and run these regex / keyword passes in order:

```
http(s)?://                    ← API endpoints, embedded URLs
[A-Za-z0-9+/]{40,}=*           ← base64 blobs (often encrypted constants)
[0-9a-fA-F]{32,}               ← hex constants (keys, hashes, IVs)
"AES"                          ← cipher selection - leads to key material
SecretKeySpec | KeyGenerator   ← runtime-generated keys
SharedPreferences              ← potentially insecure local storage
PRAGMA key                     ← SQLCipher-encrypted databases
api_key | apiKey | API_KEY     ← obvious credential constants
debuggable | DEBUG             ← debug-mode toggles still in production
TrustManager | HostnameVerifier ← weakened TLS validation
SSLContext\.getInstance        ← custom TLS - pinning candidates
addJavascriptInterface         ← WebView-to-native bridge - RCE candidate
loadUrl\("javascript:         ← JS injection in WebViews
Runtime.exec | ProcessBuilder  ← command execution
File.exists.*\/system\/xbin\/su  ← root detection
```

The patterns above identify ~80% of high-impact findings before you even start dynamic analysis.

### When jadx Output Looks Wrong

If decompiled methods are full of `// JADX WARNING: ...` and unreadable, the app likely uses:

- **R8 with full mode optimisation** - heavy inlining and method merging.
- **DexGuard / DashO / Promon Shield** - commercial obfuscators with control-flow flattening, string encryption, and reflection-only API access.
- **Native-code logic invoked via JNI** - the Java side is a thin shim; real logic is in `lib/*.so`.

Fallback: open the same DEX in CFR (`cfr_0.152.jar`), Procyon, or [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) - different decompilers fail on different patterns and side-by-side comparison usually recovers most methods.

## Step 2: Disassemble with apktool

```bash
apktool d target.apk -o disassembled/
```

apktool produces smali (Dalvik assembly) and decoded resources. Use this when you need to modify and rebuild the APK.

### Why Smali, Not Java

You cannot patch jadx-decompiled Java back into a working APK - the decompilation is lossy. Patching happens at the smali (DEX assembly) layer because smali round-trips losslessly: assemble → DEX → assemble → smali yields identical results.

### Smali at a Glance

A snippet of smali looks like:

```smali
.method public checkRoot()Z
    .registers 4
    const-string v0, "/system/xbin/su"
    new-instance v1, Ljava/io/File;
    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/io/File;->exists()Z
    move-result v2
    return v2
.end method
```

The corresponding Java is:

```java
public boolean checkRoot() {
    File f = new File("/system/xbin/su");
    return f.exists();
}
```

### Common Smali Patches

To force the function to always return `false`, replace its body:

```smali
.method public checkRoot()Z
    .registers 1
    const/4 v0, 0x0          # 0 = false
    return v0
.end method
```

To always return `true`:

```smali
    const/4 v0, 0x1
    return v0
```

To skip a code path:

```smali
# Original
invoke-direct {p0}, Lcom/app/RootChecker;->isRooted()Z
move-result v0
if-eqz v0, :cond_safe
# rooted path

# Patched - invert the condition
invoke-direct {p0}, Lcom/app/RootChecker;->isRooted()Z
move-result v0
if-nez v0, :cond_safe         # NEZ instead of EQZ
```

### Pulling Out Native Libraries

```bash
unzip target.apk lib/arm64-v8a/libnative.so -d native/
file native/lib/arm64-v8a/libnative.so
# ELF 64-bit LSB shared object, ARM aarch64

# Disassemble in Ghidra / IDA / Binary Ninja / radare2
r2 -A native/lib/arm64-v8a/libnative.so
```

When the Java side is a thin wrapper around JNI calls, all the interesting logic - anti-tamper, key derivation, certificate pinning, license validation - lives here. Modern obfuscators like [O-LLVM](https://github.com/obfuscator-llvm/obfuscator) layer on bogus control flow, instruction substitution, and string encryption; budget time accordingly.

## Step 3: Analyze the Manifest

`AndroidManifest.xml` reveals: exported components (activities, services, receivers), permissions, intent filters, backup settings, and debuggable flags.

### High-Value Manifest Findings

```xml
<!-- ✕ debuggable in production -->
<application android:debuggable="true">

<!-- ✕ allowBackup leaks SharedPrefs/databases via adb backup -->
<application android:allowBackup="true">

<!-- ⚠ exported component with no permission gate -->
<activity android:name=".AdminActivity" android:exported="true"/>

<!-- ⚠ deeplink without intent verification -->
<activity android:name=".LinkHandler">
  <intent-filter android:autoVerify="false">
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="https" android:host="example.com"/>
  </intent-filter>
</activity>

<!-- ⚠ usesCleartextTraffic permits HTTP -->
<application android:usesCleartextTraffic="true">

<!-- ⚠ network_security_config that disables pinning in debug only -->
<application android:networkSecurityConfig="@xml/network_security_config">
```

### `network_security_config.xml` Worth Special Attention

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set>
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

If `<debug-overrides>` trusts user certificates **and** the app is `debuggable=true` (or you can patch it to be), Burp's user-installed CA is automatically trusted.

### Exported Component Auditing

Every `exported="true"` component is callable by other (potentially malicious) apps on the device. Check:

- **Activities**: can they be launched without authentication? (e.g. `AdminActivity`, `WebViewActivity` accepting URL extras)
- **Services**: do they expose sensitive operations via Intents?
- **BroadcastReceivers**: do they trust extras without sender verification?
- **ContentProviders**: are read/write permissions enforced? Path-based permissions misconfigured?

`adb shell am start -n com.victim/.AdminActivity` is the simplest verification.

## Step 4: Identify Security Issues

| What to Look For | Where |
|------------------|-------|
| Hardcoded API keys | `strings.xml`, `BuildConfig.java`, native libs |
| Insecure storage | SharedPreferences, SQLite, file storage |
| Weak crypto | Custom implementations, ECB mode, hardcoded IVs |
| Certificate pinning | `network_security_config.xml`, OkHttp CertificatePinner |
| Root detection | Checking `/system/xbin/su`, SafetyNet, Play Integrity |

The expanded checklist I run on every assessment:

| Category | Specific check |
|---|---|
| **Storage** | `SharedPreferences` in plaintext (use EncryptedSharedPreferences); SQLite without SQLCipher; files in `getExternalFilesDir()` (world-readable); SD card writes; Keystore key without `setUserAuthenticationRequired` |
| **Crypto** | Hardcoded keys/IVs in source; ECB mode; static IV across all encryptions; custom MAC implementations; SHA-1 for password hashing; PBKDF2 with iteration count < 10000; key derived from a constant string |
| **Networking** | Cleartext HTTP allowed; `TrustManager` overridden to no-op; `HostnameVerifier.verify` returns true unconditionally; pinning bypassable by network_security_config user override |
| **Authentication** | Biometric flag trusted client-side; session token stored without expiry; logout doesn't invalidate token server-side; predictable session identifiers |
| **WebView** | `setJavaScriptEnabled(true)` + `addJavascriptInterface` + loads remote URLs; `setAllowFileAccess(true)` with file:// loadable; mixed-content allowed |
| **IPC** | Exported components without permission; broadcast receivers acting on extras without validation; ContentProviders with overly broad URI permissions |
| **Deeplinks** | URL parameters reflected into WebViews; deeplink handlers performing privileged actions without confirmation; URL schemes without `autoVerify`/HTTPS App Links |
| **Logging** | Sensitive data in `Log.d/i/e`; reachable in production via `logcat` with `READ_LOGS` (pre-API 17) or via `adb logcat` |
| **Dynamic loading** | `DexClassLoader` from network-loaded sources; native library loaded from external storage |

### Static-Analysis Tooling

Beyond manual review:

- [**MobSF**](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - best automated first-pass; flags ~70% of common issues.
- [**APKLeaks**](https://github.com/dwisiswant0/apkleaks) - fast secret hunter (API keys, tokens, URLs).
- [**Quark-Engine**](https://github.com/quark-engine/quark-engine) - risk scoring per "malicious behaviour" rule set.
- [**androguard**](https://github.com/androguard/androguard) - programmatic API for custom analysis.
- [**semgrep with mobsfscan rules**](https://github.com/MobSF/mobsfscan) - pattern-based code scanning with mobile-specific rules.

## Step 5: Patch and Rebuild

Modify smali code to bypass checks, rebuild with `apktool b`, sign with `apksigner`, install with `adb install`.

### The Full Patch / Rebuild / Resign Cycle

```bash
# 1. Decompile
apktool d target.apk -o work/

# 2. Edit smali (e.g., neutralise root detection)
$EDITOR work/smali/com/example/security/RootDetector.smali

# 3. Make the app debuggable + force network_security_config to trust user CA
sed -i 's|<application |<application android:debuggable="true" |' work/AndroidManifest.xml

# 4. Rebuild
apktool b work/ -o patched-unsigned.apk

# 5. Generate a debug keystore (once)
keytool -genkey -v -keystore debug.keystore -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US" -storepass android -keypass android

# 6. Sign with apksigner (the modern, post-v2 way)
apksigner sign --ks debug.keystore --ks-pass pass:android \
    --ks-key-alias androiddebugkey --key-pass pass:android \
    --out patched.apk patched-unsigned.apk

# 7. Verify
apksigner verify --verbose patched.apk

# 8. Install
adb install -r -t patched.apk
```

### Common Rebuild Failures and Fixes

- **"resource ID is invalid"** during apktool b → run `apktool empty-framework-dir --force` and re-decode with `apktool if framework-res.apk` first.
- **"Couldn't find android-XX target"** → install Android SDK platforms matching the app's `targetSdkVersion`.
- **App installs but crashes immediately** → almost always a smali edit registered the wrong number of registers (`.registers N` directive). Check the modified method's local count.
- **App detects modification at runtime** → the APK signature has changed, and the app verifies it. Hook `PackageManager.getPackageInfo` to return the original signature, or patch out the verification function.
- **"INSTALL_PARSE_FAILED_NO_CERTIFICATES"** on Android 11+ → the v2 signing scheme is required; use `apksigner` (not legacy `jarsigner`).

### `apk-mitm` for the Common Case

If your only goal is to bypass network_security_config pinning, [`apk-mitm`](https://github.com/shroudedcode/apk-mitm) automates the entire decompile → patch → rebuild → sign cycle with a single command:

```bash
apk-mitm target.apk
# Output: target-patched.apk - installable, with permissive nsc and v1+v2 sigs
```

Worth knowing for fast triage; doesn't replace manual smali editing for non-trivial bypasses.

## Native Library Reverse Engineering

For the increasing number of apps that move sensitive logic into JNI:

```bash
# Identify what's exported
nm -D --defined-only lib/arm64-v8a/libnative.so | grep ' T '

# JNI functions are named Java_com_package_Class_method
# e.g. Java_com_example_NativeLib_decryptKey

# Disassemble the function in Ghidra/IDA, look for:
#   - JNIEnv* calls (NewStringUTF, GetStringUTFChars) - string handling
#   - native crypto (AES, ChaCha20) - key derivation
#   - inline obfuscation patterns from O-LLVM (bogus control flow, opaque predicates)
```

For dynamic analysis, hook native exports with Frida directly:

```javascript
Interceptor.attach(Module.findExportByName('libnative.so', 'Java_com_example_NativeLib_decryptKey'), {
    onEnter: function (args) {
        console.log('[+] decryptKey called, JNIEnv=' + args[0]);
    },
    onLeave: function (ret) {
        // ret is a jstring; convert via Java.use('java.lang.String')
    }
});
```

## Building a Repeatable Workflow

A repeatable assessment kit I keep:

1. `apk-mitm` for fast pinning bypass during initial triage.
2. `apktool` + smali patches for targeted bypasses (root, anti-debug, anti-Frida).
3. `jadx-gui` for static review with my saved search patterns.
4. `MobSF` running in the background for first-pass automated findings.
5. `Frida` + `Objection` for runtime hooking once the app launches.
6. Burp Suite or mitmproxy for network capture.
7. Ghidra for native libraries.

A first-time assessment of a moderately complex app takes 1-2 days. With the workflow above, every subsequent app of similar shape collapses to half a day.

> APK reverse engineering is the foundation of Android security testing. Master jadx for analysis and apktool for modification - they complement each other. Native libraries and runtime instrumentation are the next frontiers, but the static workflow you build here is the lever for everything else.
