# Operational iOS SSL Pinning Bypass — Working Playbook

> You're testing iOS apps in authorized scope (bug bounty / pentest / CTF / research on apps you control). SSL pinning blocks your intercept proxy (Burp / mitmproxy / Caido) from seeing TLS traffic, even after installing your CA. This playbook is the operational sequence: cheapest tooling first, surgical Frida hooks next, binary patching as the last resort.

**Assume jailbroken device for production runs**; non-jailbroken path is documented for when only an IPA is available.

---

## Phase 0 — Prerequisites

### Device Setup

**Preferred jailbreak:**
- **A11 and below, iOS 15–17**: `palera1n`
- **A12+, iOS 15–16.6.1**: `Dopamine`
- **Legacy hardware**: `checkra1n`

**SSH access:**
```bash
iproxy 2222 22  # over USB via libimobiledevice
# Default: root / alpine (rotate immediately after first boot)
```

**On-device packages** (via Sileo/Zebra/apt):

| Package | Purpose |
|---------|---------|
| `frida-server` | Match version to host Frida (from build.frida.re repo) |
| `Filza` or `NewTerm 3` | File browsing + on-device shell |
| `SSL Kill Switch 3` | Drop-in pinning bypass for iOS 14–17 |
| `Liberty Lite (Beta)` or `Choicy` | Prevent jailbreak detection |
| `appinst` or `TrollStore` | Sideload patched IPAs without re-signing |

### Host Setup (Windows / macOS / Linux)

```bash
# Python environment
python3 -m venv ~/ios-pentest
source ~/ios-pentest/bin/activate
pip install frida-tools objection

# Proxy tooling
pip install mitmproxy
# OR: Burp Suite (configure listener on 0.0.0.0:8080)
```

**Essential static analysis tools:**
- `class-dump`
- `otool`
- `lldb`
- `Hopper` / `IDA` / `Ghidra`
- `frida-ios-dump` (AloneMonkey)

### CA Installation Checklist

**Critical**: Install Burp/mitmproxy CA on device:

1. Settings → General → VPN & Device Management → trust profile
2. Settings → General → About → Certificate Trust Settings → **enable for the CA**

> ⚠️ **Common silent failure**: Root CA installed but **not trusted for TLS** — verify both steps above.

### Connectivity Sanity Check

**Before touching pinning**, prove the proxy + CA chain works on a **non-pinned** app:

```
Safari → https://example.com
✓ No warning
✓ Request appears in proxy
```

If Safari fails, your CA install is wrong — fix that first.

---

## Phase 1 — Recon: Identify the Pinning Implementation

> Pin bypass is library-specific. Fingerprint first; don't fire generic hooks blindly.

### 1.1 Pull the Binary

**From jailbroken device:**
```bash
frida-ios-dump -l                      # List installed apps
frida-ios-dump <bundle.id>             # Produces Decrypted.ipa
unzip Decrypted.ipa -d app/
```

The Mach-O binary is at: `app/Payload/<App>.app/<App>`

### 1.2 Static Fingerprint

**Search for known pinning identifiers:**
```bash
strings -a Payload/App.app/App | grep -Ei \
  'pin|TrustKit|AFNetworking|AFSecurityPolicy|Alamofire|ServerTrust|TLSPin|publicKeyHashes'
```

**Method/class dump:**
```bash
class-dump Payload/App.app/App > classdump.txt
grep -Ei 'Pinning|TrustEvaluator|ServerTrust|CertificateValidator' classdump.txt
```

**Embedded certificates / pin sets:**
```bash
find Payload/App.app -name '*.cer' -o -name '*.der' -o -name '*.crt' -o -name '*.pem'
grep -r 'NSPinnedDomains' Payload/App.app/Info.plist   # iOS 14+ ATS pinning
```

### 1.3 Fingerprinting Matrix

| Signature | Stack | Bypass Tier |
|-----------|-------|-------------|
| `AFSecurityPolicy`, `AFURLSessionManager` | AFNetworking | SSL Kill Switch 3 |
| `Alamofire`, `ServerTrustManager`, `PublicKeysTrustEvaluator` | Alamofire | Frida hook (§1.4) |
| `TSKPinningValidator`, `TrustKitConfig` | TrustKit | TrustKit hook |
| `NSPinnedDomains` in Info.plist | iOS 14+ ATS | SSL Kill Switch 3 / plist patch |
| `SecTrustEvaluate(WithError)?` direct calls | Custom CFNetwork | Frida `SecTrust*` hook |
| `BoringSSL_Context_set_custom_verify`, `ssl_crypto_x509_session_verify_cert_chain` | Flutter | libflutter.so hook |
| `cronet`, `BoringSSL_SSL_get_peer_cert_chain` | Chromium/Cronet | Cronet hook |
| `_TtC..._URLSessionPinningDelegate` names | Custom Swift | Hook `URLSession:didReceive:` |
| References to `ProGuard`, `Xamarin`, `Mono` | Xamarin | Mono hook |

---

## Phase 2 — Bypass Methods (Escalation Order)

### Method A — SSL Kill Switch 3 (Try First — 30 seconds)

Works for **~70% of apps** using stock AFNetworking, ATS `NSPinnedDomains`, or no pinning:

1. Install via Sileo: `https://repo.thecaptain989.com/` or evilpenguinblog's repo
2. Settings → SSL Kill Switch 3 → enable for target bundle ID
3. Force-close and relaunch app
4. Replay the flow with proxy attached

✓ **Done** if traffic appears in proxy.

❌ **Doesn't work on:**
- TrustKit with custom callback
- Flutter / Cronet
- Custom `SecTrustEvaluate` checks
- Alamofire's `PublicKeysTrustEvaluator`

→ **Proceed to Method B.**

### Method B — Objection (Frida Wrapper — 2 Minutes)

```bash
# On host, with frida-server running on device
objection -g <bundle.id> explore
```

Inside the Objection REPL:
```
ios sslpinning disable
```

This patches:
- `SecTrustEvaluate` / `SecTrustEvaluateWithError`
- NSURLSession delegate `didReceiveChallenge`
- AFNetworking's `setSSLPinningMode:`
- TrustKit's `TSKPinningValidator.evaluateTrust:forHostname:`

✓ **Done** if traffic appears.

❌ **Doesn't work on:**
- Alamofire's `PublicKeysTrustEvaluator`
- Flutter
- Custom BoringSSL

→ **Proceed to Method C.**

### Method C — Targeted Frida Hooks

Run from host:
```bash
frida -U -f <bundle.id> -l bypass.js --no-pause
```

Combine patterns below — they don't conflict.

#### C.1 — Generic Apple ObjC + Sec* Trust APIs

```javascript
// bypass.js — generic iOS trust bypass
if (ObjC.available) {
  try {
    // NSURLSession delegate path
    var resolver = new ApiResolver('objc');
    resolver.enumerateMatches(
      '-[* URLSession:didReceiveChallenge:completionHandler:]',
      {
        onMatch: function (m) {
          Interceptor.attach(m.address, {
            onEnter: function (args) {
              this.challenge = new ObjC.Object(args[3]);
              this.handler   = new ObjC.Block(args[4]);
            },
            onLeave: function () {
              try {
                var protSpace = this.challenge.protectionSpace();
                var trust = protSpace.serverTrust();
                if (trust && !trust.isNull()) {
                  var cred = ObjC.classes.NSURLCredential
                    .credentialForTrust_(trust);
                  this.handler.implementation(0, cred);
                }
              } catch (e) { }
            }
          });
        },
        onComplete: function () {}
      }
    );
  } catch (e) { console.log('[!] NSURLSession hook failed: ' + e); }
}

// Sec* C API path — catches Cronet, custom CFNetwork
var SecTrustEvaluate = Module.findExportByName(null, 'SecTrustEvaluate');
if (SecTrustEvaluate) {
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(
    function (trust, resultPtr) {
      Memory.writeU32(resultPtr, 1);  // kSecTrustResultProceed = 1
      return 0;  // errSecSuccess
    },
    'int', ['pointer', 'pointer']
  ));
}

var SecTrustEvaluateWithError = Module.findExportByName(null, 'SecTrustEvaluateWithError');
if (SecTrustEvaluateWithError) {
  Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(
    function (trust, errorPtr) {
      if (!errorPtr.isNull()) Memory.writePointer(errorPtr, NULL);
      return 1;  // true => trusted
    },
    'bool', ['pointer', 'pointer']
  ));
}
```

#### C.2 — TrustKit

```javascript
if (ObjC.available && ObjC.classes.TSKPinningValidator) {
  var V = ObjC.classes.TSKPinningValidator;
  V['- evaluateTrust:forHostname:'].implementation = function () {
    return 0;  // TSKTrustEvaluationSuccess = 0
  };
  
  if (V['- handleChallenge:forHostname:completionHandler:']) {
    V['- handleChallenge:forHostname:completionHandler:'].implementation =
      function (challenge, hostname, completion) {
        var cred = ObjC.classes.NSURLCredential
          .credentialForTrust_(challenge.protectionSpace().serverTrust());
        new ObjC.Block(completion).implementation(0, cred);
        return true;
      };
  }
}
```

#### C.3 — AFNetworking

```javascript
if (ObjC.available && ObjC.classes.AFSecurityPolicy) {
  var P = ObjC.classes.AFSecurityPolicy;
  P['- evaluateServerTrust:forDomain:'].implementation = function () {
    return true;
  };
  P['- setSSLPinningMode:'].implementation = function () { };
  P['- setAllowInvalidCertificates:'].implementation = function () { };
}
```

#### C.4 — Alamofire

```javascript
// Alamofire's PublicKeysTrustEvaluator is Swift name-mangled
// Hook C trust APIs (C.1 already does) and disable ServerTrustManager:

var alamo = Process.findModuleByName('Alamofire');
if (alamo) {
  alamo.enumerateSymbols().forEach(function (s) {
    if (/TrustEvaluator.*evaluate/.test(s.name)) {
      try {
        Interceptor.replace(s.address, new NativeCallback(
          function () { return 1; },
          'bool', ['pointer','pointer','pointer']
        ));
      } catch (e) { }
    }
  });
}
```

#### C.5 — Flutter

Flutter ships its own BoringSSL; target is `ssl_crypto_x509_session_verify_cert_chain`:

```javascript
var flutter = Process.findModuleByName('Flutter');
if (flutter) {
  // Offset shifts per Flutter release — use Ghidra to locate pattern
  // Practical approach: use flutter-ssl-bypass-frida repository
  // Identify version: strings Flutter | grep 'Flutter Engine'
}
```

**Recommendation**: Clone `flutter-ssl-bypass-frida` or `disable-flutter-tls`, match offset for your Flutter version.

#### C.6 — Cronet / Chromium

If you see `cronet_*` symbols, this is a Chromium build. Cronet bundles BoringSSL:

```javascript
// SecTrustEvaluate hooks don't apply to Cronet
// Use frida-cronet-bypass or hook Cronet_UrlRequest_*Verify*
```

#### C.7 — Jailbreak Detection (Preflight)

If app dies before you can hook, jailbreak detection is the gate:

```javascript
// File-existence probes
var open = Module.findExportByName(null, 'open');
Interceptor.attach(open, {
  onEnter: function (args) {
    this.path = Memory.readUtf8String(args[0]);
  },
  onLeave: function (retval) {
    if (this.path && /(Cydia|Sileo|MobileSubstrate|frida|cycript|apt|bash|ssh|jailbreak)/i.test(this.path)) {
      retval.replace(-1);
    }
  }
});

// fork() — JB checks often try fork() and bail if it works
var fork = Module.findExportByName(null, 'fork');
if (fork) {
  Interceptor.replace(fork, new NativeCallback(function () {
    return -1;
  }, 'int', []));
}

// URL scheme checks (canOpenURL: with cydia://, sileo://)
if (ObjC.available) {
  var UIApp = ObjC.classes.UIApplication;
  UIApp['- canOpenURL:'].implementation = function (url) {
    var s = url.absoluteString().toString();
    if (/(cydia|sileo|undecimus|filza)/i.test(s)) return false;
    return this.canOpenURL_(url);
  };
}
```

### Method D — Non-Jailbroken: Patch the IPA

When you only have the IPA (no JB device):

#### D.1 — Objection Patchipa (Recommended)

```bash
objection patchipa --source Target.ipa --codesign-signature <CERT_HASH>
```

This injects `FridaGadget.dylib` + load command. Resign and sideload via Xcode / Sideloadly / AltStore, then run Frida.

#### D.2 — Static Binary Patch

Open binary in Hopper/Ghidra:
- Find `SecTrustEvaluateWithError`
- Replace prologue with `MOV X0, #1 ; RET`
- For AFNetworking: NOP the `evaluateServerTrust:forDomain:` body + force true
- Resign: `ldid -S` (on-device) or `codesign --force --sign <dev-id>` (macOS)

#### D.3 — `optool` / `insert_dylib`

Add load command for `libsubstitute.dylib` or `FridaGadget.dylib` if patchipa fails.

**Resigning on Windows**: Use a macOS VM or CI runner:
```bash
codesign --force --sign <dev-id> --entitlements Entitlements.plist <binary>
```

**Avoid resigning**: Use **TrollStore** on compatible iOS (15.0–16.6.1, 17.0).

### Method E — Plist Tweak for ATS Pinning

iOS 14+ `NSPinnedDomains` in `Info.plist`:

```bash
unzip Target.ipa -d ipa/
```

Edit `ipa/Payload/App.app/Info.plist` — **remove** this section:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.target.com</key>
        <dict>
            <key>NSPinnedCAIdentities</key>
            <array>
                <dict><key>SPKI-SHA256-BASE64</key><string>...</string></dict>
            </array>
        </dict>
    </dict>
</dict>
```

Optionally add:
```xml
<key>NSAllowsArbitraryLoads</key>
<true/>
```

Then resign and sideload. **Note**: Only works if app relies solely on ATS pinning — most production apps add code-level checks.

---

## Phase 3 — Verification

After running bypass:

1. **Proxy hit**: Relaunch app cold, exercise login / profile / known API endpoint
   - ✓ Burp should show decrypted request

2. **Don't trust login screen alone**: Many apps pin only `/auth/token`, letting others through plainly
   - Walk a **real** user flow

3. **Re-pin probe**: Kill app, disable Frida hook, relaunch
   - ✓ Requests should **fail** if pinning is real

4. **WebView traffic**: `WKWebView` uses separate TLS stack
   - Verify by visiting HTTPS page in in-app WebView

5. **Background tasks**: Some pinning lives in APNs registration or `BGTaskScheduler` jobs
   - Trigger deliberately if applicable

6. **Documentation**: For bug-bounty report:
   - Note pinning **was** present and bypassed
   - Don't claim "no pinning" — bypassability on JB device is different from stock device

---

## Phase 4 — Common Failure Modes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| App crashes on launch with `frida -f` | Jailbreak / Frida detection | C.7 hooks; try `frida --runtime=v8` |
| `Failed to attach: unable to connect` | `frida-server` not running or version mismatch | `pkill frida-server; frida-server &`; pin versions |
| Burp shows no traffic, no errors | CA installed but not trusted for TLS | Settings → About → Certificate Trust Settings → enable |
| `NSURLErrorDomain -1200` | TLS handshake fail — proxy CA missing or pinning still on | Verify CA in Safari first; re-check bypass |
| Some requests proxied, others not | App uses two HTTP stacks (NSURLSession + Alamofire) | Layer hooks: C.1 + C.4 + C.5 |
| Bypass works once, fails on re-launch | App caches pin result in keychain | Hook `keychainServices` or rerun with `--no-pause -f` |
| Flutter app — nothing works | BoringSSL inside Flutter ignores system trust | C.5, must hit Flutter's verify function |
| React Native / NativeScript | JS-layer pinning via `react-native-ssl-pinning` | Frida-hook bridge call or patch JS bundle |

---

## Phase 5 — Output & Deliverables

For each app bypassed, record in a notebook (kept in your scope directory):

- **App bundle ID + version**
- **Pinning library detected** (from Phase 1)
- **Method used** (A/B/C-x/D/E) + exact Frida script
- **Pinned vs unpinned endpoints**
- **Pin set / SPKI hashes recovered**
- **Bypass persistence** across app updates

### Critical Artifacts to Produce

```
~/ios-pentest/
├── bypass.js                 # Layered Frida script
├── app-name-notes.md         # Per-app fingerprint + method + endpoints
└── app-name-decrypted.ipa    # For non-JB patching path
```

---

## References

- **OWASP MASTG** — Mobile App Security Testing Guide, iOS Network Communication
- **Frida iOS Handbook** — https://frida.re/docs/ios/
- **Objection** — https://github.com/sensepost/objection
- **SSL Kill Switch 3** — https://github.com/julioverne/SSLKillSwitch
- **TrustKit** — https://github.com/datatheorem/TrustKit (API surface reference)
- **frida-ios-dump** — IPA decryption from JB device (AloneMonkey)
- **HackTricks** — iOS pentesting checklist

---

## Quick Start: Dry-Run This Plan

1. **Open this file**, walk Phases 0 → 1 mentally
2. **List anything missing** on your host (Windows) — e.g., `iproxy` / libimobiledevice?
3. **Pick a target app** in scope
4. **Run Phase 1 fingerprint only** (no bypass yet)
   - The output tells us which method to script for

**When ready to execute**, I'll generate the exact `bypass.js` for the target's specific pin stack.
