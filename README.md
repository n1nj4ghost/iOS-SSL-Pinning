# Bypassing SSL Pinning in iOS Applications: A Deep Dive into Mobile Security Testing
## Introduction
SSL pinning is a security mechanism implemented by iOS applications to prevent Man-in-the-Middle (MITM) attacks by validating that the server's certificate matches a pre-pinned certificate or public key. While this is an excellent security practice, penetration testers and security researchers often need to bypass it during authorized security assessments.
This guide explores various techniques to bypass SSL pinning in iOS applications for legitimate security testing purposes.
 - -
## What is SSL Pinning?
SSL pinning is a technique where an application "pins" an expected certificate or public key and refuses to establish a connection if the server presents a different certificate, even if it's signed by a trusted Certificate Authority (CA).
### Types of SSL Pinning:
1. **Certificate Pinning**: The app pins the complete certificate
2. **Public Key Pinning**: The app pins only the public key
3. **Hash Pinning**: The app pins the hash of the certificate or public key
### Why Applications Implement SSL Pinning:
- Protect against compromised CAs
- Prevent MITM attacks
- Ensure secure communication with backend servers
- Compliance with security standards
 - -
## Prerequisites & Tools
Before you begin, ensure you have the following setup:
### Required Tools:
1. **Jailbroken iPhone/iPad** - Running iOS 12–16+ (Palera1n, Checkra1n, etc.)
2. **Burp Suite Professional** - For intercepting HTTPS traffic
3. **Xcode & iOS Development Tools** - For app analysis
4. **Frida** - Dynamic instrumentation toolkit
5. **MobSF (Mobile Security Framework)** - For static analysis
6. **Charles Proxy** - Alternative to Burp Suite
7. **SSH Access Tools** - To connect to jailbroken device
### Required Knowledge:
- Basic iOS development and Swift/Objective-C
- Understanding of cryptography and certificates
- Familiarity with dynamic hooking and instrumentation
 - -
## Method 1: Using Frida for Runtime Instrumentation
Frida is one of the most powerful tools for bypassing SSL pinning. It allows you to inject code into running processes and modify behavior at runtime.
### Step 1: Setup Frida
```bash
# Install Frida on your Mac
pip3 install frida-tools
# Install Frida on the jailbroken iOS device
# SSH into the device
ssh root@<device-ip>
# Install Frida server via Cydia or Sileo
# Or use apt:
apt install frida
```
### Step 2: Create a Frida Script
Create a JavaScript file `bypass-ssl.js` that hooks into the URLSession delegate methods:
```javascript
// Bypass SSL Pinning for URLSession
console.log("[*] Starting SSL Pinning Bypass Script");
// Hook URLSession didReceiveChallenge
var URLSession = ObjC.classes.NSURLSession;
var delegate = ObjC.classes.NSURLSessionDelegate;
// Method 1: Hook URLSession:didReceiveChallenge:completionHandler:
var originalDidReceiveChallenge = delegate["- URLSession:didReceiveChallenge:completionHandler:"];
if (originalDidReceiveChallenge) {
 Interceptor.attach(originalDidReceiveChallenge.implementation, {
 onEnter: function(args) {
 console.log("[+] URLSession:didReceiveChallenge called");
 },
 onLeave: function(retval) {
 console.log("[+] Challenge bypassed");
 }
 });
}
// Method 2: Hook SecTrustEvaluate
var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
if (SecTrustEvaluate) {
 Interceptor.attach(SecTrustEvaluate, {
 onLeave: function(retval) {
 console.log("[+] SecTrustEvaluate called - Bypassing");
 retval.replace(0); // Return errSecSuccess (0)
 }
 });
}
// Method 3: Hook NSURLSession pinning validation
var NSURLSession = ObjC.classes.NSURLSession;
var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
try {
 var sessionConfig = NSURLSessionConfiguration.$defaultSessionConfiguration();
 console.log("[+] URLSession Configuration hooked");
} catch(e) {
 console.log("[!] Error: " + e);
}
// Method 4: Hook CommonCrypto functions
var CCCryptorCreate = Module.findExportByName(null, "CCCryptorCreate");
if (CCCryptorCreate) {
 console.log("[+] CommonCrypto found");
}
console.log("[+] SSL Pinning Bypass Active");
```
### Step 3: Run the Frida Script
```bash
# List running processes
frida-ps -U
# Inject the script into the target app
frida -U -n "TargetAppName" -l bypass-ssl.js
# Or create a standalone hook
frida -U -n "TargetAppName" -l bypass-ssl.js - no-pause
```
 - -
## Method 2: Using BurpSuite with Jailbroken Device
### Step 1: Configure Burp Suite
1. Install Burp Suite on your Mac
2. Generate a custom CA certificate:
 - Burp → Preferences → Network → SSL/TLS
 - Export CA Certificate
### Step 2: Install Certificate on iOS Device
1. Transfer the Burp CA certificate to the device via email
2. Settings → Profile Downloaded → Install
3. Settings → General → About → Certificate Trust Settings → Enable Burp certificate
### Step 3: Configure Proxy
1. Settings → WiFi → Select Network → HTTP Proxy → Manual
2. Set Burp's IP and port (default: 8080)
3. Open the app and intercept traffic
### Step 4: Bypass Pinning with Frida
While Burp intercepts, use Frida to disable certificate validation on the fly (use the script from Method 1).
 - -
## Method 3: Static Binary Patching
This method involves modifying the app binary to remove or disable SSL pinning checks.
### Step 1: Decrypt the App Binary
```bash
# SSH into jailbroken device
ssh root@<device-ip>
# Locate the app
find /var/containers -name "TargetApp.app" -type d
# Dump the encrypted binary using dumpdecrypted or similar tools
cd /var/containers/Bundle/Application/[APP_ID]/TargetApp.app
dumpdecrypted -o TargetApp.decrypted TargetApp
```
### Step 2: Analyze with Hopper or Ghidra
1. Open the decrypted binary in Hopper Disassembler or Ghidra
2. Search for SSL pinning-related functions:
 - `SSLSetEnabledCiphers`
 - `SecTrustEvaluate`
 - `evaluateServerTrust`
 - Certificate validation methods
### Step 3: Patch the Binary
```bash
# Use radare2 or Keystone to patch the binary
r2 -w TargetApp.decrypted
# Example: Replace validation checks with NOP instructions
wa nop @ 0x00012345 # Replace instruction with NOP
```
### Step 4: Repackage and Sign
```bash
# Create new IPA from patched binary
# Use zsign or similar tools to re-sign
zsign -k certificate.p12 -p password -m mobileprovision.mobileprovision -o signed.ipa TargetApp.ipa
```
 - -
## Method 4: Using Objection Framework
Objection is a runtime mobile exploration toolkit that simplifies SSL pinning bypass.
### Installation
```bash
pip3 install objection
```
### Bypass SSL Pinning
```bash
# List running apps
objection -g "TargetApp" explore
# In the objection REPL:
ios sslpinning disable
# Verify the bypass
ios http get https://example.com
```
 - -
## Method 5: Charles Proxy with Certificate Replacement
Charles Proxy provides a GUI-based approach for iOS security testing.
### Steps:
1. Install Charles Proxy on Mac
2. Generate SSL Proxying certificate
3. Install Charles CA certificate on iOS device (similar to Burp)
4. Configure Charles to proxy HTTPS traffic
5. Use Charles's rewriting tools to modify requests/responses
6. Combine with Frida for deeper instrumentation
 - -
## Common SSL Pinning Implementations & Bypass Techniques
### Implementation 1: AFNetworking
```swift
// Vulnerable implementation
let manager = AFHTTPSessionManager()
manager.setSessionDidReceiveAuthenticationChallengeBlock { session, challenge, completionHandler in
 completionHandler(.UseCredential, URLCredentialForTrust(challenge.protectionSpace.serverTrust))
}
```
**Bypass**: Hook `setSessionDidReceiveAuthenticationChallengeBlock`
### Implementation 2: Alamofire
```swift
// Pinning implementation
let manager = ServerTrustManager(evaluators: [
 "example.com": PinnedCertificatesTrustEvaluator()
])
```
**Bypass**: Hook `PinnedCertificatesTrustEvaluator.evaluate()`
### Implementation 3: Custom Certificate Validation
```swift
func evaluateServerTrust(_ trust: SecTrust) -> Bool {
 var secResult: SecTrustResultType = .invalid
 SecTrustEvaluate(trust, &secResult)
 return secResult == .unspecified || secResult == .proceed
}
```
**Bypass**: Hook `SecTrustEvaluate` and return success
 - -
## Advanced Techniques
### 1. Certificate Unpinning via Code Injection
Use Cydia Substrate or Theos to create tweaks that modify app behavior at runtime:
```objc
// Cydia Substrate Tweak
#import <substrate.h>
static BOOL (*original_evaluateServerTrust)(id, SEL, void*) = NULL;
static BOOL hooked_evaluateServerTrust(id self, SEL cmd, void* trust) {
 NSLog(@"[*] evaluateServerTrust called - Bypassing");
 return YES; // Always return YES (trust is valid)
}
__attribute__((constructor))
static void _logicHook() {
 MSHookMessageEx(objc_getClass("SomeClass"), 
 @selector(evaluateServerTrust:), 
 (IMP)&hooked_evaluateServerTrust, 
 (IMP*)&original_evaluateServerTrust);
}
```
### 2. Network Extension Framework Abuse
On newer iOS versions, use NEProxyServer to intercept all traffic:
```swift
let proxySettings = NEProxySettings()
proxySettings.httpServer = NEProxyServer(address: "127.0.0.1", port: 8080)
proxySettings.httpsServer = NEProxyServer(address: "127.0.0.1", port: 8080)
```
### 3. Reverse Engineering with IDA Pro
1. Load app binary in IDA Pro
2. Search for cryptographic function calls
3. Identify certificate validation logic
4. Patch validation routines
 - -
## Detection Evasion
Apps may implement anti-tampering or jailbreak detection. Bypass these with:
```javascript
// Frida script to bypass jailbreak detection
Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
 onEnter: function(args) {
 var path = ObjC.Object(args[2]).toString();
 if (path.includes("Cydia") || path.includes("substrate")) {
 console.log("[!] Jailbreak detection attempt detected");
 }
 }
});
```
 - -
## Ethical & Legal Considerations
⚠️ **Important**: SSL pinning bypass should ONLY be performed:
1. ✅ On applications you own
2. ✅ With explicit written authorization from the application owner
3. ✅ During authorized penetration testing engagements
4. ✅ In controlled testing environments
5. ✅ For legitimate security research
Unauthorized access or modification is illegal and unethical.
 - -
## Mitigation Strategies
### For Developers:
1. **Multi-layer Pinning**: Pin multiple certificates/keys
2. **Certificate Rotation**: Regularly update pinned certificates
3. **Runtime Integrity Checks**: Detect code injection attempts
4. **Obfuscation**: Obscure pinning logic in code
5. **Jailbreak Detection**: Detect and respond to jailbroken devices
6. **Anti-debugging**: Detect and prevent debuggers/Frida
7. **Certificate Transparency (CT)**: Monitor certificates in public logs
### Example Secure Implementation:
```swift
import CryptoKit
class SecureSSLPinning {
 static let pinnedKeys = [
 "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
 "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
 ]
 
 static func evaluateTrust(_ trust: SecTrust) -> Bool {
 var secResult: SecTrustResultType = .invalid
 let status = SecTrustEvaluate(trust, &secResult)
 
 guard status == errSecSuccess else { return false }
 
 // Verify certificate chain
 guard SecTrustGetCertificateCount(trust) > 0 else { return false }
 
 // Pin public keys
 for i in 0..<SecTrustGetCertificateCount(trust) {
 if let cert = SecTrustGetCertificateAtIndex(trust, i) {
 let pubKey = SecCertificateCopyKey(cert)
 // Verify against pinnedKeys
 }
 }
 
 return true
 }
}
```
 - -
## Conclusion
SSL pinning bypass is a critical skill for mobile security professionals. While the techniques discussed are powerful, they should only be used in authorized security testing scenarios. Understanding both sides - how to bypass and how to defend - is essential for building secure iOS applications.
### Key Takeaways:
- Frida is the most versatile tool for runtime instrumentation
- Burp Suite + jailbroken device is the standard pentesting setup
- Multiple bypass methods exist; adapt based on the app's implementation
- Always obtain proper authorization before testing
- Implement multi-layered defenses in production apps
 - -
## References & Further Reading
- [OWASP Mobile Security Testing Guide (MSTG)](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Frida Documentation](https://frida.re/)
- [iOS Security Guide - Apple](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
- [HackingTeam SSL Pinning Bypass Research](https://www.hackingteam.it/)
- [Security Research - Certificate Pinning](https://www.certificate-pinning.io/)
 - -
**Disclaimer**: This article is for educational purposes only. 
**Author**: Rahul Dhiman | Cybersecurity Professional 
**Last Updated**: March 25, 2026
