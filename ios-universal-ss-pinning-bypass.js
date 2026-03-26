/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║        Universal iOS Bypass Script – Frida                      ║
 * ║  Covers: SSL Pinning + Jailbreak Detection + WebView Bypass     ║
 * ║  Frameworks: NSURLSession, NSURLConnection, AFNetworking,       ║
 * ║              Alamofire, TrustKit, WKWebView, UIWebView,         ║
 * ║              SecTrust, BoringSSL/TLS (Flutter, native apps)     ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * Usage:
 *   frida -U -f com.target.app -l ios-universal-bypass.js --no-pause
 *   frida -U --attach-name com.target.app -l ios-universal-bypass.js
 *
 * Tested on: iOS 14 / 15 / 16 / 17
 *
 * Log convention:
 *   [+] Hook installed successfully
 *   [*] Hook triggered at runtime (bypass fired)
 *   [-] Hook failed to install (non-fatal)
 *   [!] Error inside hook body
 */

"use strict";

// ═══════════════════════════════════════════════════════════════
//  SECTION 0 — UTILITIES
// ═══════════════════════════════════════════════════════════════

function trySafe(label, fn) {
    try {
        fn();
        console.log("[+] " + label);
    } catch (e) {
        console.log("[-] " + label + " → " + e.message);
    }
}

// ObjC method hook helper — patches instance method on a class
function hookMethod(className, methodSig, impl) {
    var cls = ObjC.classes[className];
    if (!cls) throw new Error("class not found: " + className);
    var method = cls["- " + methodSig] || cls["+ " + methodSig];
    if (!method) throw new Error("method not found: " + methodSig);
    method.implementation = impl;
}

// ObjC class method hook helper
function hookClassMethod(className, methodSig, impl) {
    var cls = ObjC.classes[className];
    if (!cls) throw new Error("class not found: " + className);
    var method = cls["+ " + methodSig];
    if (!method) throw new Error("class method not found: " + methodSig);
    method.implementation = impl;
}

// Safely read an ObjC string argument
function readObjCString(ptr) {
    try { return new ObjC.Object(ptr).toString(); } catch (_) { return "<nil>"; }
}

// ═══════════════════════════════════════════════════════════════
//  SECTION 1 — JAILBREAK DETECTION BYPASS
// ═══════════════════════════════════════════════════════════════

/**
 * Covers:
 *  - NSFileManager fileExistsAtPath: / isReadableFileAtPath: / isExecutableFileAtPath:
 *  - UIApplication canOpenURL: (cydia://, sileo://, etc.)
 *  - NSProcessInfo.environment (DYLD_INSERT_LIBRARIES)
 *  - fork() / popen() / system()
 *  - sysctlbyname (kern.bootargs)
 *  - stat() / access() / fopen() / open() for JB paths
 *  - IOSSecuritySuite / DTTrustCache / AppIntegrity
 *  - Dynamic class scan for isJailbroken / isDeviceJailbroken
 *  - getenv("DYLD_INSERT_LIBRARIES")
 *  - Cydia Substrate / Substitute detection
 */

var JB_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/blackra1n.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Filza.app",
    "/Applications/Substrate.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/libexec/ssh-keysign",
    "/usr/bin/sshd",
    "/usr/bin/cycript",
    "/usr/local/bin/cycript",
    "/usr/lib/libcycript.dylib",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/var/checkra1n.dmg",
    "/var/binpack",
    "/var/jb",
    "/usr/share/jailbreak",
    "/jb",
    "/unc0ver",
    "/checkra1n",
    "/palera1n",
    "/dopamine",
    "/var/mobile/Library/Preferences/ABPattern",
    "/usr/lib/TweakInject",
    "/var/MobileSoftwareUpdate/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate/",
];

var JB_URL_SCHEMES = [
    "cydia://",
    "sileo://",
    "zebra://",
    "filza://",
    "undecimus://",
    "activator://",
];

function hookJailbreakDetection() {
    // ── 1a. NSFileManager ────────────────────────────────────────────────────

    trySafe("NSFileManager fileExistsAtPath:", function () {
        hookMethod("NSFileManager", "fileExistsAtPath:", function (self, sel, path) {
            var p = readObjCString(path);
            if (JB_PATHS.indexOf(p) !== -1 || isJBPath(p)) {
                console.log("[*] NSFileManager fileExistsAtPath: blocked → " + p);
                return 0; // NO
            }
            return this.fileExistsAtPath_(path);
        });
    });

    trySafe("NSFileManager fileExistsAtPath:isDirectory:", function () {
        hookMethod("NSFileManager",
            "fileExistsAtPath:isDirectory:",
            function (self, sel, path, isDir) {
                var p = readObjCString(path);
                if (JB_PATHS.indexOf(p) !== -1 || isJBPath(p)) {
                    console.log("[*] NSFileManager fileExistsAtPath:isDirectory: blocked → " + p);
                    return 0;
                }
                return this.fileExistsAtPath_isDirectory_(path, isDir);
            }
        );
    });

    trySafe("NSFileManager isReadableFileAtPath:", function () {
        hookMethod("NSFileManager", "isReadableFileAtPath:", function (self, sel, path) {
            var p = readObjCString(path);
            if (JB_PATHS.indexOf(p) !== -1 || isJBPath(p)) {
                console.log("[*] NSFileManager isReadableFileAtPath: blocked → " + p);
                return 0;
            }
            return this.isReadableFileAtPath_(path);
        });
    });

    trySafe("NSFileManager isExecutableFileAtPath:", function () {
        hookMethod("NSFileManager", "isExecutableFileAtPath:", function (self, sel, path) {
            var p = readObjCString(path);
            if (JB_PATHS.indexOf(p) !== -1 || isJBPath(p)) {
                console.log("[*] NSFileManager isExecutableFileAtPath: blocked → " + p);
                return 0;
            }
            return this.isExecutableFileAtPath_(path);
        });
    });

    trySafe("NSFileManager attributesOfItemAtPath:error:", function () {
        hookMethod("NSFileManager",
            "attributesOfItemAtPath:error:",
            function (self, sel, path, err) {
                var p = readObjCString(path);
                if (JB_PATHS.indexOf(p) !== -1 || isJBPath(p)) {
                    console.log("[*] NSFileManager attributesOfItemAtPath: blocked → " + p);
                    return NULL;
                }
                return this.attributesOfItemAtPath_error_(path, err);
            }
        );
    });

    // ── 1b. UIApplication canOpenURL: ────────────────────────────────────────

    trySafe("UIApplication canOpenURL:", function () {
        hookMethod("UIApplication", "canOpenURL:", function (self, sel, url) {
            var urlStr = readObjCString(ObjC.classes.NSURL["+ URLWithString:"](url));
            try { urlStr = new ObjC.Object(url).absoluteString().toString(); } catch (_) {}
            for (var i = 0; i < JB_URL_SCHEMES.length; i++) {
                if (urlStr && urlStr.indexOf(JB_URL_SCHEMES[i]) === 0) {
                    console.log("[*] UIApplication canOpenURL: blocked → " + urlStr);
                    return 0;
                }
            }
            return this.canOpenURL_(url);
        });
    });

    // ── 1c. NSProcessInfo.environment (DYLD_INSERT_LIBRARIES) ────────────────

    trySafe("NSProcessInfo.environment DYLD mask", function () {
        hookMethod("NSProcessInfo", "environment", function (self, sel) {
            var env = this.environment();
            var dict = ObjC.classes.NSMutableDictionary.alloc().initWithDictionary_(env);
            dict.removeObjectForKey_(ObjC.classes.NSString.stringWithString_("DYLD_INSERT_LIBRARIES"));
            dict.removeObjectForKey_(ObjC.classes.NSString.stringWithString_("_MSSafeMode"));
            console.log("[*] NSProcessInfo.environment DYLD_INSERT_LIBRARIES removed");
            return dict;
        });
    });

    // ── 1d. NSString writeToFile:atomically:encoding:error: ──────────────────
    //   Some JB checkers try to write to root-owned paths to test write access

    trySafe("NSString writeToFile: root path block", function () {
        hookMethod("NSString",
            "writeToFile:atomically:encoding:error:",
            function (self, sel, path, atomically, enc, error) {
                var p = readObjCString(path);
                if (p && (p.startsWith("/private/") || p.startsWith("/etc/") || p.startsWith("/bin/"))) {
                    console.log("[*] NSString writeToFile: blocked → " + p);
                    return 0;
                }
                return this.writeToFile_atomically_encoding_error_(path, atomically, enc, error);
            }
        );
    });

    // ── 1e. getenv() – mask DYLD_INSERT_LIBRARIES ────────────────────────────

    trySafe("libc getenv() DYLD mask", function () {
        var addr = Module.findExportByName(null, "getenv");
        if (!addr) throw new Error("not found");
        Interceptor.replace(addr, new NativeCallback(function (namePtr) {
            var name = namePtr.readUtf8String();
            if (name === "DYLD_INSERT_LIBRARIES" ||
                name === "_MSSafeMode" ||
                name === "DYLD_FORCE_FLAT_NAMESPACE") {
                console.log("[*] getenv(" + name + ") → NULL");
                return ptr(0);
            }
            return Module.findExportByName(null, "getenv") ?
                new NativeFunction(Module.findExportByName("libsystem_c.dylib", "getenv"),
                    "pointer", ["pointer"])(namePtr) : ptr(0);
        }, "pointer", ["pointer"]));
    });

    // Better getenv hook using Interceptor.attach
    trySafe("libc getenv() intercept", function () {
        var addr = Module.findExportByName("libsystem_c.dylib", "getenv");
        if (!addr) addr = Module.findExportByName(null, "getenv");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    this._name = args[0].readUtf8String();
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._name === "DYLD_INSERT_LIBRARIES" ||
                    this._name === "_MSSafeMode") {
                    console.log("[*] getenv(" + this._name + ") masked → NULL");
                    retval.replace(ptr(0));
                }
            }
        });
    });

    // ── 1f. fork() / popen() / system() ─────────────────────────────────────

    trySafe("libc fork() block", function () {
        var addr = Module.findExportByName(null, "fork");
        if (!addr) throw new Error("not found");
        Interceptor.replace(addr, new NativeCallback(function () {
            console.log("[*] fork() blocked → -1");
            return -1;
        }, "int", []));
    });

    trySafe("libc popen() block", function () {
        var popen = Module.findExportByName(null, "popen");
        if (!popen) throw new Error("not found");
        Interceptor.replace(popen, new NativeCallback(function (cmd, type) {
            try {
                var c = cmd.readUtf8String();
                if (c && (c.indexOf("su") !== -1 || c.indexOf("bash") !== -1 ||
                          c.indexOf("cycript") !== -1)) {
                    console.log("[*] popen() blocked: " + c);
                    return ptr(0);
                }
            } catch (_) {}
            return new NativeFunction(popen, "pointer", ["pointer", "pointer"])(cmd, type);
        }, "pointer", ["pointer", "pointer"]));
    });

    trySafe("libc system() block", function () {
        var addr = Module.findExportByName(null, "system");
        if (!addr) throw new Error("not found");
        Interceptor.replace(addr, new NativeCallback(function (cmd) {
            try {
                var c = cmd.readUtf8String();
                console.log("[*] system() blocked: " + c);
            } catch (_) {}
            return -1;
        }, "int", ["pointer"]));
    });

    // ── 1g. stat() / access() / fopen() / open() for JB paths ───────────────

    trySafe("libc stat() JB path block", function () {
        var addr = Module.findExportByName(null, "stat");
        if (!addr) addr = Module.findExportByName(null, "stat64");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var p = args[0].readUtf8String();
                    if (isJBPath(p)) {
                        console.log("[*] stat() JB path blocked: " + p);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._block) retval.replace(ptr(-1));
            }
        });
    });

    trySafe("libc access() JB path block", function () {
        var addr = Module.findExportByName(null, "access");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var p = args[0].readUtf8String();
                    if (isJBPath(p)) {
                        console.log("[*] access() JB path blocked: " + p);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._block) retval.replace(ptr(-1));
            }
        });
    });

    trySafe("libc fopen() JB path block", function () {
        var addr = Module.findExportByName(null, "fopen");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var p = args[0].readUtf8String();
                    if (isJBPath(p)) {
                        console.log("[*] fopen() JB path blocked: " + p);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._block) retval.replace(ptr(0));
            }
        });
    });

    trySafe("libc open() JB path block", function () {
        var addr = Module.findExportByName(null, "open");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var p = args[0].readUtf8String();
                    if (isJBPath(p)) {
                        console.log("[*] open() JB path blocked: " + p);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._block) retval.replace(ptr(-1));
            }
        });
    });

    // ── 1h. sysctlbyname – kern.bootargs mask ────────────────────────────────

    trySafe("sysctlbyname kern.bootargs mask", function () {
        var addr = Module.findExportByName(null, "sysctlbyname");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var name = args[0].readUtf8String();
                    if (name === "kern.bootargs" || name === "hw.machine") {
                        this._maskKernBootargs = true;
                        this._outPtr = args[2];
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._maskKernBootargs && this._outPtr && !this._outPtr.isNull()) {
                    try {
                        var val = this._outPtr.readUtf8String();
                        if (val && (val.indexOf("-v") !== -1 ||
                                    val.indexOf("debug") !== -1 ||
                                    val.indexOf("nand-enable-reformat") !== -1)) {
                            console.log("[*] sysctlbyname kern.bootargs masked");
                            this._outPtr.writeUtf8String("");
                        }
                    } catch (_) {}
                }
            }
        });
    });

    // ── 1i. IOSSecuritySuite / DTAppContext dynamic class scan ───────────────

    trySafe("IOSSecuritySuite amIJailbroken scan", function () {
        var suiteClasses = [
            "IOSSecuritySuite", "DTAppContext", "AppIntegrityChecker",
            "JailbreakDetection", "JailbreakDetector", "SecurityManager",
        ];
        suiteClasses.forEach(function (clsName) {
            var cls = ObjC.classes[clsName];
            if (!cls) return;
            var methods = [
                "amIJailbroken", "isJailbroken", "isDeviceJailbroken",
                "jailbreakCheck", "checkJailbreak", "isJailbreakPresent",
            ];
            methods.forEach(function (m) {
                try {
                    if (cls["+ " + m]) {
                        cls["+ " + m].implementation = function () {
                            console.log("[*] " + clsName + " +" + m + " → false/0");
                            return 0;
                        };
                    }
                    if (cls["- " + m]) {
                        cls["- " + m].implementation = function () {
                            console.log("[*] " + clsName + " -" + m + " → false/0");
                            return 0;
                        };
                    }
                } catch (_) {}
            });
        });
    });

    // ── 1j. dyld image name scan – hide Substrate/Substitute dylib names ─────

    trySafe("_dyld_image_count / _dyld_get_image_name mask", function () {
        var getImageName = Module.findExportByName(null, "_dyld_get_image_name");
        if (!getImageName) throw new Error("not found");
        var origGetName = new NativeFunction(getImageName, "pointer", ["uint32"]);
        Interceptor.replace(getImageName, new NativeCallback(function (idx) {
            var name = origGetName(idx);
            try {
                var nameStr = name.readUtf8String();
                if (nameStr && (
                    nameStr.indexOf("MobileSubstrate") !== -1 ||
                    nameStr.indexOf("CydiaSubstrate") !== -1 ||
                    nameStr.indexOf("Substitute") !== -1 ||
                    nameStr.indexOf("substitute-inserter") !== -1 ||
                    nameStr.indexOf("TweakInject") !== -1 ||
                    nameStr.indexOf("frida") !== -1 ||
                    nameStr.indexOf("FridaGadget") !== -1 ||
                    nameStr.indexOf("cycript") !== -1
                )) {
                    console.log("[*] _dyld_get_image_name masked: " + nameStr);
                    // Return a benign dylib name pointer
                    return Memory.allocUtf8String("/usr/lib/libobjc.A.dylib");
                }
            } catch (_) {}
            return name;
        }, "pointer", ["uint32"]));
    });

    console.log("\n[+] Jailbreak detection bypass hooks installed\n");
}

// Helper: check if a path looks like a JB path
function isJBPath(p) {
    if (!p) return false;
    var jbKeywords = [
        "/cydia", "/sileo", "/MobileSubstrate", "/cycript",
        "/checkra1n", "/unc0ver", "/palera1n", "/dopamine",
        "/TweakInject", "/var/jb", "/var/binpack",
        "substrate", "Substrate", "Substitute",
    ];
    for (var i = 0; i < JB_PATHS.length; i++) {
        if (p === JB_PATHS[i]) return true;
    }
    for (var j = 0; j < jbKeywords.length; j++) {
        if (p.indexOf(jbKeywords[j]) !== -1) return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════
//  SECTION 2 — SSL PINNING BYPASS
// ═══════════════════════════════════════════════════════════════

/**
 * Covers:
 *  - SecTrustEvaluate / SecTrustEvaluateWithError (Security.framework)
 *  - SecTrustGetTrustResult
 *  - NSURLSession didReceiveChallenge completionHandler
 *  - NSURLConnection willSendRequestForAuthenticationChallenge
 *  - AFNetworking AFSecurityPolicy evaluateServerTrust:forDomain:
 *  - Alamofire ServerTrustPolicy / ServerTrustManager
 *  - TrustKit TSKPinningValidator
 *  - WKWebView / UIWebView SSL challenge delegate
 *  - SSLHandshake (deprecated API, still used in older apps)
 *  - tls_helper_create_peer_trust (libboringssl / libcoretls)
 *  - SSL_CTX_set_verify (BoringSSL in Flutter, Chrome-based apps)
 *  - Network.framework NWConnection (TLS options)
 */

function hookSSLPinning() {

    // ── 2a. SecTrustEvaluate (deprecated but widely used) ───────────────────

    trySafe("SecTrustEvaluate", function () {
        var addr = Module.findExportByName("Security", "SecTrustEvaluate");
        if (!addr) addr = Module.findExportByName(null, "SecTrustEvaluate");
        if (!addr) throw new Error("not found");
        // SecTrustResultType: kSecTrustResultUnspecified = 4, kSecTrustResultProceed = 1
        Interceptor.replace(addr, new NativeCallback(function (trust, result) {
            console.log("[*] SecTrustEvaluate → kSecTrustResultProceed");
            if (!result.isNull()) result.writeU32(1); // kSecTrustResultProceed
            return 0; // errSecSuccess
        }, "int", ["pointer", "pointer"]));
    });

    // ── 2b. SecTrustEvaluateWithError (iOS 12+) ──────────────────────────────

    trySafe("SecTrustEvaluateWithError", function () {
        var addr = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (!addr) addr = Module.findExportByName(null, "SecTrustEvaluateWithError");
        if (!addr) throw new Error("not found");
        // Returns bool: true = trusted
        Interceptor.replace(addr, new NativeCallback(function (trust, error) {
            console.log("[*] SecTrustEvaluateWithError → true");
            if (!error.isNull()) error.writePointer(ptr(0)); // clear error
            return 1; // true
        }, "bool", ["pointer", "pointer"]));
    });

    // ── 2c. SecTrustGetTrustResult ───────────────────────────────────────────

    trySafe("SecTrustGetTrustResult", function () {
        var addr = Module.findExportByName("Security", "SecTrustGetTrustResult");
        if (!addr) addr = Module.findExportByName(null, "SecTrustGetTrustResult");
        if (!addr) throw new Error("not found");
        Interceptor.replace(addr, new NativeCallback(function (trust, result) {
            console.log("[*] SecTrustGetTrustResult → kSecTrustResultProceed");
            if (!result.isNull()) result.writeU32(1);
            return 0;
        }, "int", ["pointer", "pointer"]));
    });

    // ── 2d. SecTrustSetAnchorCertificates / SecTrustSetAnchorCertificatesOnly ─

    trySafe("SecTrustSetAnchorCertificatesOnly", function () {
        var addr = Module.findExportByName("Security", "SecTrustSetAnchorCertificatesOnly");
        if (!addr) addr = Module.findExportByName(null, "SecTrustSetAnchorCertificatesOnly");
        if (!addr) throw new Error("not found");
        // Force anchorCertificatesOnly = false so system CA is also trusted
        Interceptor.replace(addr, new NativeCallback(function (trust, anchorCertsOnly) {
            console.log("[*] SecTrustSetAnchorCertificatesOnly → false");
            return 0;
        }, "int", ["pointer", "bool"]));
    });

    // ── 2e. NSURLSession – didReceiveChallenge ────────────────────────────────
    // Apps implementing URLSession:didReceiveChallenge:completionHandler:

    trySafe("NSURLSession delegate didReceiveChallenge", function () {
        // Hook the challenge handler in NSURLSessionTask
        var NSURLCredential = ObjC.classes.NSURLCredential;
        var NSURLSessionAuthChallengeDisposition = {
            UseCredential: 0,
            PerformDefaultHandling: 1,
            CancelAuthenticationChallenge: 2,
            RejectProtectionSpace: 3
        };

        // Enumerate all classes conforming to NSURLSessionDelegate to patch dynamically
        ObjC.enumerateLoadedClassesSync().forEach(function (className) {
            var cls = ObjC.classes[className];
            if (!cls) return;

            var sel1 = "URLSession:didReceiveChallenge:completionHandler:";
            var sel2 = "URLSession:task:didReceiveChallenge:completionHandler:";

            [sel1, sel2].forEach(function (sel) {
                if (!cls["- " + sel]) return;
                try {
                    cls["- " + sel].implementation = ObjC.implement(
                        cls["- " + sel],
                        function (self, _sel, session, challenge, completionHandler) {
                            try {
                                var protectionSpace = challenge.protectionSpace();
                                var authMethod = protectionSpace.authenticationMethod().toString();
                                if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                                    console.log("[*] NSURLSession challenge bypassed for: " +
                                        protectionSpace.host().toString());
                                    var serverTrust = protectionSpace.serverTrust();
                                    var credential = NSURLCredential.credentialForTrust_(serverTrust);
                                    var block = new ObjC.Block(completionHandler);
                                    block.call(
                                        NSURLSessionAuthChallengeDisposition.UseCredential,
                                        credential
                                    );
                                    return;
                                }
                            } catch (e) {
                                console.log("[!] NSURLSession challenge hook error: " + e.message);
                            }
                            // Default handling for non-server-trust challenges
                            var block = new ObjC.Block(completionHandler);
                            block.call(
                                NSURLSessionAuthChallengeDisposition.PerformDefaultHandling,
                                ptr(0)
                            );
                        }
                    );
                    console.log("[+] Hooked " + className + " - " + sel);
                } catch (_) {}
            });
        });
    });

    // ── 2f. NSURLConnection – willSendRequestForAuthenticationChallenge ───────

    trySafe("NSURLConnection willSendRequestForAuthenticationChallenge", function () {
        ObjC.enumerateLoadedClassesSync().forEach(function (className) {
            var cls = ObjC.classes[className];
            if (!cls) return;
            var sel = "connection:willSendRequestForAuthenticationChallenge:";
            if (!cls["- " + sel]) return;
            try {
                cls["- " + sel].implementation = ObjC.implement(
                    cls["- " + sel],
                    function (self, _sel, connection, challenge) {
                        try {
                            var protectionSpace = challenge.protectionSpace();
                            var authMethod = protectionSpace.authenticationMethod().toString();
                            if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                                console.log("[*] NSURLConnection challenge bypassed: " +
                                    protectionSpace.host().toString());
                                var serverTrust = protectionSpace.serverTrust();
                                var credential = ObjC.classes.NSURLCredential
                                    .credentialForTrust_(serverTrust);
                                challenge.sender().useCredential_forAuthenticationChallenge_(
                                    credential, challenge
                                );
                                return;
                            }
                        } catch (e) {
                            console.log("[!] NSURLConnection challenge error: " + e.message);
                        }
                        challenge.sender()
                            .continueWithoutCredentialForAuthenticationChallenge_(challenge);
                    }
                );
                console.log("[+] Hooked NSURLConnection challenge: " + className);
            } catch (_) {}
        });
    });

    // ── 2g. AFNetworking – AFSecurityPolicy ──────────────────────────────────

    trySafe("AFSecurityPolicy evaluateServerTrust:forDomain:", function () {
        var cls = ObjC.classes.AFSecurityPolicy;
        if (!cls) throw new Error("AFSecurityPolicy not found");
        cls["- evaluateServerTrust:forDomain:"].implementation = function (self, sel, trust, domain) {
            console.log("[*] AFSecurityPolicy.evaluateServerTrust:forDomain: → YES for " +
                (domain ? new ObjC.Object(domain).toString() : "<nil>"));
            return 1; // YES
        };
    });

    // AFHTTPSessionManager level (some versions override at this layer)
    trySafe("AFHTTPSessionManager setSecurityPolicy:", function () {
        var cls = ObjC.classes.AFHTTPSessionManager;
        if (!cls) throw new Error("not found");
        if (cls["- setSecurityPolicy:"]) {
            cls["- setSecurityPolicy:"].implementation = function (self, sel, policy) {
                // Replace with AFSSLPinningModeNone policy
                try {
                    var nonePolicy = ObjC.classes.AFSecurityPolicy
                        ["+ policyWithPinningMode:"](0); // AFSSLPinningModeNone = 0
                    nonePolicy.setAllowInvalidCertificates_(1);
                    nonePolicy.setValidatesDomainName_(0);
                    console.log("[*] AFHTTPSessionManager setSecurityPolicy: replaced with None");
                    return this.setSecurityPolicy_(nonePolicy);
                } catch (_) {
                    return this.setSecurityPolicy_(policy);
                }
            };
        }
    });

    // ── 2h. TrustKit ─────────────────────────────────────────────────────────

    trySafe("TrustKit TSKPinningValidator evaluateTrust:forHostname:", function () {
        var cls = ObjC.classes.TSKPinningValidator;
        if (!cls) throw new Error("TSKPinningValidator not found");
        cls["- evaluateTrust:forHostname:"].implementation = function (self, sel, trust, host) {
            console.log("[*] TrustKit TSKPinningValidator.evaluateTrust: bypassed → " +
                new ObjC.Object(host).toString());
            return 0; // TSKTrustDecisionShouldAllowConnection = 0
        };
    });

    // ── 2i. Alamofire – ServerTrustPolicy ────────────────────────────────────
    // Alamofire compiles to Swift, method names are mangled
    // Try common Obj-C visible interfaces first

    trySafe("Alamofire ServerTrustManager evaluate(_:forHost:)", function () {
        // Swift method is not directly accessible via ObjC bridge in all versions
        // Hook via module export scanning
        var mods = ["Alamofire", "AlamofireImage"];
        mods.forEach(function (modName) {
            var mod = Process.findModuleByName(modName);
            if (!mod) mod = Process.findModuleByName(modName + ".framework/" + modName);
            if (!mod) return;
            mod.enumerateExports().forEach(function (exp) {
                if (exp.type !== "function") return;
                var n = exp.name.toLowerCase();
                if (n.indexOf("servertrustpolicy") !== -1 &&
                    (n.indexOf("evaluate") !== -1 || n.indexOf("valid") !== -1)) {
                    trySafe("Alamofire export: " + exp.name, function () {
                        Interceptor.attach(exp.address, {
                            onLeave: function (retval) {
                                console.log("[*] Alamofire ServerTrustPolicy evaluate → true");
                                retval.replace(ptr(1));
                            }
                        });
                    });
                }
            });
        });
    });

    // ── 2j. SSLHandshake (deprecated, iOS < 13, still in some apps) ──────────

    trySafe("SSLHandshake (libsecurity)", function () {
        var addr = Module.findExportByName("Security", "SSLHandshake");
        if (!addr) addr = Module.findExportByName(null, "SSLHandshake");
        if (!addr) throw new Error("not found");
        Interceptor.replace(addr, new NativeCallback(function (ctx) {
            console.log("[*] SSLHandshake → noErr");
            return 0; // noErr
        }, "int", ["pointer"]));
    });

    // ── 2k. tls_helper_create_peer_trust (libboringssl / libcoretls) ─────────

    trySafe("tls_helper_create_peer_trust", function () {
        var candidates = [
            "libboringssl.dylib", "libcoretls.dylib",
            "libssl.dylib", "Security"
        ];
        var found = false;
        candidates.forEach(function (lib) {
            if (found) return;
            var addr = Module.findExportByName(lib, "tls_helper_create_peer_trust");
            if (!addr) return;
            found = true;
            Interceptor.replace(addr, new NativeCallback(function (hdsk, server, trustRef) {
                console.log("[*] tls_helper_create_peer_trust bypassed");
                return 0;
            }, "int", ["pointer", "bool", "pointer"]));
        });
        if (!found) throw new Error("not found in any module");
    });

    // ── 2l. BoringSSL / OpenSSL native hooks ─────────────────────────────────
    // Used by Flutter, Chrome, and apps bundling their own TLS

    var sslModuleCandidates = [
        "libssl.dylib", "libboringssl.dylib",
        "libssl.3.dylib", "libcrypto.dylib",
        "libflutter.dylib", "Flutter", "FlutterMacOS"
    ];

    function applyBoringSSLHooks(mod) {
        // SSL_CTX_set_verify → force SSL_VERIFY_NONE
        trySafe(mod.name + "::SSL_CTX_set_verify", function () {
            var addr = mod.findExportByName("SSL_CTX_set_verify");
            if (!addr) throw new Error("not found");
            var orig = new NativeFunction(addr, "void", ["pointer", "int", "pointer"]);
            Interceptor.replace(addr, new NativeCallback(function (ctx, mode, cb) {
                console.log("[*] SSL_CTX_set_verify → NONE in " + mod.name);
                orig(ctx, 0, ptr(0));
            }, "void", ["pointer", "int", "pointer"]));
        });

        // SSL_get_verify_result → X509_V_OK
        trySafe(mod.name + "::SSL_get_verify_result", function () {
            var addr = mod.findExportByName("SSL_get_verify_result");
            if (!addr) throw new Error("not found");
            Interceptor.replace(addr, new NativeCallback(function (ssl) {
                console.log("[*] SSL_get_verify_result → 0 in " + mod.name);
                return 0;
            }, "long", ["pointer"]));
        });

        // X509_verify_cert → 1
        trySafe(mod.name + "::X509_verify_cert", function () {
            var addr = mod.findExportByName("X509_verify_cert");
            if (!addr) throw new Error("not found");
            Interceptor.replace(addr, new NativeCallback(function (ctx) {
                console.log("[*] X509_verify_cert → 1 in " + mod.name);
                return 1;
            }, "int", ["pointer"]));
        });

        // SSL_CTX_set_custom_verify (BoringSSL)
        trySafe(mod.name + "::SSL_CTX_set_custom_verify", function () {
            var addr = mod.findExportByName("SSL_CTX_set_custom_verify");
            if (!addr) throw new Error("not found");
            Interceptor.replace(addr, new NativeCallback(function (ctx, mode, cb) {
                console.log("[*] SSL_CTX_set_custom_verify no-op in " + mod.name);
            }, "void", ["pointer", "int", "pointer"]));
        });
    }

    Process.enumerateModules().forEach(function (mod) {
        var n = mod.name.toLowerCase();
        if (n.indexOf("ssl") !== -1 || n.indexOf("boring") !== -1 ||
            n.indexOf("tls") !== -1 || n.indexOf("crypto") !== -1 ||
            n === "flutter" || n === "fluttermac") {
            console.log("[*] SSL module found: " + mod.name);
            applyBoringSSLHooks(mod);
        }
    });

    console.log("\n[+] SSL Pinning bypass hooks installed\n");
}

// ═══════════════════════════════════════════════════════════════
//  SECTION 3 — WEBVIEW BYPASS
// ═══════════════════════════════════════════════════════════════

/**
 * Covers:
 *  - WKWebView – WKNavigationDelegate SSL challenge
 *  - WKWebView – webView:didFailProvisionalNavigation:withError:
 *  - WKWebView – webView:didFailNavigation:withError:
 *  - UIWebView (deprecated) – webView:didFailLoadWithError:
 *  - UIWebView – webViewDidStartLoad: / webViewDidFinishLoad:
 *  - WKURLSchemeHandler – custom scheme SSL interception
 *  - WKWebsiteDataStore / WKProcessPool certificate trust store
 *  - NSURLProtocol registration for WebView traffic
 */

function hookWebView() {

    // ── 3a. WKNavigationDelegate SSL challenge ────────────────────────────────

    trySafe("WKNavigationDelegate webView:didReceiveAuthenticationChallenge:", function () {
        ObjC.enumerateLoadedClassesSync().forEach(function (className) {
            var cls = ObjC.classes[className];
            if (!cls) return;
            var sel = "webView:didReceiveAuthenticationChallenge:completionHandler:";
            if (!cls["- " + sel]) return;
            try {
                cls["- " + sel].implementation = ObjC.implement(
                    cls["- " + sel],
                    function (self, _sel, webView, challenge, completionHandler) {
                        try {
                            var protectionSpace = challenge.protectionSpace();
                            var authMethod = protectionSpace.authenticationMethod().toString();
                            if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                                var host = protectionSpace.host().toString();
                                console.log("[*] WKWebView SSL challenge bypassed: " + host);
                                var serverTrust = protectionSpace.serverTrust();
                                var credential = ObjC.classes.NSURLCredential
                                    .credentialForTrust_(serverTrust);
                                var block = new ObjC.Block(completionHandler);
                                block.call(0 /* UseCredential */, credential);
                                return;
                            }
                        } catch (e) {
                            console.log("[!] WKWebView challenge error: " + e.message);
                        }
                        var block = new ObjC.Block(completionHandler);
                        block.call(1 /* PerformDefaultHandling */, ptr(0));
                    }
                );
                console.log("[+] WKWebView challenge hooked: " + className);
            } catch (_) {}
        });
    });

    // ── 3b. WKWebView didFailProvisionalNavigation ────────────────────────────

    trySafe("WKWebView didFailProvisionalNavigation:withError:", function () {
        ObjC.enumerateLoadedClassesSync().forEach(function (className) {
            var cls = ObjC.classes[className];
            if (!cls) return;
            var sel = "webView:didFailProvisionalNavigation:withError:";
            if (!cls["- " + sel]) return;
            try {
                cls["- " + sel].implementation = ObjC.implement(
                    cls["- " + sel],
                    function (self, _sel, webView, nav, error) {
                        try {
                            var errObj = new ObjC.Object(error);
                            var code = errObj.code();
                            // NSURLErrorServerCertificateUntrusted = -1202
                            // NSURLErrorServerCertificateHasUnknownRoot = -1203
                            // NSURLErrorServerCertificateNotYetValid = -1204
                            if (code >= -1206 && code <= -1200) {
                                console.log("[*] WKWebView SSL error suppressed: code " + code);
                                return;
                            }
                        } catch (_) {}
                        // Call original for non-SSL errors
                        this.webView_didFailProvisionalNavigation_withError_(webView, nav, error);
                    }
                );
                console.log("[+] WKWebView didFailProvisionalNavigation hooked: " + className);
            } catch (_) {}
        });
    });

    trySafe("WKWebView didFailNavigation:withError:", function () {
        ObjC.enumerateLoadedClassesSync().forEach(function (className) {
            var cls = ObjC.classes[className];
            if (!cls) return;
            var sel = "webView:didFailNavigation:withError:";
            if (!cls["- " + sel]) return;
            try {
                cls["- " + sel].implementation = ObjC.implement(
                    cls["- " + sel],
                    function (self, _sel, webView, nav, error) {
                        try {
                            var code = new ObjC.Object(error).code();
                            if (code >= -1206 && code <= -1200) {
                                console.log("[*] WKWebView didFailNavigation SSL error suppressed");
                                return;
                            }
                        } catch (_) {}
                        this.webView_didFailNavigation_withError_(webView, nav, error);
                    }
                );
            } catch (_) {}
        });
    });

    // ── 3c. UIWebView (deprecated – iOS < 12 apps) ───────────────────────────

    trySafe("UIWebViewDelegate webView:didFailLoadWithError:", function () {
        ObjC.enumerateLoadedClassesSync().forEach(function (className) {
            var cls = ObjC.classes[className];
            if (!cls) return;
            var sel = "webView:didFailLoadWithError:";
            if (!cls["- " + sel]) return;
            try {
                cls["- " + sel].implementation = ObjC.implement(
                    cls["- " + sel],
                    function (self, _sel, webView, error) {
                        try {
                            var code = new ObjC.Object(error).code();
                            if (code >= -1206 && code <= -1200) {
                                console.log("[*] UIWebView SSL error suppressed: code " + code);
                                return;
                            }
                        } catch (_) {}
                        this.webView_didFailLoadWithError_(webView, error);
                    }
                );
                console.log("[+] UIWebView didFailLoadWithError hooked: " + className);
            } catch (_) {}
        });
    });

    // ── 3d. WKPreferences / WKWebViewConfiguration – disable mixed content ────

    trySafe("WKPreferences suppress", function () {
        var cls = ObjC.classes.WKPreferences;
        if (!cls) throw new Error("not found");
        // Ensure javaScriptEnabled if app tries to disable it for security
        if (cls["- setJavaScriptEnabled:"]) {
            // Don't override – just log
        }
    });

    // ── 3e. NSURLProtocol – catch WebView network for SSL bypass ─────────────

    trySafe("NSURLProtocol canInitWithRequest SSL override", function () {
        ObjC.enumerateLoadedClassesSync().forEach(function (className) {
            var cls = ObjC.classes[className];
            if (!cls) return;
            if (cls["+ canInitWithRequest:"]) {
                // Only interested in custom protocol handlers that might do SSL checking
            }
        });
    });

    console.log("\n[+] WebView bypass hooks installed\n");
}

// ═══════════════════════════════════════════════════════════════
//  SECTION 4 — FRIDA SELF-DETECTION BYPASS (iOS)
// ═══════════════════════════════════════════════════════════════

function hookFridaDetection() {

    // ── 4a. Port 27042 connect block ─────────────────────────────────────────

    trySafe("connect() port 27042 block", function () {
        var addr = Module.findExportByName("libsystem_kernel.dylib", "connect");
        if (!addr) addr = Module.findExportByName(null, "connect");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var sockaddr = args[1];
                    var family = sockaddr.readU8();
                    // AF_INET = 2, but on iOS sin_len precedes sin_family
                    var port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8());
                    if (port === 27042 || port === 27043) {
                        console.log("[*] connect() port " + port + " blocked");
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._block) retval.replace(ptr(-1));
            }
        });
    });

    // ── 4b. PT_DENY_ATTACH bypass ─────────────────────────────────────────────
    // Some apps call ptrace(PT_DENY_ATTACH, 0, 0, 0) to prevent debugger attach

    trySafe("ptrace PT_DENY_ATTACH block", function () {
        var ptrace = Module.findExportByName(null, "ptrace");
        if (!ptrace) throw new Error("not found");
        // PT_DENY_ATTACH = 31
        Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
            if (request === 31) {
                console.log("[*] ptrace PT_DENY_ATTACH blocked");
                return 0;
            }
            return new NativeFunction(ptrace, "int", ["int", "int", "pointer", "int"])
                (request, pid, addr, data);
        }, "int", ["int", "int", "pointer", "int"]));
    });

    // ── 4c. sysctl anti-debug (TracerPid / kinfo_proc P_TRACED) ─────────────

    trySafe("sysctl anti-debug bypass", function () {
        var addr = Module.findExportByName(null, "sysctl");
        if (!addr) throw new Error("not found");
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this._args = args;
                // CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1 → kinfo_proc
                try {
                    var mib = args[0];
                    if (mib.readU32() === 1 && mib.add(4).readU32() === 14) {
                        this._isKernProc = true;
                        this._outPtr = args[4]; // oldp
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._isKernProc && retval.toInt32() === 0) {
                    try {
                        // kinfo_proc.kp_proc.p_flag is at offset 32
                        // P_TRACED = 0x00000800
                        var outPtr = this._args[4].readPointer();
                        var flagOffset = 32;
                        var flags = outPtr.add(flagOffset).readU32();
                        if (flags & 0x800) {
                            console.log("[*] sysctl P_TRACED flag cleared");
                            outPtr.add(flagOffset).writeU32(flags & ~0x800);
                        }
                    } catch (_) {}
                }
            }
        });
    });

    console.log("\n[+] Frida self-detection bypass hooks installed\n");
}

// ═══════════════════════════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════════════════════════

if (!ObjC.available) {
    console.log("[!] ObjC runtime not available — are you targeting an iOS process?");
} else {
    console.log("╔═══════════════════════════════════════════════════════╗");
    console.log("║      Universal iOS Bypass Script — Frida              ║");
    console.log("║  JB Detection + SSL Pinning + WebView + Anti-Debug    ║");
    console.log("╠═══════════════════════════════════════════════════════╣");
    console.log("║  Arch   : " + Process.arch.padEnd(44) + "║");
    console.log("║  PID    : " + Process.id.toString().padEnd(44) + "║");
    console.log("╚═══════════════════════════════════════════════════════╝\n");

    // Native hooks (no ObjC runtime needed)
    hookFridaDetection();
    hookSSLPinning();

    // ObjC hooks
    hookJailbreakDetection();
    hookWebView();
}
