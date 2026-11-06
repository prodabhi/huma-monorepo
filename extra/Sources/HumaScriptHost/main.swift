import CryptoKit
import Darwin
import Foundation
import JavaScriptCore

// Runs the proof engine's worker (backend/integrations/noir/worker.mjs, bundled into one worker.js) on macOS's own
// JavaScriptCore, in place of a bundled Node.js (about 116 MB). Like `node worker.mjs`: the request arrives on stdin
// and the answer leaves on stdout. The script gets only what the engine uses, through __host: its own files, starting
// bb, SHA-256 and P-256 signature checks. Every call happens on the main thread; finished child processes and timers
// come back to it, and JavaScriptCore runs promise jobs as each call returns.
//
// Usage: HumaScriptHost <engine>/worker.js

umask(0o077)
signal(SIGPIPE, SIG_IGN)
guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("Usage: HumaScriptHost <worker.js>\n".utf8)); exit(64)
}
let script = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
let engine = script.deletingLastPathComponent()
guard let source = try? String(contentsOf: script, encoding: .utf8) else {
    FileHandle.standardError.write(Data("The engine script is missing.\n".utf8)); exit(66)
}
// The worker rejects requests over 64 MB; reading one byte more lets it say so.
let request = FileHandle.standardInput.readData(ofLength: 64 * 1024 * 1024 + 1)

let context = JSContext()!
func finish(_ code: Int32) -> Never { exit(code) }
context.exceptionHandler = { _, _ in
    // An exception nothing in the script caught. Never print it: it could quote private input.
    FileHandle.standardError.write(Data("The engine stopped unexpectedly.\n".utf8))
    finish(1)
}

// MARK: Bytes between Swift and JavaScript

func bytes(_ value: JSValue) -> Data? {
    let ctx = context.jsGlobalContextRef, ref = value.jsValueRef
    var exception: JSValueRef?
    guard JSValueGetTypedArrayType(ctx, ref, &exception) == kJSTypedArrayTypeUint8Array,
          let object = JSValueToObject(ctx, ref, &exception) else { return nil }
    // The script only passes arrays that start at the beginning of their own buffer (prelude.mjs, copy).
    let length = JSObjectGetTypedArrayByteLength(ctx, object, &exception)
    guard length > 0, let pointer = JSObjectGetTypedArrayBytesPtr(ctx, object, &exception) else { return Data() }
    return Data(bytes: pointer, count: length)
}
func array(_ data: Data) -> JSValue {
    let ctx = context.jsGlobalContextRef
    var exception: JSValueRef?
    let object = JSObjectMakeTypedArray(ctx, kJSTypedArrayTypeUint8Array, data.count, &exception)!
    if !data.isEmpty, let pointer = JSObjectGetTypedArrayBytesPtr(ctx, object, &exception) {
        data.copyBytes(to: pointer.assumingMemoryBound(to: UInt8.self), count: data.count)
    }
    return JSValue(jsValueRef: object, in: context)
}

/// Throws a JavaScript Error with a Node-style code (ENOENT, EEXIST, …) from inside a host call.
@discardableResult func fail(_ number: Int32 = errno) -> JSValue {
    let codes: [Int32: String] = [ENOENT: "ENOENT", EEXIST: "EEXIST", EACCES: "EACCES", EPERM: "EPERM", ENOTDIR: "ENOTDIR",
                                  EISDIR: "EISDIR", ENOTEMPTY: "ENOTEMPTY", EINVAL: "EINVAL", ELOOP: "ELOOP"]
    let code = codes[number] ?? "EIO"
    let error = JSValue(newErrorFromMessage: code, in: context)!
    error.setValue(code, forProperty: "code")
    context.exception = error
    return JSValue(undefinedIn: context)
}
func fail(message: String) -> JSValue {
    context.exception = JSValue(newErrorFromMessage: message, in: context)
    return JSValue(undefinedIn: context)
}

// MARK: The host object

let host = JSValue(newObjectIn: context)!
func define(_ name: String, _ block: Any) { host.setValue(block, forProperty: name) }

define("readFile", { (path: String) -> JSValue in
    let fd = open(path, O_RDONLY | O_CLOEXEC)
    guard fd >= 0 else { return fail() }
    defer { close(fd) }
    var data = Data(), buffer = [UInt8](repeating: 0, count: 1 << 20)
    while true {
        let count = read(fd, &buffer, buffer.count)
        if count < 0 { return fail() }
        if count == 0 { return array(data) }
        data.append(buffer, count: count)
    }
} as @convention(block) (String) -> JSValue)

define("writeFile", { (path: String, value: JSValue, exclusive: Bool, mode: Int32) -> JSValue in
    guard let data = bytes(value) else { return fail(EINVAL) }
    let fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | (exclusive ? O_EXCL : O_TRUNC), mode_t(mode))
    guard fd >= 0 else { return fail() }
    defer { close(fd) }
    var written = 0
    let failed = data.withUnsafeBytes { raw -> Bool in
        while written < raw.count {
            let count = write(fd, raw.baseAddress! + written, raw.count - written)
            if count <= 0 { return true }
            written += count
        }
        return false
    }
    return failed ? fail() : JSValue(undefinedIn: context)
} as @convention(block) (String, JSValue, Bool, Int32) -> JSValue)

define("lstat", { (path: String) -> JSValue in
    var info = stat()
    guard lstat(path, &info) == 0 else { return fail() }
    let kind: String
    switch info.st_mode & S_IFMT {
    case S_IFREG: kind = "file"
    case S_IFDIR: kind = "directory"
    case S_IFLNK: kind = "link"
    default: kind = "other"
    }
    return JSValue(object: ["type": kind, "size": Double(info.st_size), "uid": Double(info.st_uid), "mode": Double(info.st_mode & 0o7777)],
                   in: context)
} as @convention(block) (String) -> JSValue)

define("readdir", { (path: String) -> JSValue in
    guard let names = try? FileManager.default.contentsOfDirectory(atPath: path) else {
        var info = stat(); return fail(lstat(path, &info) == 0 ? ENOTDIR : ENOENT)
    }
    return JSValue(object: names.sorted(), in: context)
} as @convention(block) (String) -> JSValue)

define("mkdir", { (path: String, recursive: Bool, mode: Int32) -> JSValue in
    if recursive {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) { return isDirectory.boolValue ? JSValue(undefinedIn: context) : fail(EEXIST) }
        do { try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: mode]) }
        catch { return fail(EACCES) }
        return JSValue(undefinedIn: context)
    }
    return mkdir(path, mode_t(mode)) == 0 ? JSValue(undefinedIn: context) : fail()
} as @convention(block) (String, Bool, Int32) -> JSValue)

define("symlink", { (target: String, path: String) -> JSValue in
    symlink(target, path) == 0 ? JSValue(undefinedIn: context) : fail()
} as @convention(block) (String, String) -> JSValue)

define("readlink", { (path: String) -> JSValue in
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
    let count = readlink(path, &buffer, buffer.count - 1)
    guard count >= 0 else { return fail() }
    return JSValue(object: String(decoding: buffer[0..<count].map { UInt8(bitPattern: $0) }, as: UTF8.self), in: context)
} as @convention(block) (String) -> JSValue)

define("unlink", { (path: String) -> JSValue in
    unlink(path) == 0 ? JSValue(undefinedIn: context) : fail()
} as @convention(block) (String) -> JSValue)

// Starts a tool (bb, capture-input), writes its input, collects its output, and calls back on the main thread with
// (failedToStart, exitCode, signalName, output). Its diagnostics are discarded, as the worker asks.
define("spawn", { (path: String, arguments: [String], environment: [String: Any], input: JSValue, callback: JSValue) -> JSValue in
    guard let data = bytes(input) else { return fail(EINVAL) }
    let process = Process(), stdin = Pipe(), stdout = Pipe()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.environment = environment.compactMapValues { $0 as? String }
    process.standardInput = stdin; process.standardOutput = stdout; process.standardError = FileHandle.nullDevice
    let output = DispatchGroup(), collected = NSMutableData()
    output.enter()
    DispatchQueue.global().async {
        collected.append(stdout.fileHandleForReading.readDataToEndOfFile()); output.leave()
    }
    process.terminationHandler = { finished in
        output.notify(queue: .main) {
            let signal = finished.terminationReason == .uncaughtSignal ? "SIG\(finished.terminationStatus)" : ""
            callback.call(withArguments: [false, finished.terminationReason == .exit ? finished.terminationStatus : 0, signal,
                                          array(collected as Data)])
        }
    }
    do { try process.run() } catch {
        try? stdout.fileHandleForWriting.close()
        DispatchQueue.main.async { callback.call(withArguments: [true, 0, "", array(Data())]) }
        return JSValue(undefinedIn: context)
    }
    try? stdout.fileHandleForWriting.close()
    DispatchQueue.global().async {
        try? stdin.fileHandleForWriting.write(contentsOf: data)
        try? stdin.fileHandleForWriting.close()
    }
    return JSValue(undefinedIn: context)
} as @convention(block) (String, [String], [String: Any], JSValue, JSValue) -> JSValue)

define("sha256", { (value: JSValue) -> JSValue in
    guard let data = bytes(value) else { return fail(EINVAL) }
    return array(Data(SHA256.hash(data: data)))
} as @convention(block) (JSValue) -> JSValue)

define("p256Verify", { (key: JSValue, signature: JSValue, message: JSValue) -> Bool in
    guard let key = bytes(key), let signature = bytes(signature), let message = bytes(message),
          let publicKey = try? P256.Signing.PublicKey(x963Representation: key),
          let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
    return publicKey.isValidSignature(parsed, for: message)
} as @convention(block) (JSValue, JSValue, JSValue) -> Bool)

define("validUTF8", { (value: JSValue) -> Bool in
    guard let data = bytes(value) else { return false }
    return Data(String(decoding: data, as: UTF8.self).utf8) == data
} as @convention(block) (JSValue) -> Bool)

define("random", { (count: Int) -> JSValue in
    var data = Data(count: max(0, min(count, 65_536)))
    _ = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
    return array(data)
} as @convention(block) (Int) -> JSValue)

let started = DispatchTime.now().uptimeNanoseconds
define("now", { () -> Double in Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000 } as @convention(block) () -> Double)

var timers: [Int: DispatchWorkItem] = [:], nextTimer = 1
define("setTimeout", { (callback: JSValue, milliseconds: Double) -> Int in
    let id = nextTimer; nextTimer += 1
    let item = DispatchWorkItem { timers[id] = nil; callback.call(withArguments: []) }
    timers[id] = item
    DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(Int(max(0, milliseconds))), execute: item)
    return id
} as @convention(block) (JSValue, Double) -> Int)
define("clearTimeout", { (id: Int) in timers.removeValue(forKey: id)?.cancel() } as @convention(block) (Int) -> Void)

define("write", { (fd: Int32, value: JSValue) in
    guard let data = bytes(value) else { return }
    (fd == 2 ? FileHandle.standardError : FileHandle.standardOutput).write(data)
} as @convention(block) (Int32, JSValue) -> Void)
define("stdin", { () -> JSValue in array(request) } as @convention(block) () -> JSValue)
define("env", { () -> JSValue in JSValue(object: ProcessInfo.processInfo.environment, in: context) } as @convention(block) () -> JSValue)
define("uid", { () -> Double in Double(getuid()) } as @convention(block) () -> Double)
define("exit", { (code: Int32) in finish(code) } as @convention(block) (Int32) -> Void)

context.setObject(host, forKeyedSubscript: "__host" as NSString)
context.setObject(engine.path, forKeyedSubscript: "__humaRoot" as NSString)
context.setObject(engine.appendingPathComponent("worker.mjs").absoluteString, forKeyedSubscript: "__humaWorkerURL" as NSString)

// worker.js is one async function (see package.py); when it settles, exit as Node would.
let done = context.evaluateScript(source, withSourceURL: script)!
let settled: @convention(block) (JSValue) -> Void = { _ in
    let code = context.evaluateScript("globalThis.process?.exitCode ?? 0")?.toInt32() ?? 0
    finish(code)
}
let failed: @convention(block) (JSValue) -> Void = { _ in
    FileHandle.standardError.write(Data("The engine stopped unexpectedly.\n".utf8))
    finish(1)
}
done.invokeMethod("then", withArguments: [JSValue(object: settled, in: context)!, JSValue(object: failed, in: context)!])
dispatchMain()
