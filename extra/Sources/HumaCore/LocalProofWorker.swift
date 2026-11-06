import Foundation
import Darwin

/// Runs local workers in an owned process group, with bounded output and cancellation.
public enum LocalProofWorker {
    /// `proving` runs in the background at low priority (see backgroundThreads); `finishing` is a proof the writer
    /// is waiting for, so it uses the performance cores (one left for the interface).
    public enum Workload: Sendable { case standard, proving, finishing }
    /// Threads for a proof the writer is waiting for: performance cores less one, fewer when the Mac is warm.
    public static func finishingThreads(thermal: ProcessInfo.ThermalState = ProcessInfo.processInfo.thermalState) -> Int {
        var cores: Int32 = 0, size = MemoryLayout<Int32>.size
        if sysctlbyname("hw.perflevel0.logicalcpu", &cores, &size, nil, 0) != 0 || cores < 1 { cores = Int32(max(2, ProcessInfo.processInfo.activeProcessorCount / 2)) }
        let threads = min(12, max(2, Int(cores) - 1))
        return thermal == .serious ? min(threads, 4) : threads
    }
    /// Threads for parts proved while the writer types: four on a cool Mac outside Low Power Mode (a 600-operation part
    /// measured 6.1 s on two threads, 4.2 s on four), otherwise two, so fewer parts are left for Finish. They run at low
    /// priority.
    public static func backgroundThreads(thermal: ProcessInfo.ThermalState = ProcessInfo.processInfo.thermalState,
                                         lowPower: Bool = ProcessInfo.processInfo.isLowPowerModeEnabled) -> Int {
        thermal == .nominal && !lowPower ? min(4, finishingThreads(thermal: thermal)) : 2
    }
    public static func run(executable: URL, arguments: [String] = [], request: Data,
                           timeout: TimeInterval = 1_800, workload: Workload = .standard) async throws -> Data {
        let control = WorkerControl()
        let task = Task.detached(priority: .utility) {
            try execute(executable: executable, arguments: arguments, request: request, timeout: timeout,
                        workload: workload, control: control)
        }
        return try await withTaskCancellationHandler {
            do {
                let result = try await task.value
                try Task.checkCancellation()
                return result
            } catch {
                try Task.checkCancellation()
                throw error
            }
        } onCancel: {
            control.stop(.cancelled)
            task.cancel()
        }
    }
    private static func execute(executable: URL, arguments: [String], request: Data, timeout: TimeInterval,
                                workload: Workload, control: WorkerControl) throws -> Data {
        guard request.count <= 64 * 1024 * 1024 else { throw HumaError.configuration("The private session exceeds the local proof worker's input limit.") }
        let proving = workload != .standard
        let lease = proving ? try ProvingLease() : nil
        defer { lease?.release() }
        if proving && ProcessInfo.processInfo.thermalState == .critical {
            throw HumaError.configuration("This Mac is too warm to start a proof. Let it cool down and try again.")
        }
        let input = Pipe(), output = Pipe(), errors = Pipe()
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw HumaError.configuration("Could not prepare the local worker's input pipe.")
        }
        var environment = ProcessInfo.processInfo.environment
        environment["HUMA_PROVER_THREADS"] = nil // only the server prover may raise the worker's thread count
        // Node reads these to load extra code; the bundled worker never needs them.
        for name in environment.keys where name.hasPrefix("NODE_") || name == "UV_THREADPOOL_SIZE" { environment[name] = nil }
        if proving {
            // R0VM/ACVM use Rayon; Barretenberg also has its own thread setting; the Noir worker passes
            // HUMA_PROVER_THREADS to both. A shell setting must never choose the count.
            let threads = String(workload == .finishing ? finishingThreads() : backgroundThreads())
            environment["RAYON_NUM_THREADS"] = threads
            environment["HARDWARE_CONCURRENCY"] = threads
            environment["HUMA_PROVER_THREADS"] = threads
        }
        let descriptors = [input.fileHandleForReading, input.fileHandleForWriting,
                           output.fileHandleForReading, output.fileHandleForWriting,
                           errors.fileHandleForReading, errors.fileHandleForWriting]
        let pid = try control.launch(executable: executable, arguments: arguments, environment: environment,
            input: descriptors[0].fileDescriptor, output: descriptors[3].fileDescriptor,
            errors: descriptors[5].fileDescriptor, descriptors: descriptors.map(\.fileDescriptor))
        if workload == .proving { _ = setpriority(PRIO_PROCESS, id_t(pid), 10) }
        try? input.fileHandleForReading.close(); try? output.fileHandleForWriting.close(); try? errors.fileHandleForWriting.close()
        // Long-session proofs carry one 14.6 KB proof per chunk, twice (proof and envelope).
        let stdout = BoundedWorkerOutput(limit: 96 * 1024 * 1024)
        let stderr = BoundedWorkerOutput(limit: 64 * 1024)
        let readers = DispatchGroup()
        for (handle, collector) in [(output.fileHandleForReading, stdout), (errors.fileHandleForReading, stderr)] {
            readers.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { readers.leave() }
                collector.read(handle)
            }
        }
        let deadline = DispatchWorkItem { control.stop(.deadline) }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)
        let thermal = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        thermal.schedule(deadline: .now() + 1, repeating: 1)
        thermal.setEventHandler {
            if proving && ProcessInfo.processInfo.thermalState == .critical { control.stop(.thermal) }
        }
        thermal.resume()
        defer { deadline.cancel(); thermal.cancel() }
        var inputError: Error?
        do { try input.fileHandleForWriting.write(contentsOf: request) }
        catch { inputError = error; control.stop(.failed) }
        try? input.fileHandleForWriting.close()
        var status: Int32 = 0
        var waited: pid_t
        repeat { waited = waitpid(pid, &status, 0) } while waited < 0 && errno == EINTR
        let reason = control.finish()
        let drained = readers.wait(timeout: .now() + 5) == .success
        if !drained { try? output.fileHandleForReading.close(); try? errors.fileHandleForReading.close() }
        switch reason {
        case .cancelled: throw CancellationError()
        case .deadline: throw HumaError.configuration("Proof worker reached its time limit. Your draft is unchanged.")
        case .thermal: throw HumaError.configuration("Proof stopped because this Mac became too warm. Your draft is unchanged; try again after it cools down.")
        default: break
        }
        if let inputError { throw inputError }
        guard drained else { throw HumaError.configuration("The local proof worker did not close its output. Your writing was not uploaded.") }
        let (result, exceeded) = stdout.snapshot()
        guard waited == pid, status == 0, !exceeded else {
            // The worker names the step that failed (never any text), so a screenshot of this is enough to diagnose it.
            struct Failure: Decodable { let failure: String }
            let step = (try? JSONDecoder().decode(Failure.self, from: result))?.failure
                .filter { $0.isLetter || $0.isNumber || " .:_-".contains($0) }.prefix(100)
            throw HumaError.configuration("Huma couldn’t finish the proof on this Mac. Your writing is safe and wasn’t uploaded."
                + (step.map { " (Details: \($0))" } ?? ""))
        }
        return result
    }
}

private final class WorkerControl: @unchecked Sendable {
    enum Stop { case cancelled, deadline, thermal, failed }
    private let lock = NSLock()
    private var pid: pid_t?
    private var reason: Stop?
    private var finished = false

    func launch(executable: URL, arguments: [String], environment: [String: String], input: Int32,
                output: Int32, errors: Int32, descriptors: [Int32]) throws -> pid_t {
        lock.lock(); defer { lock.unlock() }
        if reason != nil { throw CancellationError() }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw HumaError.invalidResponse }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw HumaError.invalidResponse }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else { throw HumaError.invalidResponse }
        for (source, target) in [(input, STDIN_FILENO), (output, STDOUT_FILENO), (errors, STDERR_FILENO)] {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw HumaError.invalidResponse }
        }
        for fd in descriptors where fd > STDERR_FILENO {
            guard posix_spawn_file_actions_addclose(&actions, fd) == 0 else { throw HumaError.invalidResponse }
        }
        let argv = ([executable.path] + arguments).map { strdup($0) } + [nil]
        let envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
        var child: pid_t = 0
        let error = argv.withUnsafeBufferPointer { args in
            envp.withUnsafeBufferPointer { env in
                posix_spawn(&child, executable.path, &actions, &attributes,
                            UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: env.baseAddress!))
            }
        }
        guard error == 0 else { throw HumaError.configuration("Could not start the bundled local proof worker.") }
        pid = child
        return child
    }
    func stop(_ reason: Stop) {
        lock.lock(); defer { lock.unlock() }
        guard !finished, self.reason == nil else { return }
        self.reason = reason
        if let pid { Self.end(pid) }
    }
    func finish() -> Stop? {
        lock.lock(); defer { lock.unlock() }
        // Clean up any helper that outlived its worker. This group was created atomically at spawn.
        if let pid { Self.end(pid) }
        pid = nil; finished = true
        return reason
    }
    /// The host's tools (bb, witness) run in their own process groups, so they're stopped by pid before the host;
    /// otherwise a retry would prove alongside the cancelled run.
    private static func end(_ pid: pid_t) {
        var children = [pid_t](repeating: 0, count: 64)
        let count = proc_listchildpids(pid, &children, Int32(children.count * MemoryLayout<pid_t>.stride))
        for child in children.prefix(Int(max(0, min(count, Int32(children.count))))) where child > 0 { kill(child, SIGKILL) }
        kill(-pid, SIGKILL)
    }
}

private final class ProvingLease {
    private var descriptor: Int32
    init() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("huma-\(getuid())-proving.lock").path
        descriptor = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw HumaError.configuration("Could not reserve the local prover.") }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            close(descriptor); descriptor = -1
            throw HumaError.configuration("Huma is already creating a proof in another window. Wait for it or cancel that proof first.")
        }
    }
    func release() { if descriptor >= 0 { close(descriptor); descriptor = -1 } }
    deinit { release() }
}

private final class BoundedWorkerOutput: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var data = Data()
    private var exceeded = false
    init(limit: Int) { self.limit = limit }
    func read(_ handle: FileHandle) {
        do {
            while let chunk = try handle.read(upToCount: 65_536), !chunk.isEmpty {
                lock.lock()
                let remaining = max(0, limit - data.count)
                if chunk.count > remaining { exceeded = true }
                data.append(chunk.prefix(remaining))
                lock.unlock()
            }
        } catch {
            lock.lock(); exceeded = true; lock.unlock()
        }
    }
    func snapshot() -> (Data, Bool) {
        lock.lock(); defer { lock.unlock() }
        return (data, exceeded)
    }
}
