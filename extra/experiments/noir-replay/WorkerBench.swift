import Foundation
import HumaCore

// Reuse the app's cancellation, thermal, priority and exclusive-job controls.
@main struct WorkerBench {
    static func main() async {
        do {
            var args = Array(CommandLine.arguments.dropFirst())
            let request: Data
            if args.first == "--request-file" {
                guard args.count >= 3 else { throw HumaError.invalidResponse }
                request = try Data(contentsOf: URL(fileURLWithPath: args[1])); args.removeFirst(2)
            } else { request = Data() }
            guard let executable = args.first else { throw HumaError.invalidResponse }
            let started = ContinuousClock.now
            let task = Task {
                try await LocalProofWorker.run(executable: URL(fileURLWithPath: executable),
                    arguments: Array(args.dropFirst()), request: request, timeout: 180, workload: .proving)
            }
            signal(SIGINT, SIG_IGN); signal(SIGTERM, SIG_IGN)
            let signals = [SIGINT, SIGTERM].map { number in
                let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
                source.setEventHandler { task.cancel() }; source.resume(); return source
            }
            defer { signals.forEach { $0.cancel() } }
            let output = try await task.value
            let elapsed = started.duration(to: .now).components
            let ms = Double(elapsed.seconds) * 1000 + Double(elapsed.attoseconds) / 1e15
            let result: Any = output.isEmpty ? NSNull() : (try JSONSerialization.jsonObject(with: output))
            let report: [String: Any] = ["elapsedMs": ms, "result": result]
            FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]))
        } catch {
            FileHandle.standardError.write(Data("Experiment worker: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
