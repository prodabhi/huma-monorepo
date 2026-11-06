import Foundation
import Darwin
import XCTest
@testable import HumaCore

@MainActor
final class LocalProofWorkerTests: XCTestCase {
    private func waitForFile(_ url: URL) async throws {
        for _ in 0..<100 {
            if FileManager.default.fileExists(atPath: url.path) { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTFail("Worker never reached the expected checkpoint")
        throw HumaError.invalidResponse
    }
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
    func testWorkerDrainsStderrWhileReadingItsResponse() async throws {
        let program = "import sys; data=sys.stdin.buffer.read(); sys.stderr.buffer.write(b'x'*262144); sys.stderr.flush(); sys.stdout.buffer.write(data)"
        let input = Data("public test response".utf8)
        let result = try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
            arguments: ["-c", program], request: input, timeout: 5)
        XCTAssertEqual(result, input)
    }
    func testWorkerExitBeforeReadingDoesNotTerminateCaller() async throws {
        do {
            _ = try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                arguments: ["-c", "import sys; sys.exit(7)"], request: Data(repeating: 65, count: 512 * 1024), timeout: 5)
            XCTFail("A broken input pipe must throw")
        } catch { XCTAssertNotNil(error) }
    }
    func testWorkerRejectsNonzeroExitAndEnforcesDeadline() async throws {
        for program in ["import sys; sys.stdin.buffer.read(); sys.exit(7)", "import time; time.sleep(30)"] {
            do {
                _ = try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                    arguments: ["-c", program], request: Data(), timeout: 0.2)
                XCTFail("A failed or expired worker must not return a proof")
            } catch { XCTAssertTrue(error is HumaError) }
        }
    }
    func testCancellationStopsTheWorkerAndItsProverChild() async throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let ready = directory.appendingPathComponent("child.json")
        let program = """
        import subprocess, sys, pathlib, json, os
        sys.stdin.buffer.read()
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        pathlib.Path(sys.argv[1]).write_text(json.dumps({'child': child.pid, 'group': os.getpgrp()}))
        child.wait()
        """
        let task = Task {
            try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                arguments: ["-c", program, ready.path], request: Data(), timeout: 10)
        }
        defer { task.cancel() }
        try await waitForFile(ready)
        let info = try JSONSerialization.jsonObject(with: Data(contentsOf: ready)) as! [String: Int32]
        let child = info["child"]!, group = info["group"]!
        defer { if getpgid(child) == group { kill(child, SIGKILL) } }
        let started = ContinuousClock.now
        task.cancel()
        do { _ = try await task.value; XCTFail("Cancellation returned a result") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertLessThan(started.duration(to: .now), .seconds(2))
        for _ in 0..<100 {
            if kill(child, 0) != 0 { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertEqual(kill(child, 0), -1, "The prover child must not survive cancellation")
        XCTAssertEqual(errno, ESRCH)
    }
    func testProvingIsExclusiveAndCancellationReleasesTheReservation() async throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let ready = directory.appendingPathComponent("ready")
        let program = "import pathlib,sys,time; sys.stdin.buffer.read(); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)"
        let first = Task {
            try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                arguments: ["-c", program, ready.path], request: Data(), timeout: 10, workload: .proving)
        }
        defer { first.cancel() }
        try await waitForFile(ready)
        do {
            _ = try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                arguments: ["-c", "print('unexpected second prover')"], request: Data(), workload: .proving)
            XCTFail("A second prover was admitted")
        } catch { XCTAssertTrue(error.localizedDescription.contains("already creating a proof")) }
        first.cancel(); _ = try? await first.value
        let result = try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
            arguments: ["-c", "print('reservation released')"], request: Data(), workload: .proving)
        XCTAssertEqual(String(data: result, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), "reservation released")
    }
    func testProvingUsesBackgroundThreadsLowerPriorityAndAnOwnedProcessGroup() async throws {
        let program = "import os,json; print(json.dumps({'threads':os.environ.get('RAYON_NUM_THREADS'),'backendThreads':os.environ.get('HARDWARE_CONCURRENCY'),'workerThreads':os.environ.get('HUMA_PROVER_THREADS'),'priority':os.getpriority(os.PRIO_PROCESS,0),'pid':os.getpid(),'group':os.getpgrp()}))"
        let result = try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
            arguments: ["-c", program], request: Data(), workload: .proving)
        let actual = try JSONSerialization.jsonObject(with: result) as! [String: Any]
        let threads = String(LocalProofWorker.backgroundThreads())
        XCTAssertEqual(actual["threads"] as? String, threads)
        XCTAssertEqual(actual["backendThreads"] as? String, threads)
        XCTAssertEqual(actual["workerThreads"] as? String, threads) // the Noir worker reads this one
        XCTAssertGreaterThanOrEqual(actual["priority"] as! Int, 10)
        XCTAssertEqual(actual["pid"] as? Int, actual["group"] as? Int)
    }
    func testBackgroundPartsUseMoreThreadsOnlyOnACoolMacOutsideLowPowerMode() {
        let full = LocalProofWorker.finishingThreads(thermal: .nominal)
        XCTAssertEqual(LocalProofWorker.backgroundThreads(thermal: .nominal, lowPower: false), min(4, full))
        XCTAssertEqual(LocalProofWorker.backgroundThreads(thermal: .nominal, lowPower: true), 2)
        XCTAssertEqual(LocalProofWorker.backgroundThreads(thermal: .fair, lowPower: false), 2)
        XCTAssertEqual(LocalProofWorker.backgroundThreads(thermal: .serious, lowPower: false), 2)
    }
}
