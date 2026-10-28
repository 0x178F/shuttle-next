import Foundation
import Dispatch

final class CredentialBoundaryGate: @unchecked Sendable {
    private let lock = NSLock()
    private let proceed = DispatchSemaphore(value: 0)
    private var entered = false
    private var finished = false
    private var observer: CheckedContinuation<Bool, Never>?

    func enterAndWait() {
        let observer = lock.withLock {
            entered = true
            defer { self.observer = nil }
            return self.observer
        }
        observer?.resume(returning: true)
        proceed.wait()
    }

    // The driver must not need a cooperative worker to release the credential boundary.
    @MainActor
    func waitForEntry() async -> Bool {
        await withCheckedContinuation { continuation in
            let ready: Bool? = lock.withLock {
                if entered { return true }
                if finished { return false }
                observer = continuation
                return nil
            }
            if let ready { continuation.resume(returning: ready) }
        }
    }

    func finish() {
        let observer = lock.withLock {
            finished = true
            defer { self.observer = nil }
            return self.observer
        }
        observer?.resume(returning: false)
    }

    func release() {
        proceed.signal()
    }
}
