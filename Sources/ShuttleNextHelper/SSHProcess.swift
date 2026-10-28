import Darwin
import Foundation
import ShuttleCore

private var connectedSSHPID: pid_t = 0

private func forwardConnectionSignal(_ signalNumber: Int32) {
    let pid = connectedSSHPID
    if pid > 0 { kill(pid, signalNumber) }
}

enum SSHProcess {
    // Inherit the terminal's foreground process group and stdio for interactive SSH.
    static func run(arguments: [String], environment: [String: String]) throws -> Int32 {
        var connectionSignals = sigset_t()
        sigemptyset(&connectionSignals)
        for number in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] { sigaddset(&connectionSignals, number) }
        var oldMask = sigset_t()
        guard pthread_sigmask(SIG_BLOCK, &connectionSignals, &oldMask) == 0 else { throw spawnError() }
        let previousINT = signal(SIGINT, forwardConnectionSignal)
        let previousTERM = signal(SIGTERM, forwardConnectionSignal)
        let previousHUP = signal(SIGHUP, forwardConnectionSignal)
        let previousQUIT = signal(SIGQUIT, forwardConnectionSignal)
        defer {
            connectedSSHPID = 0
            signal(SIGINT, previousINT)
            signal(SIGTERM, previousTERM)
            signal(SIGHUP, previousHUP)
            signal(SIGQUIT, previousQUIT)
            pthread_sigmask(SIG_SETMASK, &oldMask, nil)
        }

        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { throw spawnError() }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setsigmask(&attributes, &oldMask) == 0,
              posix_spawnattr_setsigdefault(&attributes, &connectionSignals) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)) == 0 else {
            throw spawnError()
        }

        var argv = try cStrings(["/usr/bin/ssh"] + arguments)
        defer { for pointer in argv { if let pointer { free(pointer) } } }
        var envp = try cStrings(environment.map { "\($0.key)=\($0.value)" })
        defer { for pointer in envp { if let pointer { free(pointer) } } }
        var pid: pid_t = 0
        let result = argv.withUnsafeMutableBufferPointer { argumentBuffer in
            envp.withUnsafeMutableBufferPointer { environmentBuffer in
                posix_spawn(&pid, "/usr/bin/ssh", nil, &attributes,
                            argumentBuffer.baseAddress!, environmentBuffer.baseAddress!)
            }
        }
        guard result == 0 else { throw spawnError() }
        connectedSSHPID = pid
        pthread_sigmask(SIG_SETMASK, &oldMask, nil)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 {
            if errno == EINTR { continue }
            kill(pid, SIGTERM)
            throw ShuttleError.connection("SSH terminated without an available exit status.")
        }
        // Darwin wait status stores the exit code in bits 8-15 and the signal in bits 0-6.
        let terminatingSignal = status & 0x7f
        return terminatingSignal == 0 ? (status >> 8) & 0xff : 128 + terminatingSignal
    }

    private static func cStrings(_ values: [String]) throws -> [UnsafeMutablePointer<CChar>?] {
        var pointers: [UnsafeMutablePointer<CChar>?] = []
        pointers.reserveCapacity(values.count + 1)
        for value in values {
            guard !value.utf8.contains(0), let pointer = strdup(value) else {
                for pointer in pointers { if let pointer { free(pointer) } }
                throw spawnError()
            }
            pointers.append(pointer)
        }
        pointers.append(nil)
        return pointers
    }

    private static func spawnError() -> ShuttleError {
        .connection("The system SSH executable could not be started.")
    }
}
