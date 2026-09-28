#if os(macOS)
import Foundation
import Security
import Testing
@testable import CodexBarCore

/// Proves resolved Muse Keychain tokens are cached in memory for the app session: the owning CLI
/// rewrites its Keychain item on use, which resets the item ACL and wipes previously granted access,
/// so later refreshes must not touch Keychain at all until the API actually rejects the token.
/// All seams (gate, interaction, preflight, data read) are stubbed, so these tests never touch the
/// real Keychain.
@Suite(.serialized)
struct MuseTokenCacheTests {
    private static let keychainPayload = Data(#"{"access_token":"dca:fixture-keychain"}"#.utf8)

    private func withIsolatedHome<T>(_ operation: (URL) throws -> T) throws -> T {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        return try operation(home)
    }

    /// Runs an operation with the Keychain enabled, an explicit interaction context, a stubbed
    /// no-UI preflight outcome, and a stubbed data read — the exact seams the reader consults.
    private func withMuseKeychainDoubles<T>(
        preflight: KeychainAccessPreflight.Outcome,
        interaction: ProviderInteraction,
        dataRead: (@Sendable ([String: Any]) -> (OSStatus, Data?))?,
        onPreflight: ((String, String?) -> Void)? = nil,
        keychainDisabled: Bool = false,
        operation: () throws -> T) throws -> T
    {
        let stubPreflight: (String, String?) -> KeychainAccessPreflight.Outcome = { service, account in
            onPreflight?(service, account)
            return preflight
        }
        return try KeychainAccessGate.withTaskOverrideForTesting(keychainDisabled) {
            try ProviderInteractionContext.$current.withValue(interaction) {
                try KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting(stubPreflight) {
                    try MuseCredentials.$keychainReadOverrideForTesting.withValue(dataRead) {
                        try operation()
                    }
                }
            }
        }
    }

    private func accessTokenOnHome(
        _ home: URL,
        preflight: KeychainAccessPreflight.Outcome,
        interaction: ProviderInteraction = .background,
        dataRead: (@Sendable ([String: Any]) -> (OSStatus, Data?))?,
        onPreflight: ((String, String?) -> Void)? = nil,
        keychainDisabled: Bool = false) throws -> String
    {
        try self.withMuseKeychainDoubles(
            preflight: preflight,
            interaction: interaction,
            dataRead: dataRead,
            onPreflight: onPreflight,
            keychainDisabled: keychainDisabled)
        {
            try MuseCredentials.accessToken(environment: [:], homeDirectory: home)
        }
    }

    private func hasLoginOnHome(
        _ home: URL,
        preflight: KeychainAccessPreflight.Outcome,
        interaction: ProviderInteraction = .background,
        dataRead: (@Sendable ([String: Any]) -> (OSStatus, Data?))?,
        onPreflight: ((String, String?) -> Void)? = nil,
        keychainDisabled: Bool = false) throws -> Bool
    {
        try self.withMuseKeychainDoubles(
            preflight: preflight,
            interaction: interaction,
            dataRead: dataRead,
            onPreflight: onPreflight,
            keychainDisabled: keychainDisabled)
        {
            MuseCredentials.hasLogin(environment: [:], homeDirectory: home)
        }
    }

    @Test
    func `cached token serves refreshes without touching the keychain`() throws {
        let dataReads = LockIsolated(0)
        let preflightChecks = LockIsolated(0)
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReads.setValue(dataReads.value + 1)
            return (errSecSuccess, Self.keychainPayload)
        }
        let recordPreflight: (String, String?) -> Void = { _, _ in
            preflightChecks.setValue(preflightChecks.value + 1)
        }
        try self.withIsolatedHome { home in
            let first = try self.accessTokenOnHome(
                home,
                preflight: .allowed,
                dataRead: dataRead,
                onPreflight: recordPreflight)
            #expect(first == "dca:fixture-keychain")
            // The owning CLI reset the item ACL after the first read: the preflight now denies,
            // but the cached token keeps the refresh working without any Keychain traffic.
            let second = try self.accessTokenOnHome(
                home,
                preflight: .interactionRequired,
                dataRead: dataRead,
                onPreflight: recordPreflight)
            #expect(second == "dca:fixture-keychain")
            #expect(try self.hasLoginOnHome(
                home,
                preflight: .interactionRequired,
                dataRead: dataRead,
                onPreflight: recordPreflight) == true)
        }
        #expect(dataReads.value == 1)
        #expect(preflightChecks.value == 1)
    }

    @Test
    func `cached token keeps the login visible when the item disappears`() throws {
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            (errSecSuccess, Self.keychainPayload)
        }
        try self.withIsolatedHome { home in
            let first = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(first == "dca:fixture-keychain")
            #expect(try self.hasLoginOnHome(home, preflight: .notFound, dataRead: dataRead) == true)
        }
    }

    @Test
    func `disabling keychain access drops the cached token`() throws {
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            (errSecSuccess, Self.keychainPayload)
        }
        try self.withIsolatedHome { home in
            let first = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(first == "dca:fixture-keychain")
            // Disabling Keychain access after a successful read drops the cached token: the
            // provider no longer reports a login and never serves the cached secret.
            #expect(try self.hasLoginOnHome(
                home,
                preflight: .allowed,
                dataRead: dataRead,
                keychainDisabled: true) == false)
            #expect(throws: MuseUsageError.missingCredentials) {
                try self.accessTokenOnHome(
                    home,
                    preflight: .allowed,
                    dataRead: dataRead,
                    keychainDisabled: true)
            }
            // Re-enabling does not resurrect the dropped token: the next read goes to Keychain.
            let reReads = LockIsolated(0)
            let reRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
                reReads.setValue(reReads.value + 1)
                return (errSecSuccess, Self.keychainPayload)
            }
            let second = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: reRead)
            #expect(second == "dca:fixture-keychain")
            #expect(reReads.value == 1)
        }
    }

    @Test
    func `invalidation forces the next refresh to re-read the keychain`() throws {
        let rotatedPayload = Data(#"{"access_token":"dca:fixture-rotated"}"#.utf8)
        let dataReads = LockIsolated(0)
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReads.setValue(dataReads.value + 1)
            return (errSecSuccess, dataReads.value == 1 ? Self.keychainPayload : rotatedPayload)
        }
        try self.withIsolatedHome { home in
            let first = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(first == "dca:fixture-keychain")
            MuseCredentials.invalidateCachedToken(environment: [:], homeDirectory: home)
            let second = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(second == "dca:fixture-rotated")
        }
        #expect(dataReads.value == 2)
    }

    @Test
    func `cache entries are isolated by home`() throws {
        let dataReads = LockIsolated(0)
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReads.setValue(dataReads.value + 1)
            return (errSecSuccess, Self.keychainPayload)
        }
        try self.withIsolatedHome { firstHome in
            let token = try self.accessTokenOnHome(firstHome, preflight: .allowed, dataRead: dataRead)
            #expect(token == "dca:fixture-keychain")
        }
        try self.withIsolatedHome { secondHome in
            #expect(throws: MuseUsageError.missingCredentials) {
                try self.accessTokenOnHome(secondHome, preflight: .notFound, dataRead: dataRead)
            }
        }
        #expect(dataReads.value == 1)
    }

    @Test
    func `rotated inline tokens are always served fresh`() throws {
        let dataReads = LockIsolated(0)
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReads.setValue(dataReads.value + 1)
            return (errSecSuccess, Self.keychainPayload)
        }
        try self.withIsolatedHome { home in
            // Seed the cache with a keychain-resolved token first.
            let seeded = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(seeded == "dca:fixture-keychain")
            let directory = home.appendingPathComponent(".config/muse", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let file = directory.appendingPathComponent("auth.json")
            try Data(#"{"providers":{"meta":{"mechanism":"oauth","access_token":"dca:fixture-inline-first"}}}"#.utf8)
                .write(to: file)
            #expect(try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
                == "dca:fixture-inline-first")
            // Rotating the inline token is picked up immediately: inline tokens take precedence
            // and are never served from the keychain cache.
            try Data(#"{"providers":{"meta":{"mechanism":"oauth","access_token":"dca:fixture-inline-second"}}}"#.utf8)
                .write(to: file)
            #expect(try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
                == "dca:fixture-inline-second")
        }
        #expect(dataReads.value == 1)
    }
}
#endif
