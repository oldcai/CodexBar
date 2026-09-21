import Foundation
import Testing
@testable import CodexBarCore

#if os(macOS)
import LocalAuthentication
import Security
#endif

struct MuseCredentialsTests {
    @Test
    func `Keychain payload selects the device token rather than the inference key`() throws {
        let data = Data(#"{"api_key":"LLM|fixture-inference","access_token":"dca:fixture-device"}"#.utf8)
        #expect(try MuseCredentials.accessToken(fromKeychainPayload: data) == "dca:fixture-device")
    }

    @Test(arguments: [#"{"api_key":"LLM|fixture-inference"}"#, #"{"access_token":"LLM|fixture-inference"}"#])
    func `Keychain payloads without a device token are rejected`(body: String) throws {
        #expect(throws: MuseUsageError.invalidCredentials) {
            try MuseCredentials.accessToken(fromKeychainPayload: Data(body.utf8))
        }
    }

    @Test
    func `inline CLI token is selected without any Keychain read`() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("auth.json")
        try Data(#"{"providers":{"meta":{"mechanism":"oauth","access_token":"dca:fixture-file"}}}"#.utf8)
            .write(to: file)
        let environment = ["MUSE_AUTH_PATH": file.path]
        #expect(MuseCredentials.hasLogin(environment: environment, homeDirectory: directory))
        #expect(try MuseCredentials
            .accessToken(environment: environment, homeDirectory: directory) == "dca:fixture-file")
    }

    @Test
    func `oauth metadata identifies a Keychain-backed login`() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("auth.json")
        try Data(#"{"providers":{"meta":{"mechanism":"oauth","storage":"keychain"}}}"#.utf8).write(to: file)
        #expect(MuseCredentials.hasLogin(environment: ["MUSE_AUTH_PATH": file.path], homeDirectory: directory))
    }

    @Test
    func `invalid inline credentials cannot fall through to another Keychain login`() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("auth.json")
        try Data(#"{"providers":{"meta":{"mechanism":"oauth","access_token":"LLM|fixture-wrong-kind"}}}"#.utf8)
            .write(to: file)
        #expect(throws: MuseUsageError.invalidCredentials) {
            try MuseCredentials.accessToken(environment: ["MUSE_AUTH_PATH": file.path], homeDirectory: directory)
        }
    }

    @Test
    func `descriptor exposes subscription OAuth without an API-key override`() {
        let descriptor = ProviderDescriptorRegistry.descriptor(for: .muse)
        #expect(!descriptor.metadata.defaultEnabled)
        #expect(descriptor.fetchPlan.sourceModes == Set([.auto, .oauth]))
        #expect(descriptor.credentials?.supportsAPIKeyOverride == false)
        #expect(descriptor.cli.aliases == ["muse-code"])
    }
}

#if os(macOS)
/// Proves the Muse Keychain data read is preflight-gated: refreshes must never issue a
/// `kSecReturnData` query unless the no-UI preflight already reports `.allowed`, because data
/// queries can surface the legacy ACL prompt even with UI-fail policy. An explicit manual refresh
/// may attempt one interactive read so the user can authorize access; scheduled, menu-open, and
/// CLI refreshes always fail closed. Resolved tokens are cached per home so external ACL resets
/// do not break later refreshes. All seams (gate, interaction, preflight, data read) are stubbed,
/// so these tests never touch the real Keychain.
@Suite(.serialized)
struct MuseKeychainPreflightTests {
    private static let keychainPayload = Data(#"{"access_token":"dca:fixture-keychain"}"#.utf8)
    private static let oauthMetadataAuthFile = #"{"providers":{"meta":{"mechanism":"oauth","storage":"keychain"}}}"#

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
        dataRead: (([String: Any]) -> (OSStatus, Data?))?,
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
                    try MuseCredentials.withKeychainDataReadOverrideForTesting(dataRead, operation: operation)
                }
            }
        }
    }

    private func accessToken(
        preflight: KeychainAccessPreflight.Outcome,
        interaction: ProviderInteraction = .background,
        authFileBody: String? = nil,
        dataRead: (([String: Any]) -> (OSStatus, Data?))? = nil) throws -> String
    {
        try self.withIsolatedHome { home in
            try self.accessTokenOnHome(
                home,
                preflight: preflight,
                interaction: interaction,
                authFileBody: authFileBody,
                dataRead: dataRead)
        }
    }

    private func accessTokenOnHome(
        _ home: URL,
        preflight: KeychainAccessPreflight.Outcome,
        interaction: ProviderInteraction = .background,
        authFileBody: String? = nil,
        dataRead: (([String: Any]) -> (OSStatus, Data?))? = nil,
        onPreflight: ((String, String?) -> Void)? = nil,
        keychainDisabled: Bool = false) throws -> String
    {
        if let authFileBody {
            let directory = home.appendingPathComponent(".config/muse", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Data(authFileBody.utf8).write(to: directory.appendingPathComponent("auth.json"))
        }
        return try self.withMuseKeychainDoubles(
            preflight: preflight,
            interaction: interaction,
            dataRead: dataRead,
            onPreflight: onPreflight,
            keychainDisabled: keychainDisabled)
        {
            try MuseCredentials.accessToken(environment: [:], homeDirectory: home)
        }
    }

    private func hasLogin(
        preflight: KeychainAccessPreflight.Outcome,
        interaction: ProviderInteraction = .background,
        dataRead: (([String: Any]) -> (OSStatus, Data?))? = nil) throws -> Bool
    {
        try self.withIsolatedHome { home in
            try self.hasLoginOnHome(home, preflight: preflight, interaction: interaction, dataRead: dataRead)
        }
    }

    private func hasLoginOnHome(
        _ home: URL,
        preflight: KeychainAccessPreflight.Outcome,
        interaction: ProviderInteraction = .background,
        dataRead: (([String: Any]) -> (OSStatus, Data?))? = nil,
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

    @Test(arguments: [
        KeychainAccessPreflight.Outcome.interactionRequired,
        .temporarilyUnavailable,
        .failure(-25293),
    ])
    func `background denied preflight fails closed without issuing a data read`(
        preflight: KeychainAccessPreflight.Outcome) throws
    {
        var dataReadAttempts = 0
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReadAttempts += 1
            return (errSecSuccess, Self.keychainPayload)
        }
        // Without auth-file evidence of a login, an unreadable Keychain entry reports as missing.
        #expect(throws: MuseUsageError.missingCredentials) {
            try self.accessToken(preflight: preflight, dataRead: dataRead)
        }
        #expect(try self.hasLogin(preflight: preflight, dataRead: dataRead) == false)
        // OAuth metadata without an inline token proves a Keychain-backed login, so the same
        // denial surfaces as unavailable instead of missing.
        #expect(throws: MuseUsageError.keychainUnavailable) {
            try self.accessToken(
                preflight: preflight,
                authFileBody: Self.oauthMetadataAuthFile,
                dataRead: dataRead)
        }
        #expect(dataReadAttempts == 0)
    }

    @Test
    func `background missing item reports missing credentials without issuing a data read`() throws {
        var dataReadAttempts = 0
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReadAttempts += 1
            return (errSecSuccess, Self.keychainPayload)
        }
        #expect(throws: MuseUsageError.missingCredentials) {
            try self.accessToken(preflight: .notFound, dataRead: dataRead)
        }
        #expect(try self.hasLogin(preflight: .notFound, dataRead: dataRead) == false)
        #expect(dataReadAttempts == 0)
    }

    @Test(arguments: [ProviderInteraction.background, .userInitiated])
    func `granted preflight reads the device token with a non interactive query`(
        interaction: ProviderInteraction) throws
    {
        var dataReadAttempts = 0
        var observedQuery: [String: Any]?
        let token = try self.accessToken(preflight: .allowed, interaction: interaction) { query in
            dataReadAttempts += 1
            observedQuery = query
            return (errSecSuccess, Self.keychainPayload)
        }
        #expect(token == "dca:fixture-keychain")
        #expect(dataReadAttempts == 1)
        let query = try #require(observedQuery)
        #expect(query[kSecClass as String] as? String == (kSecClassGenericPassword as String))
        #expect(query[kSecAttrService as String] as? String == MuseCredentials.keychainService)
        #expect(query[kSecAttrAccount as String] as? String == MuseCredentials.keychainAccount)
        #expect(query[kSecMatchLimit as String] as? String == (kSecMatchLimitOne as String))
        #expect(query[kSecReturnData as String] as? Bool == true)
        #expect((query[kSecUseAuthenticationContext as String] as? LAContext)?.interactionNotAllowed == true)
        #expect((query[kSecUseAuthenticationUI as String] as? String)
            == KeychainNoUIQuery.uiFailPolicyForTesting())
    }

    @Test(arguments: [
        KeychainAccessPreflight.Outcome.interactionRequired,
        .temporarilyUnavailable,
    ])
    func `manual refresh attempts one interactive read when access is not granted`(
        preflight: KeychainAccessPreflight.Outcome) throws
    {
        var dataReadAttempts = 0
        var observedQuery: [String: Any]?
        var notifiedMusePreAlert = false
        var notifiedServices: [String] = []
        let recordPreAlert: (KeychainPromptContext) -> Void = { context in
            if case .museToken = context.kind {
                notifiedMusePreAlert = true
            }
            notifiedServices.append(context.service)
        }
        let token = try KeychainPromptHandler.withHandlerForTesting(recordPreAlert) {
            try self.accessToken(preflight: preflight, interaction: .userInitiated) { query in
                dataReadAttempts += 1
                observedQuery = query
                return (errSecSuccess, Self.keychainPayload)
            }
        }
        #expect(token == "dca:fixture-keychain")
        #expect(dataReadAttempts == 1)
        #expect(notifiedMusePreAlert)
        #expect(notifiedServices == [MuseCredentials.keychainService])
        let query = try #require(observedQuery)
        #expect(query[kSecAttrService as String] as? String == MuseCredentials.keychainService)
        #expect(query[kSecAttrAccount as String] as? String == MuseCredentials.keychainAccount)
        #expect(query[kSecReturnData as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
    }

    @Test
    func `denying the interactive read surfaces unavailable without granting`() throws {
        var dataReadAttempts = 0
        #expect(throws: MuseUsageError.keychainUnavailable) {
            try self.accessToken(
                preflight: .interactionRequired,
                interaction: .userInitiated,
                authFileBody: Self.oauthMetadataAuthFile,
                dataRead: { _ in
                    dataReadAttempts += 1
                    return (errSecAuthFailed, nil)
                })
        }
        #expect(dataReadAttempts == 1)
    }

    @Test
    func `manual refresh still fails closed for missing and failed items`() {
        var dataReadAttempts = 0
        var preAlertCount = 0
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReadAttempts += 1
            return (errSecSuccess, Self.keychainPayload)
        }
        let recordPreAlert: (KeychainPromptContext) -> Void = { _ in preAlertCount += 1 }
        KeychainPromptHandler.withHandlerForTesting(recordPreAlert) {
            #expect(throws: MuseUsageError.missingCredentials) {
                try self.accessToken(preflight: .notFound, interaction: .userInitiated, dataRead: dataRead)
            }
            #expect(throws: MuseUsageError.keychainUnavailable) {
                try self.accessToken(
                    preflight: .failure(-25293),
                    interaction: .userInitiated,
                    authFileBody: Self.oauthMetadataAuthFile,
                    dataRead: dataRead)
            }
        }
        #expect(dataReadAttempts == 0)
        #expect(preAlertCount == 0)
    }

    @Test(arguments: [
        KeychainAccessPreflight.Outcome.interactionRequired,
        .temporarilyUnavailable,
    ])
    func `manual availability check never issues a data read`(
        preflight: KeychainAccessPreflight.Outcome) throws
    {
        var dataReadAttempts = 0
        var preAlertCount = 0
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReadAttempts += 1
            return (errSecSuccess, Self.keychainPayload)
        }
        let recordPreAlert: (KeychainPromptContext) -> Void = { _ in preAlertCount += 1 }
        let result = try KeychainPromptHandler.withHandlerForTesting(recordPreAlert) {
            try self.hasLogin(preflight: preflight, interaction: .userInitiated, dataRead: dataRead)
        }
        #expect(result == false)
        #expect(dataReadAttempts == 0)
        #expect(preAlertCount == 0)
    }

    @Test
    func `keychain read preflights the same Muse service and account it queries`() throws {
        var observed: [(service: String, account: String?)] = []
        _ = try KeychainAccessGate.withTaskOverrideForTesting(false) {
            try KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting { service, account in
                observed.append((service, account))
                return .notFound
            } operation: {
                try self.withIsolatedHome { home in
                    #expect(throws: MuseUsageError.missingCredentials) {
                        try MuseCredentials.accessToken(environment: [:], homeDirectory: home)
                    }
                }
            }
        }
        let preflight = try #require(observed.first)
        #expect(observed.count == 1)
        #expect(preflight.service == MuseCredentials.keychainService)
        #expect(preflight.account == MuseCredentials.keychainAccount)
    }

    @Test
    func `cached token serves refreshes without touching the keychain`() throws {
        var dataReadAttempts = 0
        var preflightChecks = 0
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReadAttempts += 1
            return (errSecSuccess, Self.keychainPayload)
        }
        let recordPreflight: (String, String?) -> Void = { _, _ in preflightChecks += 1 }
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
        #expect(dataReadAttempts == 1)
        #expect(preflightChecks == 1)
    }

    @Test
    func `disabling keychain access drops the cached token`() throws {
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in (errSecSuccess, Self.keychainPayload) }
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
                try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead, keychainDisabled: true)
            }
            // Re-enabling does not resurrect the dropped token: the next read goes to Keychain.
            var reReads = 0
            let reRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
                reReads += 1
                return (errSecSuccess, Self.keychainPayload)
            }
            let second = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: reRead)
            #expect(second == "dca:fixture-keychain")
            #expect(reReads == 1)
        }
    }

    @Test
    func `invalidation forces the next refresh to re-read the keychain`() throws {
        let rotatedPayload = Data(#"{"access_token":"dca:fixture-rotated"}"#.utf8)
        var dataReadAttempts = 0
        try self.withIsolatedHome { home in
            let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
                dataReadAttempts += 1
                return (errSecSuccess, dataReadAttempts == 1 ? Self.keychainPayload : rotatedPayload)
            }
            let first = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(first == "dca:fixture-keychain")
            MuseCredentials.invalidateCachedToken(environment: [:], homeDirectory: home)
            let second = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(second == "dca:fixture-rotated")
        }
        #expect(dataReadAttempts == 2)
    }

    @Test
    func `cache entries are isolated by home`() throws {
        var dataReadAttempts = 0
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReadAttempts += 1
            return (errSecSuccess, Self.keychainPayload)
        }
        try self.withIsolatedHome { firstHome in
            let token = try self.accessTokenOnHome(firstHome, preflight: .allowed, dataRead: dataRead)
            #expect(token == "dca:fixture-keychain")
        }
        _ = try self.withIsolatedHome { secondHome in
            #expect(throws: MuseUsageError.missingCredentials) {
                try self.accessTokenOnHome(secondHome, preflight: .notFound, dataRead: dataRead)
            }
        }
        #expect(dataReadAttempts == 1)
    }

    @Test
    func `reset clears the token cache for testing`() throws {
        var dataReadAttempts = 0
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReadAttempts += 1
            return (errSecSuccess, Self.keychainPayload)
        }
        try self.withIsolatedHome { home in
            let token = try self.accessTokenOnHome(home, preflight: .allowed, dataRead: dataRead)
            #expect(token == "dca:fixture-keychain")
            MuseCredentials.resetTokenCacheForTesting()
            #expect(throws: MuseUsageError.missingCredentials) {
                try self.accessTokenOnHome(home, preflight: .notFound, dataRead: dataRead)
            }
        }
        #expect(dataReadAttempts == 1)
    }
}
#endif
