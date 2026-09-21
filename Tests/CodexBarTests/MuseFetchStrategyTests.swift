import Foundation
import Testing
@testable import CodexBarCore

#if os(macOS)
import Security

/// Proves an expired Muse credential retries once against a re-read credential: the first
/// rejection drops the cached token, resolution re-reads, and only a second rejection surfaces.
/// Real Keychain and network stay stubbed throughout.
struct MuseFetchStrategyTests {
    private static let stalePayload = Data(#"{"access_token":"dca:fixture-stale"}"#.utf8)
    private static let rotatedPayload = Data(#"{"access_token":"dca:fixture-rotated"}"#.utf8)

    private struct StubClaudeFetcher: ClaudeUsageFetching {
        func loadLatestUsage(model _: String) async throws -> ClaudeUsageSnapshot {
            throw MuseUsageError.parseFailed("stub")
        }

        func debugRawProbe(model _: String) async -> String {
            "stub"
        }

        func detectVersion() -> String? {
            nil
        }
    }

    private func makeContext(env: [String: String]) -> ProviderFetchContext {
        ProviderFetchContext(
            runtime: .app,
            sourceMode: .oauth,
            includeCredits: false,
            includeOptionalUsage: false,
            webTimeout: 1,
            webDebugDumpHTML: false,
            verbose: false,
            env: env,
            settings: nil,
            fetcher: UsageFetcher(environment: env),
            claudeFetcher: StubClaudeFetcher(),
            browserDetection: BrowserDetection(cacheTTL: 0))
    }

    private func freshAuthPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("CodexBar-MuseFetch-\(UUID().uuidString)", isDirectory: false).path
    }

    @Test
    func `expired token retries once against the re-read credential`() async throws {
        let attempts = LockIsolated(0)
        let seenTokens = LockIsolated<[String]>([])
        let snapshot = UsageSnapshot(primary: nil, secondary: nil, updatedAt: Date())
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            attempts.setValue(attempts.value + 1)
            return (errSecSuccess, attempts.value == 1 ? Self.stalePayload : Self.rotatedPayload)
        }
        let usageFetcher: (String) async throws -> UsageSnapshot = { token in
            seenTokens.setValue(seenTokens.value + [token])
            if token == "dca:fixture-stale" {
                throw ProviderFetchClassifiedError(kind: .authenticationExpired, message: "fixture")
            }
            return snapshot
        }
        let context = self.makeContext(env: ["MUSE_AUTH_PATH": self.freshAuthPath()])
        let result = try await self.fetch(context: context, dataRead: dataRead, usageFetcher: usageFetcher)
        #expect(result.sourceLabel == "oauth")
        #expect(seenTokens.value == ["dca:fixture-stale", "dca:fixture-rotated"])
        #expect(attempts.value == 2)
    }

    @Test
    func `persistently rejected token surfaces expired after one retry`() async throws {
        let attempts = LockIsolated(0)
        let seenTokens = LockIsolated<[String]>([])
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            attempts.setValue(attempts.value + 1)
            return (errSecSuccess, Self.stalePayload)
        }
        let usageFetcher: (String) async throws -> UsageSnapshot = { token in
            seenTokens.setValue(seenTokens.value + [token])
            throw ProviderFetchClassifiedError(kind: .authenticationExpired, message: "fixture")
        }
        let context = self.makeContext(env: ["MUSE_AUTH_PATH": self.freshAuthPath()])
        let expected = ProviderFetchClassifiedError(kind: .authenticationExpired, message: "fixture")
        await #expect(throws: expected) {
            try await self.fetch(context: context, dataRead: dataRead, usageFetcher: usageFetcher)
        }
        #expect(seenTokens.value == ["dca:fixture-stale", "dca:fixture-stale"])
        #expect(attempts.value == 2)
        // The re-read credential was rejected too, so it must not linger in the cache to be
        // sent again (and rejected again) on the next refresh.
        #expect(MuseCredentials.cachedToken(
            environment: context.env,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser) == nil)
    }

    @Test
    func `retry may prompt when the first attempt served a cached token`() async throws {
        let preAlerts = LockIsolated(0)
        let seenTokens = LockIsolated<[String]>([])
        let snapshot = UsageSnapshot(primary: nil, secondary: nil, updatedAt: Date())
        let context = self.makeContext(env: ["MUSE_AUTH_PATH": self.freshAuthPath()])
        // Seed the cache with a token the CLI later rotates away.
        let seedReads: ([String: Any]) -> (OSStatus, Data?) = { _ in (errSecSuccess, Self.stalePayload) }
        _ = try await self.fetch(context: context, dataRead: seedReads) { _ in snapshot }
        // The CLI rotated the value and reset the item ACL afterwards: the cached token is
        // rejected, and the retry re-read is this refresh's first Keychain read, so it may
        // prompt once instead of failing closed.
        let recordPreAlert: (KeychainPromptContext) -> Void = { _ in
            preAlerts.setValue(preAlerts.value + 1)
        }
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in (errSecSuccess, Self.rotatedPayload) }
        let stubPreflight: (String, String?) -> KeychainAccessPreflight.Outcome = { _, _ in .interactionRequired }
        let result = try await KeychainAccessGate.withTaskOverrideForTesting(false) {
            try await ProviderInteractionContext.$current.withValue(.userInitiated) {
                try await KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting(stubPreflight) {
                    try await MuseCredentials.withKeychainDataReadOverrideForTesting(dataRead) {
                        try await KeychainPromptHandler.withHandlerForTesting(recordPreAlert) {
                            try await MuseOAuthFetchStrategy().fetch(context) { token in
                                seenTokens.setValue(seenTokens.value + [token])
                                if token == "dca:fixture-stale" {
                                    throw ProviderFetchClassifiedError(
                                        kind: .authenticationExpired,
                                        message: "fixture")
                                }
                                return snapshot
                            }
                        }
                    }
                }
            }
        }
        #expect(result.sourceLabel == "oauth")
        #expect(seenTokens.value == ["dca:fixture-stale", "dca:fixture-rotated"])
        #expect(preAlerts.value == 1)
    }

    @Test
    func `auth-expired retry never prompts Keychain a second time`() async throws {
        let dataReads = LockIsolated(0)
        let preAlerts = LockIsolated(0)
        let seenTokens = LockIsolated<[String]>([])
        let dataRead: ([String: Any]) -> (OSStatus, Data?) = { _ in
            dataReads.setValue(dataReads.value + 1)
            return (errSecSuccess, Self.stalePayload)
        }
        let usageFetcher: (String) async throws -> UsageSnapshot = { token in
            seenTokens.setValue(seenTokens.value + [token])
            throw ProviderFetchClassifiedError(kind: .authenticationExpired, message: "fixture")
        }
        let context = self.makeContext(env: ["MUSE_AUTH_PATH": self.freshAuthPath()])
        // The ACL still requires interaction after the first authorized read (a one-time Allow,
        // or the CLI rewrote the item between the two reads): the retry re-read must fail
        // closed instead of showing a second authorization prompt.
        let recordPreAlert: (KeychainPromptContext) -> Void = { _ in
            preAlerts.setValue(preAlerts.value + 1)
        }
        let stubPreflight: (String, String?) -> KeychainAccessPreflight.Outcome = { _, _ in .interactionRequired }
        await #expect(throws: MuseUsageError.missingCredentials) {
            try await KeychainAccessGate.withTaskOverrideForTesting(false) {
                try await ProviderInteractionContext.$current.withValue(.userInitiated) {
                    try await KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting(stubPreflight) {
                        try await MuseCredentials.withKeychainDataReadOverrideForTesting(dataRead) {
                            try await KeychainPromptHandler.withHandlerForTesting(recordPreAlert) {
                                try await MuseOAuthFetchStrategy().fetch(context, usageFetcher: usageFetcher)
                            }
                        }
                    }
                }
            }
        }
        #expect(preAlerts.value == 1)
        #expect(dataReads.value == 1)
        #expect(seenTokens.value == ["dca:fixture-stale"])
    }

    private func fetch(
        context: ProviderFetchContext,
        dataRead: @escaping ([String: Any]) -> (OSStatus, Data?),
        usageFetcher: @escaping (String) async throws -> UsageSnapshot) async throws -> ProviderFetchResult
    {
        let stubPreflight: (String, String?) -> KeychainAccessPreflight.Outcome = { _, _ in .allowed }
        return try await KeychainAccessGate.withTaskOverrideForTesting(false) {
            try await KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting(stubPreflight) {
                try await MuseCredentials.withKeychainDataReadOverrideForTesting(dataRead) {
                    try await MuseOAuthFetchStrategy().fetch(context, usageFetcher: usageFetcher)
                }
            }
        }
    }
}
#endif
