#if os(macOS)
import Foundation
import Security
import Testing
@testable import CodexBarCore

/// Proves an expired Muse credential retries once against a re-read credential: the first
/// rejection drops the cached token, resolution re-reads, and only a second rejection surfaces.
/// A retry credential that is also rejected is dropped so later refreshes re-read instead of
/// leading with a known-rejected token. Real Keychain and network stay stubbed throughout.
struct MuseFetchStrategyTests {
    private static let stalePayload = Data(#"{"access_token":"dca:fixture-stale"}"#.utf8)
    private static let rotatedPayload = Data(#"{"access_token":"dca:fixture-rotated"}"#.utf8)

    private func freshAuthPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("CodexBar-MuseFetch-\(UUID().uuidString)", isDirectory: false).path
    }

    private func withDoubles<T>(
        dataRead: @escaping @Sendable ([String: Any]) -> (OSStatus, Data?),
        operation: () async throws -> T) async throws -> T
    {
        let stubPreflight: (String, String?) -> KeychainAccessPreflight.Outcome = { _, _ in .allowed }
        return try await KeychainAccessGate.withTaskOverrideForTesting(false) {
            try await KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting(stubPreflight) {
                try await MuseCredentials.$keychainReadOverrideForTesting.withValue(dataRead) {
                    try await operation()
                }
            }
        }
    }

    private func pluginResult(sourceLabel: String? = "oauth") -> ProviderPluginResult {
        let snapshot = UsageSnapshot(primary: nil, secondary: nil, extraRateWindows: nil, updatedAt: Date())
        return ProviderPluginResult(usage: snapshot, sourceLabel: sourceLabel, persist: [:])
    }

    @Test
    func `expired token retries once against the re-read credential`() async throws {
        let attempts = LockIsolated(0)
        let seenTokens = LockIsolated<[String]>([])
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            attempts.setValue(attempts.value + 1)
            return (errSecSuccess, attempts.value == 1 ? Self.stalePayload : Self.rotatedPayload)
        }
        let pluginResult = self.pluginResult(sourceLabel: "oauth+web")
        let usageFetcher: (String) async throws -> ProviderPluginResult = { token in
            seenTokens.setValue(seenTokens.value + [token])
            if token == "dca:fixture-stale" {
                throw ProviderFetchClassifiedError(kind: .authenticationExpired, message: "fixture")
            }
            return pluginResult
        }
        let context = ProviderCutoverTestSupport.context(environment: ["MUSE_AUTH_PATH": self.freshAuthPath()])
        let result = try await self.withDoubles(dataRead: dataRead) {
            try await MuseOAuthFetchStrategy().fetch(context, usageFetcher: usageFetcher)
        }
        #expect(result.sourceLabel == "oauth+web")
        #expect(seenTokens.value == ["dca:fixture-stale", "dca:fixture-rotated"])
        #expect(attempts.value == 2)
    }

    @Test
    func `persistently rejected token surfaces expired after one retry`() async throws {
        let attempts = LockIsolated(0)
        let seenTokens = LockIsolated<[String]>([])
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            attempts.setValue(attempts.value + 1)
            return (errSecSuccess, Self.stalePayload)
        }
        let usageFetcher: (String) async throws -> ProviderPluginResult = { token in
            seenTokens.setValue(seenTokens.value + [token])
            throw ProviderFetchClassifiedError(kind: .authenticationExpired, message: "fixture")
        }
        let context = ProviderCutoverTestSupport.context(environment: ["MUSE_AUTH_PATH": self.freshAuthPath()])
        let expected = ProviderFetchClassifiedError(kind: .authenticationExpired, message: "fixture")
        try await self.withDoubles(dataRead: dataRead) {
            await #expect(throws: expected) {
                try await MuseOAuthFetchStrategy().fetch(context, usageFetcher: usageFetcher)
            }
            #expect(seenTokens.value == ["dca:fixture-stale", "dca:fixture-stale"])
            #expect(attempts.value == 2)
            // The re-read credential was rejected too, so it must not linger in the cache to be
            // sent again (and rejected again) on the next refresh: the next resolution re-reads.
            #expect(MuseCredentials.cachedToken(
                environment: context.env,
                homeDirectory: FileManager.default.homeDirectoryForCurrentUser) == nil)
            _ = try MuseCredentials.accessToken(environment: context.env)
            #expect(attempts.value == 3)
        }
    }

    @Test
    func `non-authentication failures do not retry`() async throws {
        let attempts = LockIsolated(0)
        let seenTokens = LockIsolated<[String]>([])
        let dataRead: @Sendable ([String: Any]) -> (OSStatus, Data?) = { _ in
            attempts.setValue(attempts.value + 1)
            return (errSecSuccess, Self.stalePayload)
        }
        let usageFetcher: (String) async throws -> ProviderPluginResult = { token in
            seenTokens.setValue(seenTokens.value + [token])
            throw ProviderFetchClassifiedError(kind: .rateLimited, message: "fixture")
        }
        let context = ProviderCutoverTestSupport.context(environment: ["MUSE_AUTH_PATH": self.freshAuthPath()])
        let expected = ProviderFetchClassifiedError(kind: .rateLimited, message: "fixture")
        await #expect(throws: expected) {
            try await self.withDoubles(dataRead: dataRead) {
                try await MuseOAuthFetchStrategy().fetch(context, usageFetcher: usageFetcher)
            }
        }
        #expect(seenTokens.value == ["dca:fixture-stale"])
        #expect(attempts.value == 1)
    }
}
#endif
