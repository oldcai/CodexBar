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
