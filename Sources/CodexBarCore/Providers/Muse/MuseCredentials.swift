import Foundation
#if os(macOS)
import Security
#endif

/// Reads the Muse Code CLI login. Subscription usage is minted with the device-code
/// `dca:` access token, not a dashboard `LLM_` / Muse-minted `LLM|` inference key.
public enum MuseCredentials {
    public static let keychainService = "ai.meta.dev.credentials"
    public static let keychainAccount = "meta"
    public static let authPathEnvironmentKey = "MUSE_AUTH_PATH"

    private static let accessTokenPrefix = "dca:"

    public static func hasLogin(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) -> Bool
    {
        if self.authFileRecord(environment: environment, homeDirectory: homeDirectory) != nil {
            return true
        }
        if self.cachedToken(environment: environment, homeDirectory: homeDirectory) != nil {
            return true
        }
        return (try? self.keychainAccessToken(allowsPrompt: false)) != nil
    }

    public static func accessToken(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> String
    {
        let authFile = self.authFileRecord(environment: environment, homeDirectory: homeDirectory)
        if let token = authFile?.accessToken {
            return try self.requireAccessToken(token)
        }
        if let cached = self.cachedToken(environment: environment, homeDirectory: homeDirectory) {
            return cached
        }
        do {
            if let token = try self.keychainAccessToken(allowsPrompt: true) {
                self.storeCachedToken(token, environment: environment, homeDirectory: homeDirectory)
                return token
            }
        } catch MuseUsageError.keychainUnavailable {
            if authFile != nil { throw MuseUsageError.keychainUnavailable }
        }
        throw MuseUsageError.missingCredentials
    }

    /// In-memory cache of keychain-resolved device tokens, keyed by the resolved auth-file URL
    /// so distinct homes (and test fixtures) never share entries. The owning CLI rewrites its
    /// Keychain item on use, which resets the item ACL and wipes previously granted access;
    /// reusing a known-good token keeps refreshes working (and silent) until the API actually
    /// rejects it. Inline auth-file tokens are cheap file reads and always take precedence, so
    /// only keychain-resolved tokens are cached.
    private static let tokenCache = MuseTokenCache()

    static func cachedToken(environment: [String: String], homeDirectory: URL) -> String? {
        self.tokenCache.token(forKey: self.cacheKey(environment: environment, homeDirectory: homeDirectory))
    }

    static func invalidateCachedToken(environment: [String: String], homeDirectory: URL) {
        self.tokenCache.removeToken(forKey: self.cacheKey(environment: environment, homeDirectory: homeDirectory))
    }

    #if DEBUG
    static func resetTokenCacheForTesting() {
        self.tokenCache.removeAll()
    }
    #endif

    private static func cacheKey(environment: [String: String], homeDirectory: URL) -> String {
        self.authFileURL(environment: environment, homeDirectory: homeDirectory).absoluteString
    }

    private static func storeCachedToken(_ token: String, environment: [String: String], homeDirectory: URL) {
        self.tokenCache.setToken(token, forKey: self.cacheKey(environment: environment, homeDirectory: homeDirectory))
    }

    private final class MuseTokenCache: @unchecked Sendable {
        private let lock = NSLock()
        private var tokens: [String: String] = [:]

        func token(forKey key: String) -> String? {
            self.lock.withLock { self.tokens[key] }
        }

        func setToken(_ token: String, forKey key: String) {
            self.lock.withLock { self.tokens[key] = token }
        }

        func removeToken(forKey key: String) {
            self.lock.withLock { self.tokens[key] = nil }
        }

        func removeAll() {
            self.lock.withLock { self.tokens.removeAll() }
        }
    }

    static func accessToken(fromKeychainPayload data: Data) throws -> String {
        let payload: KeychainPayload
        do {
            payload = try JSONDecoder().decode(KeychainPayload.self, from: data)
        } catch {
            throw MuseUsageError.parseFailed("Muse Keychain payload is not valid JSON")
        }
        return try self.requireAccessToken(payload.accessToken)
    }

    static func authFileURL(
        environment: [String: String],
        homeDirectory: URL) -> URL
    {
        if let override = environment[self.authPathEnvironmentKey]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !override.isEmpty
        {
            return URL(fileURLWithPath: override)
        }
        return homeDirectory
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("muse", isDirectory: true)
            .appendingPathComponent("auth.json")
    }

    private static func authFileRecord(
        environment: [String: String],
        homeDirectory: URL) -> AuthFileRecord?
    {
        let url = self.authFileURL(environment: environment, homeDirectory: homeDirectory)
        guard let data = try? Data(contentsOf: url),
              let file = try? JSONDecoder().decode(AuthFile.self, from: data),
              let meta = file.providers?.meta
        else {
            return nil
        }
        let inlineToken = meta.accessToken?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let token = inlineToken.isEmpty ? nil : inlineToken
        let isOAuth = meta.mechanism?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "oauth"
        guard token != nil || isOAuth else { return nil }
        return AuthFileRecord(accessToken: token)
    }

    /// - Parameter allowsPrompt: False for availability probes, which must never prompt. True for
    ///   credential fetches, which defer to the ambient interaction context.
    private static func keychainAccessToken(allowsPrompt: Bool) throws -> String? {
        #if os(macOS)
        guard !KeychainAccessGate.isDisabled else {
            throw MuseUsageError.keychainUnavailable
        }
        // Requesting secret bytes can surface a legacy ACL prompt even when the query carries
        // `kSecUseAuthenticationUIFail`. Probe attributes and the item reference first, then ask
        // for data only when the decrypt ACL already trusts this exact executable without UI.
        // An explicit manual refresh may attempt one interactive read so the user can authorize
        // access; scheduled and menu-open refreshes always fail closed.
        switch KeychainAccessPreflight.checkGenericPassword(
            service: self.keychainService,
            account: self.keychainAccount)
        {
        case .allowed:
            return try self.readKeychainData(allowsPrompt: false)
        case .notFound:
            return nil
        case .interactionRequired, .temporarilyUnavailable:
            guard allowsPrompt, ProviderInteractionContext.current == .userInitiated else {
                throw MuseUsageError.keychainUnavailable
            }
            KeychainPromptHandler.notifyIfHandled(KeychainPromptContext(
                kind: .museToken,
                service: self.keychainService,
                account: self.keychainAccount))
            return try self.readKeychainData(allowsPrompt: true)
        case .failure:
            throw MuseUsageError.keychainUnavailable
        }
        #else
        return nil
        #endif
    }

    #if os(macOS)
    private static func readKeychainData(allowsPrompt: Bool) throws -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: self.keychainService,
            kSecAttrAccount as String: self.keychainAccount,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        if !allowsPrompt {
            KeychainNoUIQuery.apply(to: &query)
        }

        var result: AnyObject?
        let status = self.copyMatchingData(query: query, result: &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw MuseUsageError.parseFailed("Muse Keychain item was empty")
            }
            return try self.accessToken(fromKeychainPayload: data)
        case errSecItemNotFound:
            return nil
        case errSecInteractionNotAllowed, errSecAuthFailed, errSecNoAccessForItem:
            throw MuseUsageError.keychainUnavailable
        default:
            throw MuseUsageError.keychainUnavailable
        }
    }
    #endif

    #if os(macOS)
    private static func copyMatchingData(query: [String: Any], result: inout AnyObject?) -> OSStatus {
        #if DEBUG
        if let override = self.keychainDataReadOverrideForTesting {
            let (status, data) = override.read(query)
            result = data.map { $0 as NSData }
            return status
        }
        #endif
        return KeychainSecurity.copyMatching(query as CFDictionary, &result)
    }
    #endif

    #if DEBUG && os(macOS)
    final class KeychainDataReadOverrideStore: @unchecked Sendable {
        let read: ([String: Any]) -> (OSStatus, Data?)

        init(read: @escaping ([String: Any]) -> (OSStatus, Data?)) {
            self.read = read
        }
    }

    @TaskLocal private static var taskKeychainDataReadOverrideStore: KeychainDataReadOverrideStore?

    static var keychainDataReadOverrideForTesting: KeychainDataReadOverrideStore? {
        self.taskKeychainDataReadOverrideStore
    }

    static func withKeychainDataReadOverrideForTesting<T>(
        _ read: (([String: Any]) -> (OSStatus, Data?))?,
        operation: () throws -> T) rethrows -> T
    {
        try self.$taskKeychainDataReadOverrideStore.withValue(read.map(KeychainDataReadOverrideStore.init(read:))) {
            try operation()
        }
    }

    static func withKeychainDataReadOverrideForTesting<T>(
        _ read: (([String: Any]) -> (OSStatus, Data?))?,
        operation: () async throws -> T) async rethrows -> T
    {
        let store = read.map(KeychainDataReadOverrideStore.init(read:))
        return try await self.$taskKeychainDataReadOverrideStore.withValue(store) {
            try await operation()
        }
    }
    #endif

    private static func requireAccessToken(_ raw: String?) throws -> String {
        let token = raw?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !token.isEmpty else {
            throw MuseUsageError.invalidCredentials
        }
        guard token.hasPrefix(self.accessTokenPrefix) else {
            throw MuseUsageError.invalidCredentials
        }
        return token
    }

    private struct AuthFileRecord {
        let accessToken: String?
    }

    private struct AuthFile: Decodable {
        let providers: Providers?

        struct Providers: Decodable {
            let meta: Meta?
        }

        struct Meta: Decodable {
            let mechanism: String?
            let accessToken: String?

            enum CodingKeys: String, CodingKey {
                case mechanism
                case accessToken = "access_token"
            }
        }
    }

    private struct KeychainPayload: Decodable {
        let accessToken: String?

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
        }
    }
}
