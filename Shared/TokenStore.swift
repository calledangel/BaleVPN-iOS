import Foundation
import Security

enum TokenStore {
    private static func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Bundle.main.bundleIdentifier ?? "org.balevpn.ios",
            kSecAttrAccount as String: account
        ]
    }

    static func read(_ account: String = "bale-session") -> String? {
        var request = query(account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &value) == errSecSuccess,
              let data = value as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(_ token: String, account: String = "bale-session") -> Bool {
        var item = query(account)
        let data = Data(token.utf8)
        let updated = SecItemUpdate(
            item as CFDictionary, [kSecValueData as String: data] as CFDictionary
        )
        if updated == errSecSuccess { return true }
        guard updated == errSecItemNotFound else { return false }
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
    }

    static func remove(_ account: String = "bale-session") {
        SecItemDelete(query(account) as CFDictionary)
    }
}
