import Foundation
import Network
import OSLog
import SwiftUI
import UIKit
import UniformTypeIdentifiers

private let proxyLog = Logger(subsystem: Bundle.main.bundleIdentifier ?? "org.balevpn.ios", category: "Proxy")

@main
struct BaleVPNApp: App {
    var body: some Scene {
        WindowGroup { HomeView() }
    }
}

private struct AuthReply: Decodable, Sendable {
    let transaction: String?
    let token: String?
    let error: String?

    static func from(_ pointer: UnsafeMutablePointer<CChar>?) -> Self {
        guard let pointer else { return Self(transaction: nil, token: nil, error: "invalid_response") }
        defer { bale_free_string(pointer) }
        let data = Data(String(cString: pointer).utf8)
        return (try? JSONDecoder().decode(Self.self, from: data))
            ?? Self(transaction: nil, token: nil, error: "invalid_response")
    }
}

enum ProxyMethod: String, CaseIterable, Identifiable {
    case bale, flow, cloudflare, dnstt

    var showsNetwork: Bool { self == .cloudflare || self == .dnstt }

    var id: Self { self }
    var title: String {
        switch self {
        case .bale: "بله"
        case .flow: "FlowDriver"
        case .cloudflare: "Cloudflare"
        case .dnstt: "DNSTT"
        }
    }

    var profileAccount: String {
        switch self {
        case .bale: "bale-quic-identity"
        case .flow: "flow-driver-profile"
        case .cloudflare: "cloudflare-vless-profile"
        case .dnstt: "dnstt-ssh-profile"
        }
    }

    var profileInstructions: String {
        switch self {
        case .bale: "فایل پروفایل امن آیفون را وارد کن."
        case .flow: "فایل تنظیمات Drive و کلید مشترک را وارد کن."
        case .cloudflare: "لینک VLESS WebSocket TLS دامنه‌ات را جای‌گذاری کن."
        case .dnstt: "فایل پروفایل DNSTT و کلید حساب SSH را وارد کن."
        }
    }

    func validate(_ profile: UnsafePointer<CChar>) -> Bool {
        switch self {
        case .bale: bale_validate_tls_profile(profile)
        case .flow: flow_validate_profile(profile)
        case .cloudflare: cloudflare_validate(profile)
        case .dnstt: dnstt_validate(profile)
        }
    }
}

struct CloudflareScanUpdate: Codable, Sendable {
    struct Discovery: Codable, Sendable {
        let tcpFailures: Int
        let tlsFailures: Int
        let webSocketFailures: Int
    }

    struct Result: Codable, Identifiable, Sendable {
        let ip: String
        let successes: Int
        let attempts: Int
        let milliseconds: Int
        let mbps: Double
        let uploadMbps: Double?
        let uploadSuccesses: Int?
        let uploadAttempts: Int?
        let uploadSizesKiB: [Int]?
        let jitterMilliseconds: Int?
        let stage: String?
        var id: String { ip }

        var verified: Bool {
            guard successes > 0, successes == attempts else { return false }
            guard stage != nil else { return true }
            guard let uploadAttempts, uploadAttempts > 0 else { return false }
            return uploadSuccesses == uploadAttempts
        }

        var detail: String {
            if successes == 0 { return "WebSocket باز شد · دانلود کامل نشد" }
            let down = "دانلود \(successes)/\(attempts)"
            if let uploadAttempts, uploadAttempts > 0 {
                return down + " · آپلود \(uploadSuccesses ?? 0)/\(uploadAttempts)"
            }
            return stage == nil ? down + " · گزارش پیشین" : down + " · آزمون اولیه"
        }
    }

    let phase: String
    let done: Int
    let total: Int
    let reachable: Int
    let results: [Result]?
    let log: String?
    let discovery: Discovery?

    var status: String {
        switch phase {
        case "preparing": "در حال آماده‌کردن IPها"
        case "checking": "بررسی WebSocket · \(done) از \(total)"
        case "refining": "بررسی تکمیلی IPها · \(done) از \(total)"
        case "transfer": "تست دانلود از تونل · \(done) از \(total)"
        case "final": "آزمون نهایی دانلود و آپلود · \(done) از \(total)"
        case "finished": "تست \(total) IP انجام شد"
        default: "اسکن متوقف شد"
        }
    }
}

struct CloudflareScanArchive: Codable {
    let savedAt: Date
    let result: CloudflareScanUpdate
    let lines: [String]
    let recentIPs: [String]
    let network: CloudflareNetwork?

    static let file = URL.applicationSupportDirectory.appendingPathComponent("CloudflareScan.json")
    static let historyFile = URL.applicationSupportDirectory.appendingPathComponent("CloudflareHistory.json")
}

@MainActor
final class ProxyModel: ObservableObject {
    enum Status {
        case idle, connecting, ready, stopping
    }

    static let shared = ProxyModel()

    @Published var phone = ""
    @Published var code = ""
    @Published var peer = UserDefaults.standard.string(forKey: "bale-peer") ?? ""
    @Published private(set) var status: Status = .idle
    @Published private var connectionStage: Int32 = 0
    @Published private(set) var endpoint: String?
    @Published private(set) var backgroundTestRunning = false
    @Published private(set) var baleCheckingTraffic = false
    @Published private(set) var baleRetryPending = false
    @Published var method = ProxyMethod(rawValue: UserDefaults.standard.string(forKey: "proxy-method") ?? "") ?? .bale {
        didSet {
            UserDefaults.standard.set(method.rawValue, forKey: "proxy-method")
            resumeWhenActive = false
            resumePort = nil
            message = nil
        }
    }
    @Published var localPort = UserDefaults.standard.string(forKey: "proxy-port") ??
        (UserDefaults.standard.string(forKey: "bale-socks-port") ?? "1080") {
        didSet {
            UserDefaults.standard.set(localPort, forKey: "proxy-port")
            resumePort = nil
        }
    }
    @Published var portFallback = UserDefaults.standard.object(forKey: "proxy-port-fallback") as? Bool ?? true {
        didSet { UserDefaults.standard.set(portFallback, forKey: "proxy-port-fallback") }
    }
    @Published var autoResume = UserDefaults.standard.object(forKey: "proxy-auto-resume") as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(autoResume, forKey: "proxy-auto-resume")
            if !autoResume {
                resumeWhenActive = false
                cancelBaleRetry()
            }
        }
    }
    @Published private(set) var installedProfiles = Set(ProxyMethod.allCases.filter {
        TokenStore.read($0.profileAccount) != nil
    })
    @Published private(set) var scanRunning = false
    @Published private(set) var scanUpdate: CloudflareScanUpdate?
    @Published private(set) var selectedEdge: String?
    @Published private(set) var scanLog: [String] = []
    @Published private(set) var lastScanAt: Date?
    @Published private(set) var cloudflareTargets = UserDefaults.standard.string(forKey: "cloudflare-targets") ?? ""
    @Published private(set) var cloudflareNetwork: CloudflareNetwork?
    @Published private(set) var networkDetecting = false
    @Published private(set) var cloudflareHistory: [String: CloudflareScanArchive] = [:]
    private var recentCloudflareIPs: [String] = []
    private var scanNetwork: CloudflareNetwork?
    private var networkLookup: Task<Void, Never>?
    private var lastNetworkLookup: Date?
    private let networkMonitor = NWPathMonitor()
    private var lastNetworkPath: NWPath?
    private var scanID: UInt64 = 0
    @Published var dnsMode = DNSResolverMode(rawValue: UserDefaults.standard.string(forKey: "dns-mode") ?? "") ?? .automatic {
        didSet { UserDefaults.standard.set(dnsMode.rawValue, forKey: "dns-mode") }
    }
    @Published private(set) var dnsCustom = UserDefaults.standard.string(forKey: "dns-custom") ?? ""
    @Published private(set) var dnsTimeout = UInt16(clamping: UserDefaults.standard.object(forKey: "dns-timeout") as? Int ?? 15)
    @Published private(set) var dnsScanRunning = false
    @Published private(set) var dnsResults: [DNSResolverUpdate] = []
    @Published private(set) var dnsLog = (try? String(contentsOf: DNSLogFile.url, encoding: .utf8))
        .map { $0.components(separatedBy: "\n") } ?? []
    private var dnsScanDeep = false
    private var dnsVerifiedOnPath: String?
    private var dnsCustomCursor = UserDefaults.standard.integer(forKey: "dns-custom-cursor")
    private var dnsNextCursor: Int?
    @Published private(set) var activeDNSResolver: String?
    @Published private var systemDNSResolvers: [String] = []
    private var dnsScanID: UInt64 = 0
    private var connectionResolvers: [String] = []
    private var dnsWinners = UserDefaults.standard.dictionary(forKey: "dns-winners") as? [String: String] ?? [:]
    @Published var message: String?
    @Published var busy = false
    @Published var signedIn = TokenStore.read() != nil
    @Published var transaction: String?

    private var session: UInt64 = 0
    private var backgroundTask = UIBackgroundTaskIdentifier.invalid
    private var resumeWhenActive = false
    private var backgroundTestAdmitted = false
    private var reconnectAttempts = 0
    private var reconnectTask: Task<Void, Never>?
    private var activePort: UInt16?
    private var baleProbeTask: Task<Void, Never>?
    private var baleRetryTask: Task<Void, Never>?
    private var baleRetryAttempts = 0
    private var baleRetryPort: UInt16?
    private var baleRetryAfterStop = false
    private var balePortConflict = false
    private var baleHealthySince: ContinuousClock.Instant?
    private var resumePort: UInt16?
    private var testPort: UInt16?

    private init() {
        networkMonitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async { self?.cloudflarePathChanged(path) }
        }
        networkMonitor.start(queue: DispatchQueue(label: "BaleVPN.NetworkPath"))
        guard let profile = TokenStore.read(ProxyMethod.cloudflare.profileAccount) else { return }
        let decoder = JSONDecoder()
        if let data = try? Data(contentsOf: CloudflareScanArchive.historyFile),
           let history = try? decoder.decode([String: CloudflareScanArchive].self, from: data) {
            cloudflareHistory = history
        }
        if let data = try? Data(contentsOf: CloudflareScanArchive.file),
           let archive = try? decoder.decode(CloudflareScanArchive.self, from: data) {
            let key = archive.network?.key ?? "unknown"
            if archive.result.phase == "finished", cloudflareHistory[key] == nil {
                cloudflareHistory[key] = archive
            }
            showCloudflareArchive(archive)
        }
        if let host = URLComponents(string: profile.trimmingCharacters(in: .whitespacesAndNewlines))?.host,
           IPv4Address(host) != nil || IPv6Address(host) != nil {
            selectedEdge = host
        }
    }

    private func showCloudflareArchive(_ archive: CloudflareScanArchive?) {
        scanUpdate = archive?.result
        scanLog = archive?.lines ?? []
        lastScanAt = archive?.savedAt
        recentCloudflareIPs = archive?.recentIPs ?? []
    }

    private func cloudflarePathChanged(_ path: NWPath) {
        guard lastNetworkPath != path else { return }
        if lastNetworkPath != nil {
            if dnsScanRunning { stopDNSScan() }
            if method == .dnstt, status == .ready || status == .connecting {
                resumeWhenActive = autoResume
                if autoResume { resumePort = activePort }
                stopSession()
            }
            dnsResults.removeAll()
            dnsVerifiedOnPath = nil
            if scanRunning { stopCloudflareScan() }
            networkLookup?.cancel()
            networkLookup = nil
            cloudflareNetwork = nil
            lastNetworkLookup = nil
        }
        lastNetworkPath = path
        var buffer = [CChar](repeating: 0, count: 4096)
        buffer.withUnsafeMutableBufferPointer { bale_system_resolvers($0.baseAddress, $0.count) }
        systemDNSResolvers = String(cString: buffer).split(separator: ",").map(String.init).filter {
            $0.withCString(dnstt_validate_resolvers)
        }
        if method.showsNetwork { refreshCloudflareNetwork() }
    }

    func refreshCloudflareNetwork(force: Bool = false) {
        if !force {
            if networkLookup != nil { return }
            if let lastNetworkLookup, Date.now.timeIntervalSince(lastNetworkLookup) < 120 { return }
        }
        networkLookup?.cancel()
        networkDetecting = true
        networkLookup = Task {
            let previous = cloudflareNetwork
            let current = await CloudflareNetwork.detect(profile: TokenStore.read(ProxyMethod.cloudflare.profileAccount))
            guard !Task.isCancelled else { return }
            networkLookup = nil
            lastNetworkLookup = .now
            networkDetecting = false
            cloudflareNetwork = current
            if scanRunning, scanNetwork == nil {
                scanNetwork = current
            } else if !scanRunning, let current, previous?.key != current.key {
                let archive = cloudflareHistory[current.key] ?? (current.asn == nil ? cloudflareHistory["unknown"] : nil)
                showCloudflareArchive(archive)
            }
        }
    }

    func setCloudflareTargets(_ targets: CloudflareTargets) {
        cloudflareTargets = targets.canonical
        UserDefaults.standard.set(cloudflareTargets, forKey: "cloudflare-targets")
    }

    private func digits(_ value: String) -> String {
        value.compactMap(\.wholeNumberValue).filter { $0 < 10 }.map(String.init).joined()
    }

    func requestCode() async {
        guard !busy else { return }
        let number = digits(phone)
        guard (8...15).contains(number.count), !number.hasPrefix("0") else {
            message = "شماره را با پیش‌شمارهٔ کشور وارد کن، مثل ‎+98."
            return
        }
        busy = true
        message = nil
        defer { busy = false }
        let reply = await Task.detached {
            number.withCString { AuthReply.from(bale_request_code($0)) }
        }.value
        transaction = reply.transaction
        message = transaction == nil ? "ارسال کد از بله انجام نشد." : nil
    }

    func verifyCode() async {
        guard !busy, let transaction else { return }
        let otp = digits(code)
        guard (3...12).contains(otp.count) else {
            message = "کد دریافتی را وارد کن."
            return
        }
        busy = true
        message = nil
        defer { busy = false; code = "" }
        let reply = await Task.detached {
            transaction.withCString { request in
                otp.withCString { AuthReply.from(bale_verify_code(request, $0)) }
            }
        }.value
        guard let token = reply.token else {
            message = reply.error == "existing_account_required"
                ? "ورود با این کد تأیید نشد. از یک حساب موجود بله استفاده کن."
                : "بله کد ورود را تأیید نکرد."
            return
        }
        guard TokenStore.save(token) else {
            message = "ذخیرهٔ امن ورود ممکن نشد. مجوز Keychain را بررسی کن."
            return
        }
        signedIn = true
        self.transaction = nil
    }

    func connect() {
        baleRetryAttempts = 0
        baleRetryPort = nil
        _ = startConnection()
    }

    var canEdit: Bool {
        status == .idle && !backgroundTestRunning && !scanRunning && !dnsScanRunning && !baleRetryPending
    }

    private var customDNSResolvers: [String] {
        dnsCustom.split { $0.isWhitespace || $0 == "," }.map(String.init)
    }

    var dnsCandidates: [String] {
        switch dnsMode {
        case .manual: return Array(customDNSResolvers.prefix(1))
        case .automatic: return automaticDNSResolvers()
        }
    }

    private func automaticDNSResolvers() -> [String] {
        let remembered = cloudflareNetwork?.asn.flatMap { dnsWinners["AS\($0)"] }
        let network = [dnsVerifiedOnPath, remembered].compactMap { $0 } + systemDNSResolvers
        return dnsScanAddresses(network + customDNSResolvers + ["1.1.1.1:53", "8.8.8.8:53"], limit: 5)
    }

    func setDNSOptions(_ addresses: String, timeout: Int) -> Bool {
        guard canEdit, (5...45).contains(timeout), let normalized = DNSResolverText.normalize(addresses) else { return false }
        if dnsCustom != normalized {
            dnsCustomCursor = 0
            UserDefaults.standard.removeObject(forKey: "dns-custom-cursor")
        }
        dnsCustom = normalized
        dnsTimeout = UInt16(timeout)
        UserDefaults.standard.set(dnsCustom, forKey: "dns-custom")
        UserDefaults.standard.set(timeout, forKey: "dns-timeout")
        return true
    }

    func selectDNSResolver(_ address: String?) {
        guard let address, canEdit else { return }
        let list = [address] + customDNSResolvers.filter { $0 != address }
        guard setDNSOptions(list.prefix(64).joined(separator: "\n"), timeout: Int(dnsTimeout)) else { return }
        dnsMode = .manual
    }

    private func dnsScanAddresses(_ addresses: [String], limit: Int = 8) -> [String] {
        var seen = Set<String>()
        return Array(addresses.filter { seen.insert($0).inserted }.prefix(limit))
    }

    func scanDNS(scope: DNSScanScope, deep: Bool) {
        guard canEdit, let profile = TokenStore.read(ProxyMethod.dnstt.profileAccount) else { return }
        let controls = ["1.1.1.1:53", "8.8.8.8:53"]
        let candidates: [String]
        var nextCursor: Int?
        switch scope {
        case .network:
            candidates = dnsScanAddresses(dnsCandidates + systemDNSResolvers.prefix(2) + controls)
        case .iran:
            let catalog = DNSProvider.iran.compactMap { $0.addresses.first }
            candidates = dnsScanAddresses(catalog + systemDNSResolvers.prefix(1) + controls)
        case .custom:
            let custom = customDNSResolvers
            guard !custom.isEmpty else {
                message = "ابتدا یک DNS سفارشی اضافه کن یا فایل TXT را وارد کن."
                return
            }
            let start = max(0, dnsCustomCursor) % custom.count
            let end = min(start + 8, custom.count)
            candidates = Array(custom[start..<end])
            nextCursor = end % custom.count
        }
        guard !candidates.isEmpty else {
            message = "برای این حالت هیچ DNS معتبری در دسترس نیست."
            return
        }
        let id = profile.withCString { profile in
            candidates.joined(separator: ",").withCString {
                dnstt_scan_start(profile, $0, dnsTimeout, deep, dnsScanChanged)
            }
        }
        guard id != 0 else {
            message = "اسکن شروع نشد. تنظیمات DNS را بررسی کن."
            return
        }
        dnsScanID = id
        dnsNextCursor = nextCursor
        dnsScanDeep = deep
        dnsResults.removeAll()
        dnsLog = []
        let kind = deep ? "Deep" : "Quick"
        let name = cloudflareNetwork?.asn.map { "AS\($0)" } ?? "unknown ASN"
        addDNSLog("\(kind) scan · \(scope.rawValue) · \(name) · \(candidates.count) resolver(s).")
        if let nextCursor {
            addDNSLog("Custom list batch; next offset \(nextCursor) of \(customDNSResolvers.count).")
        }
        dnsScanRunning = true
        message = nil
    }

    private func addDNSLog(_ message: String) {
        let timestamp = Date.now.formatted(.iso8601.time(includingFractionalSeconds: false).timeSeparator(.colon))
        dnsLog.append("[\(timestamp)] \(message)")
    }

    func stopDNSScan() {
        guard dnsScanRunning else { return }
        dnstt_scan_stop(dnsScanID)
    }

    fileprivate func updateDNSScan(_ id: UInt64, _ update: DNSResolverUpdate) {
        guard dnsScanID == id, dnsScanRunning else { return }
        if let resolver = update.resolver {
            addDNSLog("\(resolver) · \(update.detail)")
            if let index = dnsResults.firstIndex(where: { $0.id == update.id }) {
                dnsResults[index] = update
            } else {
                dnsResults.append(update)
            }
            return
        }
        dnsScanRunning = false
        dnsScanID = 0
        let complete = update.status == "finished"
        let verified = dnsResults.filter(\.verified).count
        addDNSLog(complete ? "Scan complete. \(verified) verified resolver(s)." : "Scan stopped.")
        DNSLogFile.save(dnsLog)
        defer { dnsNextCursor = nil }
        guard complete else { return }
        if let next = dnsNextCursor {
            dnsCustomCursor = next
            UserDefaults.standard.set(next, forKey: "dns-custom-cursor")
        }
        dnsResults.sort {
            let lhs = $0.verified ? $0.milliseconds ?? Int.max : Int.max
            let rhs = $1.verified ? $1.milliseconds ?? Int.max : Int.max
            return lhs == rhs ? $0.id < $1.id : lhs < rhs
        }
        if let best = dnsResults.first(where: \.verified)?.resolver {
            if dnsScanDeep { dnsVerifiedOnPath = best }
            if let asn = cloudflareNetwork?.asn {
                dnsWinners["AS\(asn)"] = best
                UserDefaults.standard.set(dnsWinners, forKey: "dns-winners")
            }
        }
        if verified > 0 {
            message = "اسکن DNS کامل شد."
        } else if dnsResults.contains(where: { $0.status == "ssh_ready" }) {
            message = "ورود SSH موفق بود؛ تست عبور HTTPS کامل نشد."
        } else {
            message = "هیچ DNS به مرحلهٔ ورود موفق SSH نرسید. گزارش اسکن را ببین."
        }
    }

    private func startConnection() -> Bool {
        guard !busy, status == .idle, !scanRunning, !dnsScanRunning else { return false }
        guard let port = testPort ?? resumePort ?? UInt16(digits(localPort)), port > 0 else {
            message = "پورت محلی باید بین ۱ و ۶۵۵۳۵ باشد."
            return false
        }
        guard let profile = TokenStore.read(method.profileAccount) else {
            message = method.profileInstructions
            return false
        }

        let allowFallback = portFallback && !backgroundTestAdmitted
        let nextSession: UInt64
        switch method {
        case .bale:
            guard let token = TokenStore.read() else {
                signedIn = false
                message = "دوباره وارد حساب بله شو."
                return false
            }
            let target = digits(peer)
            guard let id = Int32(target), id > 0 else {
                message = "شناسهٔ عددی حساب بلهٔ سرور را وارد کن."
                return false
            }
            UserDefaults.standard.set(target, forKey: "bale-peer")
            nextSession = token.withCString { tokenPointer in
                target.withCString { peerPointer in
                    profile.withCString {
                        bale_start_socks(tokenPointer, peerPointer, port, allowFallback, $0, proxyStateChanged)
                    }
                }
            }
        case .flow:
            nextSession = profile.withCString { flow_start($0, port, allowFallback, proxyStateChanged) }
        case .cloudflare:
            nextSession = profile.withCString { cloudflare_start($0, port, allowFallback, proxyStateChanged) }
        case .dnstt:
            let resolvers = dnsCandidates
            guard !resolvers.isEmpty else {
                message = "یک آدرس DNS در تنظیمات دستی وارد کن."
                return false
            }
            connectionResolvers = resolvers
            nextSession = profile.withCString { profile in
                resolvers.joined(separator: ",").withCString {
                    dnstt_start(profile, $0, dnsTimeout, port, allowFallback, proxyStateChanged)
                }
            }
        }
        guard nextSession != 0 else {
            message = "راه‌اندازی ممکن نشد. پروفایل این روش را بررسی کن."
            return false
        }
        message = nil
        resumePort = nil
        connectionStage = 0
        session = nextSession
        status = .connecting
        return true
    }

    @discardableResult
    func importProfile(_ url: URL, for method: ProxyMethod) -> Bool {
        guard canEdit else { return false }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let file = try FileHandle(forReadingFrom: url)
            defer { try? file.close() }
            guard let data = try file.read(upToCount: 65_537), data.count <= 65_536,
                  let profile = String(data: data, encoding: .utf8) else {
                message = "این فایل پروفایل معتبر نیست."
                return false
            }
            return saveProfile(profile, for: method)
        } catch {
            message = "خواندن فایل پروفایل ممکن نشد."
            return false
        }
    }

    @discardableResult
    func saveProfile(_ profile: String, for method: ProxyMethod) -> Bool {
        guard canEdit else { return false }
        guard profile.utf8.count <= 65_536, !profile.contains("\0"),
              profile.withCString(method.validate) else {
            message = "این پروفایل معتبر \(method.title) نیست."
            return false
        }
        guard TokenStore.save(profile, account: method.profileAccount) else {
            message = "ذخیرهٔ پروفایل در Keychain ممکن نشد."
            return false
        }
        installedProfiles.insert(method)
        if method == .dnstt {
            dnsWinners.removeAll()
            dnsVerifiedOnPath = nil
            UserDefaults.standard.removeObject(forKey: "dns-winners")
            dnsResults.removeAll()
            if let settings = try? JSONDecoder().decode(DNSProfileSettings.self, from: Data(profile.utf8)),
               let timeout = settings.timeout_seconds {
                _ = setDNSOptions(dnsCustom, timeout: timeout)
            }
        }
        if method == .cloudflare {
            selectedEdge = nil
            scanUpdate = nil
            scanLog.removeAll()
            lastScanAt = nil
            recentCloudflareIPs.removeAll()
            cloudflareHistory.removeAll()
            try? FileManager.default.removeItem(at: CloudflareScanArchive.file)
            try? FileManager.default.removeItem(at: CloudflareScanArchive.historyFile)
        }
        message = "پروفایل \(method.title) ذخیره شد."
        return true
    }

    func scanCloudflare(deep: Bool) {
        guard canEdit, let profile = TokenStore.read(ProxyMethod.cloudflare.profileAccount) else { return }
        refreshCloudflareNetwork()
        scanNetwork = cloudflareNetwork
        let history = scanNetwork.flatMap { cloudflareHistory[$0.key] }
        let recent = (history?.recentIPs ?? (scanNetwork?.asn == nil ? recentCloudflareIPs : [])).joined(separator: ",")
        let id = profile.withCString { profile in
            recent.withCString { seeds in
                cloudflareTargets.withCString { targets in
                    cloudflare_scan_start(profile, seeds, targets, deep, cloudflareScanChanged)
                }
            }
        }
        guard id != 0 else {
            message = "اسکن Cloudflare شروع نشد."
            return
        }
        scanUpdate = nil
        scanLog.removeAll()
        scanID = id
        scanRunning = true
        message = nil
    }

    func stopCloudflareScan() {
        guard scanID != 0 else { return }
        cloudflare_scan_stop(scanID)
    }

    fileprivate func update(scan id: UInt64, result: CloudflareScanUpdate) {
        guard scanID == id else { return }
        scanUpdate = result
        if let line = result.log {
            let time = Date.now.formatted(Date.FormatStyle().hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits).locale(Locale(identifier: "en_GB")))
            scanLog.append("[\(time)] \(line)")
        }
        if result.phase == "finished" || result.phase == "cancelled" {
            scanID = 0
            scanRunning = false
            saveCloudflareScan(result)
        }
    }

    private func saveCloudflareScan(_ result: CloudflareScanUpdate) {
        let network = scanNetwork?.forHistory()
        scanNetwork = nil
        let key = network?.key ?? "unknown"
        if let asn = network?.asn {
            scanLog.insert("Network: AS\(asn) · \(network?.name ?? "unknown")", at: 0)
        }
        let verified = result.results?.filter(\.verified).map(\.ip) ?? []
        let previous = cloudflareHistory[key]?.recentIPs ?? []
        var seen = Set<String>()
        recentCloudflareIPs = Array((verified + previous).filter { seen.insert($0).inserted }.prefix(5))
        let savedAt = Date.now
        lastScanAt = savedAt
        let archive = CloudflareScanArchive(savedAt: savedAt, result: result, lines: scanLog, recentIPs: recentCloudflareIPs, network: network)
        do {
            let file = CloudflareScanArchive.file
            let encoder = JSONEncoder()
            let protection: Data.WritingOptions = [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try encoder.encode(archive).write(to: file, options: protection)
            if result.phase == "finished" {
                cloudflareHistory[key] = archive
                try encoder.encode(cloudflareHistory).write(to: CloudflareScanArchive.historyFile, options: protection)
            }
        } catch {
            message = "ذخیرهٔ آخرین لاگ روی آیفون ممکن نشد."
        }
    }

    func selectCloudflareEdge(_ ip: String) {
        guard canEdit, let profile = TokenStore.read(ProxyMethod.cloudflare.profileAccount) else { return }
        let link = profile.withCString { raw in
            ip.withCString { address in
                cloudflareTargets.withCString { cloudflare_link_for_ip(raw, address, $0) }
            }
        }
        guard let link else {
            message = "انتخاب این IP ممکن نشد."
            return
        }
        defer { cloudflare_free(link) }
        guard TokenStore.save(String(cString: link), account: ProxyMethod.cloudflare.profileAccount) else {
            message = "ذخیرهٔ IP ممکن نشد."
            return
        }
        selectedEdge = ip
        resumePort = nil
        message = "این IP برای اتصال Cloudflare انتخاب شد."
    }

#if DEBUG
    func importStagedProfiles() {
        guard let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first else { return }
        for method in ProxyMethod.allCases {
            let url = library.appendingPathComponent("Application Support/\(method.rawValue)-profile-import.json")
            if FileManager.default.fileExists(atPath: url.path), importProfile(url, for: method) {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }
#endif

    func disconnect() {
        cancelBaleRetry()
        stopBaleTrafficCheck()
        baleRetryPort = nil
        resumeWhenActive = false
        resumePort = nil
        if #available(iOS 26.0, *), backgroundTestRunning {
            BackgroundProxyTest.shared.finish("تست را متوقف کردی.")
        }
        stopSession()
    }

    @available(iOS 26.0, *)
    func testInBackground(length: BackgroundProxyTest.RunLength) {
        guard status == .ready, let activePort, !backgroundTestRunning else { return }
        testPort = activePort
        backgroundTestRunning = BackgroundProxyTest.shared.start(
            port: activePort,
            length: length,
            onBegin: { [weak self] in
                self?.stopBaleTrafficCheck()
                self?.backgroundTestAdmitted = true
                self?.reconnectAttempts = 0
                self?.endBackgroundTask()
                self?.message = "تست شروع شد. حالا می‌توانی به اپ دیگری بروی یا گوشی را قفل کنی."
            },
            onTrafficFailure: method == .bale ? { [weak self] in
                guard let self, self.autoResume, self.status == .ready else { return }
                self.baleRetryAfterStop = true
                self.stopSession()
            } : nil,
            onFinish: { [weak self] result, admitted in
                guard let self else { return }
                self.backgroundTestRunning = false
                self.backgroundTestAdmitted = false
                self.testPort = nil
                self.reconnectTask?.cancel()
                self.reconnectTask = nil
                if admitted { self.stopSession() }
                self.message = result
            }
        )
        if !backgroundTestRunning { testPort = nil }
        message = backgroundTestRunning ? "در انتظار شروع تست از طرف iOS…" : "ثبت تست پس‌زمینه ممکن نشد."
    }

    private func stopSession() {
        guard session != 0, status != .stopping else { return }
        stopBaleTrafficCheck()
        status = .stopping
        switch method {
        case .bale: bale_stop(session)
        case .flow, .cloudflare, .dnstt: flow_stop(session)
        }
    }

    func sceneChanged(_ phase: ScenePhase) {
        if phase == .background {
            stopBaleTrafficCheck()
            if baleRetryPending {
                cancelBaleRetry()
                resumeWhenActive = autoResume
                resumePort = baleRetryPort
            }
        }
        if phase == .background, scanRunning { stopCloudflareScan() }
        if phase == .background, dnsScanRunning { stopDNSScan() }
        if phase == .background, session != 0, !backgroundTestAdmitted, backgroundTask == .invalid {
            backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "BaleVPN proxy session") {
                [weak self] in self?.expireBackgroundTask()
            }
        } else if phase == .active {
            if method.showsNetwork { refreshCloudflareNetwork() }
            endBackgroundTask()
            resumeIfNeeded()
            if let activePort { startBaleTrafficCheck(port: activePort) }
        }
    }

    private func resumeIfNeeded() {
        guard resumeWhenActive, status == .idle, UIApplication.shared.applicationState == .active else { return }
        resumeWhenActive = false
        _ = startConnection()
    }

    private func expireBackgroundTask() {
        proxyLog.notice("BaleVPN lifecycle background time expired")
        if status == .connecting || status == .ready {
            resumeWhenActive = autoResume
            resumePort = autoResume ? activePort : nil
            message = autoResume
                ? "مهلت iOS تمام شد. با برگشتن به اپ اتصال دوباره برقرار می‌شود."
                : "مهلت اجرای پس‌زمینهٔ iOS تمام شد."
            stopSession()
        }
        endBackgroundTask()
    }

    private func endBackgroundTask() {
        guard backgroundTask != .invalid else { return }
        let task = backgroundTask
        backgroundTask = .invalid
        UIApplication.shared.endBackgroundTask(task)
    }

    func checkBaleTrafficNow() {
        guard method == .bale, status == .ready, !baleCheckingTraffic,
              !backgroundTestRunning, let activePort else { return }
        stopBaleTrafficCheck()
        startBaleTrafficCheck(port: activePort)
    }

    private func startBaleTrafficCheck(port: UInt16) {
        guard #available(iOS 17.0, *), method == .bale, session != 0,
              baleProbeTask == nil, !backgroundTestAdmitted,
              UIApplication.shared.applicationState != .background,
              status == .connecting || status == .ready else { return }
        let id = session
        baleProbeTask = Task {
            while !Task.isCancelled, session == id {
                baleCheckingTraffic = true
                let first = await ProxyHTTPSProbe.succeeds(port: port, url: ProxyHTTPSProbe.primary)
                guard !Task.isCancelled, session == id else { return }
                var healthy = first
                if !healthy {
                    healthy = await ProxyHTTPSProbe.succeeds(port: port, url: ProxyHTTPSProbe.secondary)
                }
                guard !Task.isCancelled, session == id else { return }
                baleCheckingTraffic = false
                proxyLog.notice("BaleVPN HTTPS first=\(first, privacy: .public) verified=\(healthy, privacy: .public)")
                if !healthy {
                    baleHealthySince = nil
                    baleRetryAfterStop = true
                    stopSession()
                    return
                }
                let now = ContinuousClock.now
                if let since = baleHealthySince, since.duration(to: now) >= .seconds(120) {
                    baleRetryAttempts = 0
                }
                if baleHealthySince == nil { baleHealthySince = now }
                if status == .connecting {
                    ready(port: port, portConflict: balePortConflict)
                }
                do {
                    try await Task.sleep(for: .seconds(60), tolerance: .seconds(5))
                } catch {
                    return
                }
            }
        }
    }

    private func stopBaleTrafficCheck() {
        baleProbeTask?.cancel()
        baleProbeTask = nil
        baleCheckingTraffic = false
    }

    private func cancelBaleRetry() {
        baleRetryTask?.cancel()
        baleRetryTask = nil
        baleRetryPending = false
        baleRetryAfterStop = false
    }

    private func retryBale(port: UInt16?) -> Bool {
        guard autoResume, baleRetryAttempts < 2 else { return false }
        baleRetryPort = port ?? baleRetryPort
        if UIApplication.shared.applicationState != .active {
            resumeWhenActive = true
            resumePort = baleRetryPort
            return true
        }
        baleRetryAttempts += 1
        let delay = baleRetryAttempts == 1 ? 3 : 10
        baleRetryPending = true
        message = "در حال اتصال دوباره به بله · تلاش \(baleRetryAttempts) از ۲"
        baleRetryTask = Task {
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return
            }
            baleRetryTask = nil
            baleRetryPending = false
            resumePort = baleRetryPort
            guard UIApplication.shared.applicationState == .active else {
                resumeWhenActive = autoResume
                return
            }
            if !startConnection() { resumePort = nil }
        }
        return true
    }

    private func ready(port: UInt16, portConflict: Bool) {
        endpoint = "127.0.0.1:\(port)"
        activePort = port
        status = .ready
        if #available(iOS 26.0, *), backgroundTestAdmitted {
            BackgroundProxyTest.shared.updatePort(port)
            if reconnectAttempts > 0 {
                message = "پروکسی دوباره متصل شد."
            }
        }
        if portConflict {
            message = "پورت قبلی اشغال است. آدرس جدید را از بالا کپی کن."
        }
    }

    fileprivate func update(session id: UInt64, state: Int32, port: UInt16, errorNumber: Int32) {
        guard session == id else { return }
        proxyLog.notice("BaleVPN SOCKS state=\(state, privacy: .public) port=\(port, privacy: .public) errno=\(errorNumber, privacy: .public)")
        if (20..<28).contains(state) {
            let index = Int(state - 20)
            if method == .dnstt, status == .connecting || status == .ready,
               connectionResolvers.indices.contains(index) {
                activeDNSResolver = connectionResolvers[index]
            }
            return
        }
        if (10...15).contains(state) {
            if status == .connecting { connectionStage = max(connectionStage, state) }
            return
        }
        if state == 1 {
            guard status == .connecting else { return }
            if #available(iOS 17.0, *), method == .bale, !backgroundTestAdmitted {
                activePort = port
                balePortConflict = errorNumber != 0
                connectionStage = 17
                startBaleTrafficCheck(port: port)
            } else {
                ready(port: port, portConflict: errorNumber != 0)
            }
            return
        }
        let wasStopping = status == .stopping
        let previousPort = activePort
        let baleTrafficFailed = baleRetryAfterStop
        baleRetryAfterStop = false
        stopBaleTrafficCheck()
        baleHealthySince = nil
        if status == .ready, autoResume, !backgroundTestRunning, UIApplication.shared.applicationState == .background {
            resumeWhenActive = true
            resumePort = activePort
        }
        session = 0
        endpoint = nil
        activeDNSResolver = nil
        activePort = nil
        status = .idle
        endBackgroundTask()
        if #available(iOS 26.0, *), backgroundTestRunning {
            if backgroundTestAdmitted, !wasStopping || baleTrafficFailed, reconnectAttempts < 2 {
                BackgroundProxyTest.shared.updatePort(nil)
                reconnectAttempts += 1
                let delay = reconnectAttempts * 3
                message = "ارتباط قطع شد. در حال تلاش برای اتصال دوباره…"
                reconnectTask = Task {
                    do {
                        try await Task.sleep(for: .seconds(delay))
                    } catch {
                        return
                    }
                    reconnectTask = nil
                    if !startConnection() {
                        BackgroundProxyTest.shared.finish("اتصال دوباره ممکن نشد.")
                    }
                }
                return
            }
            BackgroundProxyTest.shared.finish("پروکسی در حین تست قطع شد.")
            return
        }
        if resumeWhenActive {
            resumeIfNeeded()
            return
        }
        if method == .bale, baleTrafficFailed || (!wasStopping && (state == -1 || state == -3 || state == -5 || state == 2)) {
            if retryBale(port: previousPort) { return }
            if baleTrafficFailed {
                message = "از دو مقصد HTTPS در تونل بله پاسخ نرسید."
                return
            }
        }
        guard !wasStopping else { return }
        message = switch state {
        case -1: "ارتباط با بله برقرار نشد."
        case -2: "تماس با حساب سرور برقرار نشد."
        case -3: "اتاق تماس آماده نشد یا حساب آلمان به آن نپیوست."
        case -4:
            errorNumber == 0 ? "ساخت پروکسی محلی ناموفق بود."
                : "پورت محلی باز نشد (خطای سیستم \(errorNumber))."
        case -5: "مسیر داده یا احراز هویت دوطرفه آماده نشد."
        case -6: "دسترسی به پوشهٔ Drive تأیید نشد. پروفایل و مجوز پوشه را بررسی کن."
        case -7: "مسیر WebSocket دامنه از این شبکه باز نشد."
        case -8: "تونل DNSTT پاسخ نداد. اسکن عمیق را بزن تا مرحلهٔ خطا مشخص شود."
        case -9: "کلید سرور SSH با پروفایل هم‌خوان نیست."
        case -10: "ورود SSH ناموفق بود. پروفایل حساب تونل را بررسی کن."
        default: "ارتباط با سرور قطع شد."
        }
    }

    func signOut() {
        disconnect()
        TokenStore.remove()
        signedIn = false
        transaction = nil
    }

    var statusLabel: String {
        switch status {
        case .idle: baleRetryPending ? "در انتظار تلاش دوباره" : "خاموش"
        case .connecting:
            switch connectionStage {
            case 10: "در حال برقراری تماس"
            case 11: "در انتظار اتاق تماس"
            case 12: "در حال راه‌اندازی مسیر داده"
            case 13: "در حال بررسی دسترسی Drive"
            case 14: "در حال بررسی WebSocket دامنه"
            case 15: "در حال بررسی DNS و ورود SSH"
            case 17: "در حال بررسی عبور ترافیک"
            default: method == .bale ? "در حال اتصال به بله" : "در حال اتصال"
            }
        case .ready:
            if method == .bale, !backgroundTestAdmitted, #available(iOS 17.0, *) {
                baleCheckingTraffic ? "در حال بررسی عبور ترافیک" : "عبور ترافیک تأیید شد"
            } else {
                "پورت محلی آماده است"
            }
        case .stopping: "در حال قطع"
        }
    }
}

private func proxyStateChanged(_ session: UInt64, _ state: Int32, _ port: UInt16, _ errorNumber: Int32) {
    Task { @MainActor in
        ProxyModel.shared.update(session: session, state: state, port: port, errorNumber: errorNumber)
    }
}

private struct DNSProfileSettings: Decodable {
    let timeout_seconds: Int?
}

private func dnsScanChanged(_ id: UInt64, _ payload: UnsafePointer<CChar>?) {
    guard let payload,
          let update = try? JSONDecoder().decode(DNSResolverUpdate.self, from: Data(String(cString: payload).utf8))
    else { return }
    DispatchQueue.main.async {
        ProxyModel.shared.updateDNSScan(id, update)
    }
}

private func cloudflareScanChanged(_ scan: UInt64, _ payload: UnsafePointer<CChar>?) {
    guard let payload,
          let update = try? JSONDecoder().decode(CloudflareScanUpdate.self, from: Data(String(cString: payload).utf8))
    else { return }
    DispatchQueue.main.async {
        ProxyModel.shared.update(scan: scan, result: update)
    }
}

struct HomeView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = ProxyModel.shared
    @State private var useLongSession = true
    @State private var copiedEndpoint = false
    @State private var copiedRule = false
    @State private var importingProfile = false
    @State private var deepCloudflareScan = false
    @State private var editingCloudflareTargets = false
    @State private var showingCloudflareHistory = false
    @State private var showPreliminaryCloudflare = false
    @State private var showCloudflareLog = true
    @State private var followCloudflareLog = true
    @State private var profileMethod = ProxyMethod.bale

    private let directRule = "DOMAIN-SUFFIX,bale.ai,DIRECT"
    private let accent = Color(red: 0.03, green: 0.44, blue: 0.43)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header
                    methodCard
                    if model.method == .bale && !model.signedIn {
                        loginCard
                    } else {
                        connectionCard
                        if #available(iOS 26.0, *), model.endpoint != nil || model.backgroundTestRunning {
                            sessionCard
                        }
                    }
                    profileCard
                    if model.method == .cloudflare, model.installedProfiles.contains(.cloudflare) {
                        cloudflareNetworkCard
                        cloudflareScannerCard
                    }
                    if model.method == .dnstt {
                        cloudflareNetworkCard
                        card { DNSResolverCard(model: model) }
                    }
                    optionsCard
                    if model.method == .bale {
                        routingCard
                        if model.signedIn {
                            Button("خروج از حساب", role: .destructive) { model.signOut() }
                                .font(.footnote)
                                .padding(.horizontal, 4)
                        }
                    }
                    if let message = model.message {
                        Text(message)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)
                    }
                }
                .frame(maxWidth: 500)
                .padding(18)
                .frame(maxWidth: .infinity)
            }
            .scrollDismissesKeyboard(.interactively)
            .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
            .disabled(model.busy)
            .toolbar(.hidden, for: .navigationBar)
        }
        .tint(accent)
#if DEBUG
        .task { model.importStagedProfiles() }
#endif
        .environment(\.layoutDirection, .rightToLeft)
        .onChange(of: scenePhase) { phase in model.sceneChanged(phase) }
        .task(id: model.method) {
            if model.method.showsNetwork { model.refreshCloudflareNetwork() }
        }
        .sheet(isPresented: $editingCloudflareTargets) {
            CloudflareTargetsEditor(text: model.cloudflareTargets, save: model.setCloudflareTargets)
                .tint(accent)
        }
        .sheet(isPresented: $showingCloudflareHistory) {
            cloudflareHistorySheet
                .tint(accent)
        }
        .onChange(of: model.endpoint) { _ in copiedEndpoint = false }
        .fileImporter(isPresented: $importingProfile, allowedContentTypes: profileMethod == .cloudflare ? [.plainText] : [.json]) { result in
            if case .success(let url) = result { model.importProfile(url, for: profileMethod) }
        }
    }

    private var header: some View {
        HStack(spacing: 13) {
            Image("BaleMark")
                .resizable()
                .scaledToFit()
                .frame(width: 58, height: 58)
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("BaleVPN").font(.title2.bold())
                Text("پروکسی محلی SOCKS5")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.vertical, 6)
    }

    private var methodCard: some View {
        card {
            Picker("روش اتصال", selection: $model.method) {
                ForEach(ProxyMethod.allCases) { method in
                    Text(method.title).tag(method)
                }
            }
            .pickerStyle(.segmented)
            .disabled(!model.canEdit)
        }
    }

    private var connectionCard: some View {
        card {
            HStack {
                Text("اتصال").font(.headline)
                Spacer()
                Label(
                    model.backgroundTestRunning && model.status == .idle ? "در حال اتصال دوباره" : model.statusLabel,
                    systemImage: model.status == .ready ? "checkmark.circle.fill" : "circle"
                )
                .font(.footnote.weight(.semibold))
                .foregroundStyle(model.status == .ready ? accent : Color.secondary)
            }
            if model.method == .bale {
                field("شناسهٔ عددی حساب سرور", text: $model.peer, keyboard: .numberPad)
                    .disabled(!model.canEdit)
            }
            if let endpoint = model.endpoint {
                HStack {
                    Text(endpoint).font(.callout.monospacedDigit())
                        .environment(\.layoutDirection, .leftToRight)
                        .textSelection(.enabled)
                    Spacer()
                    Button(copiedEndpoint ? "کپی شد" : "کپی آدرس") {
                        UIPasteboard.general.string = endpoint
                        copiedEndpoint = true
                    }
                    .buttonStyle(.bordered)
                }
            }
            if #available(iOS 17.0, *), model.method == .bale, model.status == .ready, !model.backgroundTestRunning {
                Button("بررسی عبور ترافیک", systemImage: "waveform.path") { model.checkBaleTrafficNow() }
                    .buttonStyle(.bordered)
                    .disabled(model.baleCheckingTraffic)
            }
            if model.status == .idle && !model.backgroundTestRunning && !model.baleRetryPending {
                Button { model.connect() } label: {
                    Label("شروع پروکسی", systemImage: "power")
                        .frame(maxWidth: .infinity, minHeight: 28)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.scanRunning)
            } else {
                Button(role: .destructive) { model.disconnect() } label: {
                    Label("قطع اتصال", systemImage: "stop.circle")
                        .frame(maxWidth: .infinity, minHeight: 28)
                }
                .buttonStyle(.bordered)
                .disabled(model.status == .stopping)
            }
        }
    }

    @available(iOS 26.0, *)
    private var sessionCard: some View {
        card {
            Label("نشست پس‌زمینه", systemImage: "clock")
                .font(.headline)
            if model.backgroundTestRunning {
                Text("نشست فعال است").font(.callout).foregroundStyle(.secondary)
            } else {
                Picker("مدت نشست", selection: $useLongSession) {
                    Text("۵ دقیقه").tag(false)
                    Text("۱ ساعت").tag(true)
                }
                .pickerStyle(.segmented)
                Button("شروع نشست پس‌زمینه") {
                    model.testInBackground(length: useLongSession ? .oneHour : .fiveMinutes)
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private var routingCard: some View {
        card {
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 10) {
                    Text("در Shadowrocket حالت Global Routing را روی Config بگذار. قانون زیر را بالای بخش Rule تنظیمات فعال اضافه کن.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(directRule)
                        .font(.footnote.monospaced())
                        .environment(\.layoutDirection, .leftToRight)
                        .textSelection(.enabled)
                    Button(copiedRule ? "قانون کپی شد" : "کپی قانون مسیر مستقیم") {
                        UIPasteboard.general.string = directRule
                        copiedRule = true
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.top, 10)
            } label: {
                Label("مسیر بله در Shadowrocket", systemImage: "arrow.triangle.branch")
                    .font(.headline)
            }
        }
    }

    private var profileCard: some View {
        card {
            let installed = model.installedProfiles.contains(model.method)
            Label(model.method == .bale ? "احراز هویت دوطرفه" : "پروفایل \(model.method.title)", systemImage: "lock.shield")
                .font(.headline)
            Text(installed ? "پروفایل در Keychain ذخیره شده"
                 : model.method.profileInstructions)
                .font(.footnote)
                .foregroundStyle(.secondary)
            if model.method == .cloudflare {
                PasteButton(payloadType: String.self) { links in
                    if let link = links.first { model.saveProfile(link, for: .cloudflare) }
                }
                .disabled(!model.canEdit)
            }
            Button(installed ? "جایگزینی پروفایل" : "واردکردن پروفایل") {
                profileMethod = model.method
                importingProfile = true
            }
            .buttonStyle(.bordered)
            .disabled(!model.canEdit)
        }
    }

    private var cloudflareNetworkCard: some View {
        card {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Label("شبکهٔ فعلی", systemImage: "network").font(.headline)
                    if let network = model.cloudflareNetwork {
                        Text(network.name).font(.subheadline.weight(.semibold))
                        HStack(spacing: 8) {
                            Text(network.address).font(.footnote.monospacedDigit()).textSelection(.enabled)
                            if let asn = network.asn {
                                Text("AS\(asn)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            }
                        }
                        .environment(\.layoutDirection, .leftToRight)
                    } else if model.networkDetecting {
                        Text("در حال شناسایی IP عمومی").font(.footnote).foregroundStyle(.secondary)
                    } else {
                        Text("IP عمومی شناسایی نشد").font(.footnote).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if model.networkDetecting {
                    ProgressView().controlSize(.small)
                } else {
                    Button {
                        model.refreshCloudflareNetwork(force: true)
                    } label: {
                        Image(systemName: "arrow.clockwise").frame(width: 36, height: 36)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityLabel("به‌روزرسانی شبکه")
                }
            }
            if model.method == .cloudflare, !model.cloudflareHistory.isEmpty {
                Button { showingCloudflareHistory = true } label: {
                    Label("تاریخچهٔ اپراتورها", systemImage: "clock.arrow.circlepath")
                }
                .buttonStyle(.borderless)
                .font(.footnote.weight(.semibold))
            }
        }
    }

    private var cloudflareHistorySheet: some View {
        NavigationStack {
            List {
                ForEach(model.cloudflareHistory.values.sorted { $0.savedAt > $1.savedAt }, id: \.savedAt) { archive in
                    NavigationLink {
                        List {
                            ForEach(archive.result.results ?? []) { result in
                                CloudflareResultRow(result: result,
                                    winner: result.verified && result.ip == archive.result.results?.first?.ip,
                                    selected: false)
                            }
                        }
                        .navigationTitle(archive.network?.name ?? "شبکهٔ شناسایی‌نشده")
                        .navigationBarTitleDisplayMode(.inline)
                    } label: {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(archive.network?.name ?? "شبکهٔ شناسایی‌نشده").font(.headline)
                            if let best = archive.result.results?.first(where: \.verified) {
                                Text(best.ip).font(.footnote.monospacedDigit())
                                    .environment(\.layoutDirection, .leftToRight)
                            }
                            Text(archive.savedAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("تاریخچهٔ اپراتورها")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("بستن") { showingCloudflareHistory = false }
                }
            }
        }
        .environment(\.layoutDirection, .rightToLeft)
    }

    private var cloudflareScannerCard: some View {
        card {
            Label("اسکن IPهای Cloudflare", systemImage: "antenna.radiowaves.left.and.right").font(.headline)
            Button { editingCloudflareTargets = true } label: {
                HStack {
                    Label("IP و زیرشبکهٔ سفارشی", systemImage: "plus.circle")
                    Spacer()
                    if let targets = CloudflareTargets(model.cloudflareTargets), targets.ips + targets.subnets > 0 {
                        Text("\(targets.ips + targets.subnets)").monospacedDigit()
                    }
                }
            }
            .buttonStyle(.bordered)
            .disabled(!model.canEdit)
            Picker("حالت اسکن", selection: $deepCloudflareScan) {
                Text("سریع").tag(false)
                Text("دقیق").tag(true)
            }
            .pickerStyle(.segmented)
            .disabled(!model.canEdit)
            if model.scanRunning {
                Button("توقف اسکن", role: .destructive) { model.stopCloudflareScan() }
                    .buttonStyle(.bordered)
            } else {
                Button("اسکن با کانفیگ من") {
                    showCloudflareLog = true
                    followCloudflareLog = true
                    model.scanCloudflare(deep: deepCloudflareScan)
                }
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.canEdit)
            }
            if let scan = model.scanUpdate {
                Text(scan.status).font(.footnote).foregroundStyle(.secondary)
                if let lastScanAt = model.lastScanAt, !model.scanRunning {
                    Text("آخرین اسکن · \(lastScanAt.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if model.scanRunning && scan.total > 0 {
                    ProgressView(value: Double(scan.done), total: Double(scan.total))
                }
                if let results = scan.results, !results.isEmpty {
                    let verified = results.filter(\.verified)
                    let remaining = results.filter { !$0.verified }
                    ForEach(verified) { result in
                        cloudflareResult(result, winner: verified.first?.ip == result.ip)
                    }
                    let bestDownload = verified.isEmpty ? remaining.filter {
                        $0.stage == "final" && $0.successes == $0.attempts
                    }.min { $0.milliseconds < $1.milliseconds } : nil
                    if let bestDownload {
                        Text("بهترین دانلود · نتیجهٔ آپلود ناقص است")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.secondary)
                        cloudflareResult(bestDownload, winner: false)
                    }
                    let otherResults = remaining.filter { $0.ip != bestDownload?.ip }
                    if !otherResults.isEmpty {
                        DisclosureGroup(isExpanded: $showPreliminaryCloudflare) {
                            LazyVStack(spacing: 8) {
                                ForEach(otherResults) { result in
                                    cloudflareResult(result, winner: false)
                                }
                            }
                            .padding(.top, 8)
                        } label: {
                            Text("\(otherResults.count) نتیجهٔ اولیه یا ناقص").font(.footnote.weight(.semibold))
                        }
                    }
                } else if scan.phase == "finished" {
                    Text("هیچ IP نمونه روی این شبکه WebSocket را باز نکرد.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if let discovery = scan.discovery {
                        Text("تلاش‌های ناموفق · TCP: \(discovery.tcpFailures) · TLS: \(discovery.tlsFailures) · WebSocket: \(discovery.webSocketFailures)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if !model.scanLog.isEmpty {
                cloudflareLog
            }
        }
    }

    private func cloudflareResult(_ result: CloudflareScanUpdate.Result, winner: Bool) -> some View {
        Button {
            model.selectCloudflareEdge(result.ip)
        } label: {
            CloudflareResultRow(result: result, winner: winner, selected: model.selectedEdge == result.ip)
        }
        .buttonStyle(.bordered)
        .disabled(!model.canEdit)
        .contextMenu {
            Button { UIPasteboard.general.string = result.ip } label: {
                Label("کپی IP", systemImage: "doc.on.doc")
            }
        }
    }

    private var cloudflareLog: some View {
        DisclosureGroup(isExpanded: $showCloudflareLog) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    if model.scanRunning {
                        Label("Live", systemImage: "circle.fill")
                            .foregroundStyle(.green)
                            .accessibilityLabel("Scan is running")
                    }
                    Toggle("Follow live", isOn: $followCloudflareLog)
                        .toggleStyle(.switch)
                    Spacer()
                    Button {
                        UIPasteboard.general.string = model.scanLog.joined(separator: "\n")
                    } label: {
                        Label("Copy log", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                }
                .font(.caption)
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 5) {
                            ForEach(Array(model.scanLog.enumerated()), id: \.offset) { index, line in
                                Text(line)
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(line.contains("Winner:") ? .green : .primary)
                                    .id(index)
                            }
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                    }
                    .frame(height: 185)
                    .background(Color(uiColor: .tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 10))
                    .onAppear {
                        if followCloudflareLog { proxy.scrollTo(model.scanLog.count - 1, anchor: .bottom) }
                    }
                    .onChange(of: model.scanLog.count) { count in
                        if followCloudflareLog, count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
                    }
                    .onChange(of: followCloudflareLog) { follow in
                        if follow { proxy.scrollTo(model.scanLog.count - 1, anchor: .bottom) }
                    }
                }
            }
            .padding(.top, 8)
        } label: {
            Label("Scan log", systemImage: "list.bullet.rectangle").font(.subheadline.weight(.semibold))
        }
        .environment(\.layoutDirection, .leftToRight)
    }

    private var optionsCard: some View {
        card {
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 12) {
                    field("پورت SOCKS5", text: $model.localPort, keyboard: .numberPad)
                    Toggle("انتخاب پورت آزاد در صورت اشغال", isOn: $model.portFallback)
                    Toggle("اتصال دوباره بعد از بازگشت به اپ", isOn: $model.autoResume)
                }
                .padding(.top, 10)
                .disabled(!model.canEdit)
            } label: {
                Label("تنظیمات اتصال", systemImage: "slider.horizontal.3").font(.headline)
            }
        }
    }

    private var loginCard: some View {
        card {
            Text("ورود به بله").font(.headline)
            field("شماره همراه با ‎+98", text: $model.phone, keyboard: .phonePad)
                .textContentType(.telephoneNumber)
            if model.transaction != nil {
                SecureField("کد ورود", text: $model.code)
                    .textContentType(.oneTimeCode)
                    .keyboardType(.numberPad)
                    .textFieldStyle(.roundedBorder)
                Button("تأیید کد") { Task { await model.verifyCode() } }
                    .buttonStyle(.borderedProminent)
            }
            if model.busy {
                ProgressView()
            } else {
                Button(model.transaction == nil ? "ارسال کد" : "ارسال دوبارهٔ کد") {
                    Task { await model.requestCode() }
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private func field(_ title: String, text: Binding<String>, keyboard: UIKeyboardType) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.footnote).foregroundStyle(.secondary)
            TextField(title, text: text)
                .keyboardType(keyboard)
                .textFieldStyle(.roundedBorder)
                .environment(\.layoutDirection, .leftToRight)
        }
    }

    private func card<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12, content: content)
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18))
    }
}
