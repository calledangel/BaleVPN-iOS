import Foundation
import Network
import SwiftUI

struct CloudflareTargets: Decodable {
    let canonical: String
    let ips: Int
    let subnets: Int
    let error: String?

    init?(_ text: String) {
        guard !text.contains("\0"), let pointer = text.withCString({ cloudflare_targets_check($0) }) else { return nil }
        defer { cloudflare_free(pointer) }
        let data = Data(String(cString: pointer).utf8)
        guard let value = try? JSONDecoder().decode(Self.self, from: data) else { return nil }
        self = value
    }
}

struct CloudflareTargetsEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var text: String
    let save: (CloudflareTargets) -> Void

    private var validation: CloudflareTargets? { CloudflareTargets(text) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $text)
                        .font(.body.monospaced())
                        .frame(minHeight: 185)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.asciiCapable)
                        .environment(\.layoutDirection, .leftToRight)
                        .accessibilityLabel("فهرست IP و زیرشبکه")
                    PasteButton(payloadType: String.self) { values in
                        let incoming = values.joined(separator: "\n")
                        if !incoming.isEmpty {
                            text = [text, incoming].filter { !$0.isEmpty }.joined(separator: "\n")
                        }
                    }
                } header: {
                    Text("آدرس‌های سفارشی")
                } footer: {
                    Text("هر آدرس یا CIDR را با خط جدید، فاصله یا ویرگول جدا کن. اسکنر آدرس‌های تکی را جداگانه تست می‌کند و از زیرشبکه‌ها نمونه می‌گیرد.")
                }
                Section {
                    Text("188.114.96.251\n188.114.96.0/24\n2606:4700::/32")
                        .font(.footnote.monospaced())
                        .environment(\.layoutDirection, .leftToRight)
                        .textSelection(.enabled)
                } header: {
                    Text("نمونهٔ ورودی")
                }
                if let error = validation?.error {
                    Text(error).font(.footnote).foregroundStyle(.red)
                        .environment(\.layoutDirection, .leftToRight)
                } else if let validation {
                    Text("\(validation.ips) IP تکی · \(validation.subnets) زیرشبکه")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("IP و زیرشبکهٔ سفارشی")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("انصراف") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("ذخیره") {
                        guard let validation, validation.error == nil else { return }
                        save(validation)
                        dismiss()
                    }
                    .disabled(validation == nil || validation?.error != nil)
                }
            }
        }
        .environment(\.layoutDirection, .rightToLeft)
    }
}

struct CloudflareNetwork: Codable, Equatable, Sendable {
    let address: String
    let asn: Int?
    let provider: String?
    let country: String?

    var key: String { asn.map { "AS\($0)" } ?? "unknown" }
    var name: String { provider ?? asn.map { "AS\($0)" } ?? "اپراتور شناسایی نشد" }

    func forHistory() -> Self {
        Self(address: "", asn: asn, provider: provider, country: country)
    }

    private struct Envelope<Value: Decodable>: Decodable { let data: Value }
    private struct Route: Decodable {
        let asns: [Int]

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            if let values = try? container.decode([Int].self, forKey: .asns) {
                asns = values
            } else {
                asns = try container.decode([String].self, forKey: .asns).compactMap(Int.init)
            }
        }

        private enum CodingKeys: String, CodingKey { case asns }
    }
    private struct Organization: Decodable { let holder: String }

    static func detect(profile: String?) async -> Self? {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 3
        configuration.timeoutIntervalForResource = 4
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }

        var endpoints = [URL(string: "https://speed.cloudflare.com/cdn-cgi/trace")].compactMap { $0 }
        if let profile, let config = URLComponents(string: profile.trimmingCharacters(in: .whitespacesAndNewlines)),
           let host = config.queryItems?.first(where: { $0.name == "sni" })?.value ?? config.host {
            var owned = URLComponents()
            owned.scheme = "https"
            owned.host = host
            owned.port = config.port
            owned.path = "/cdn-cgi/trace"
            if let endpoint = owned.url { endpoints.append(endpoint) }
        }
        var response: Data?
        for endpoint in endpoints {
            if let data = await get(endpoint, with: session),
               let trace = String(data: data, encoding: .utf8), trace.contains("\nip=") || trace.hasPrefix("ip=") {
                response = data
                break
            }
            if Task.isCancelled { return nil }
        }
        guard let response, let trace = String(data: response, encoding: .utf8) else { return nil }
        func value(_ key: String) -> String? {
            trace.split(whereSeparator: \.isNewline)
                .first(where: { $0.hasPrefix(key + "=") })
                .map { String($0.dropFirst(key.count + 1)) }
        }
        guard let address = value("ip"), IPv4Address(address) != nil || IPv6Address(address) != nil else { return nil }
        let country = value("loc").flatMap { $0.utf8.count == 2 ? $0 : nil }
        var number: Int?
        var organization: String?
        if let route = await ripe("network-info", resource: address, as: Route.self, with: session),
           let asn = route.asns.first, asn > 0 {
            number = asn
            if let holder = await ripe("as-overview", resource: "AS\(asn)", as: Organization.self, with: session)?.holder {
                organization = displayName(holder)
            }
        }
        return Self(address: address, asn: number, provider: organization, country: country)
    }

    private static func get(_ url: URL, with session: URLSession) async -> Data? {
        guard let (data, response) = try? await session.data(from: url),
              let status = response as? HTTPURLResponse, status.statusCode == 200,
              data.count <= 65536 else { return nil }
        return data
    }

    private static func ripe<Value: Decodable>(_ endpoint: String, resource: String, as type: Value.Type,
                                               with session: URLSession) async -> Value? {
        var url = URLComponents()
        url.scheme = "https"
        url.host = "stat.ripe.net"
        url.path = "/data/\(endpoint)/data.json"
        url.queryItems = [URLQueryItem(name: "resource", value: resource)]
        guard let target = url.url, let data = await get(target, with: session) else { return nil }
        return (try? JSONDecoder().decode(Envelope<Value>.self, from: data))?.data
    }

    private static func displayName(_ holder: String) -> String {
        let known = [
            ("mobile communication", "همراه اول"), ("irancell", "ایرانسل"), ("rightel", "رایتل"),
            ("telecommunication company of iran", "مخابرات ایران"), ("tci iran", "مخابرات ایران"),
            ("shatel", "شاتل"),
            ("asiatech", "آسیاتک"), ("mobinnet", "مبین‌نت"), ("pars online", "پارس‌آنلاین"),
            ("pishgaman", "پیشگامان"), ("sabanet", "صبانت"), ("respina", "رسپینا"),
            ("hiweb", "های‌وب")
        ]
        let lowered = holder.lowercased()
        return known.first(where: { lowered.contains($0.0) })?.1 ?? holder
    }
}

struct CloudflareResultRow: View {
    let result: CloudflareScanUpdate.Result
    let winner: Bool
    let selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(result.ip).font(.subheadline.monospacedDigit().weight(.semibold))
                    .environment(\.layoutDirection, .leftToRight)
                Spacer()
                if selected {
                    Image(systemName: "checkmark.circle.fill")
                        .accessibilityLabel("IP انتخاب‌شده")
                } else if winner {
                    Label("رتبهٔ اول", systemImage: "trophy")
                        .font(.caption.weight(.semibold))
                }
            }
            if result.successes > 0 {
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 14) {
                        speed("دانلود", result.mbps, icon: "arrow.down")
                        speed("آپلود", result.uploadMbps, icon: "arrow.up")
                        measurement("پاسخ", result.milliseconds)
                        measurement("Jitter", result.jitterMilliseconds)
                    }
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 14) {
                            speed("دانلود", result.mbps, icon: "arrow.down")
                            speed("آپلود", result.uploadMbps, icon: "arrow.up")
                        }
                        HStack(spacing: 14) {
                            measurement("پاسخ", result.milliseconds)
                            measurement("Jitter", result.jitterMilliseconds)
                        }
                    }
                }
            }
            Text(result.detail)
                .font(.caption2)
                .foregroundStyle(.secondary)
            if let sizes = result.uploadSizesKiB, !sizes.isEmpty {
                Text("حجم نمونه‌های آپلود · \(sizes.map(String.init).joined(separator: " / ")) KiB")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 5)
        .contentShape(Rectangle())
    }

    private func speed(_ label: String, _ value: Double?, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Label(label, systemImage: icon).font(.caption2).foregroundStyle(.secondary)
            if let value {
                Text("\(value, format: .number.precision(.fractionLength(1))) Mbps").font(.caption.monospacedDigit())
            } else {
                Text("—").font(.caption)
            }
        }
    }

    private func measurement(_ label: String, _ value: Int?) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            if let value {
                Text("\(value) ms").font(.caption.monospacedDigit())
            } else {
                Text("—").font(.caption)
            }
        }
    }
}
