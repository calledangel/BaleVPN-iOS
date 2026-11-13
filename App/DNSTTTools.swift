import Foundation
import SwiftUI
import UniformTypeIdentifiers

struct DNSResolverUpdate: Decodable, Identifiable, Sendable {
    let resolver: String?
    let milliseconds: Int?
    let status: String
    let line: String?
    var id: String { resolver ?? status }
    var verified: Bool { status == "verified" }

    var detail: String {
        guard let line, !line.isEmpty else { return status }
        if let milliseconds { return "\(line) · \(milliseconds) ms" }
        return line
    }
}

enum DNSResolverMode: String, CaseIterable, Identifiable {
    case automatic, manual

    var id: Self { self }
    var title: String {
        switch self {
        case .automatic: "خودکار"
        case .manual: "دستی"
        }
    }

}

enum DNSScanScope: String, CaseIterable, Identifiable {
    case network, iran, custom

    var id: Self { self }
    var title: String {
        switch self {
        case .network: "شبکهٔ فعلی"
        case .iran: "DNS ایران"
        case .custom: "لیست من"
        }
    }
}

struct DNSProvider: Identifiable {
    let name: String
    let addresses: [String]
    var id: String { name }

    // https://github.com/erfnzdeh/smart-dns-ir#dns-servers
    static let iran: [Self] = [
        .init(name: "شکن", addresses: ["178.22.122.100:53", "185.51.200.2:53"]),
        .init(name: "الکترو", addresses: ["78.157.42.100:53", "78.157.42.101:53"]),
        .init(name: "رادار", addresses: ["10.202.10.10:53", "10.202.10.11:53"]),
        .init(name: "۴۰۳", addresses: ["10.202.10.202:53", "10.202.10.102:53"]),
        .init(name: "بگذر", addresses: ["185.55.225.25:53", "185.55.226.26:53"])
    ]

    static func label(for address: String?) -> String? {
        iran.first { provider in provider.addresses.contains { $0 == address } }?.name
    }
}

struct DNSResolverCard: View {
    @ObservedObject var model: ProxyModel
    @State private var editing = false
    @State private var scope = DNSScanScope.network
    @State private var showLog = true
    @State private var followLog = true

    private var selected: String {
        model.activeDNSResolver ?? model.dnsCandidates.first ?? "—"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("سرور DNS", systemImage: "server.rack").font(.headline)
            Picker("انتخاب DNS", selection: $model.dnsMode) {
                ForEach(DNSResolverMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .disabled(!model.canEdit)
            HStack {
                Text(model.activeDNSResolver == nil ? "اولویت اتصال" : "مسیر فعال")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(selected).font(.callout.monospaced()).textSelection(.enabled)
                    .environment(\.layoutDirection, .leftToRight)
            }
            Button { editing = true } label: {
                Label("فهرست DNS و تنظیمات", systemImage: "list.bullet")
            }
            .buttonStyle(.bordered)
            .disabled(!model.canEdit)

            Picker("هدف اسکن", selection: $scope) {
                ForEach(DNSScanScope.allCases) { scope in Text(scope.title).tag(scope) }
            }
            .pickerStyle(.segmented)
            .disabled(!model.canEdit)
            HStack {
                if model.dnsScanRunning {
                    ProgressView().controlSize(.small)
                    Button("توقف اسکن", action: model.stopDNSScan)
                } else {
                    Button("اسکن سریع") { model.scanDNS(scope: scope, deep: false) }
                    Button("اسکن عمیق") { model.scanDNS(scope: scope, deep: true) }
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!model.dnsScanRunning && (!model.canEdit || !model.installedProfiles.contains(.dnstt)))

            if !model.dnsResults.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(model.dnsResults) { result in
                        HStack(spacing: 10) {
                            Image(systemName: result.verified ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(result.verified ? Color.green : Color.secondary)
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(result.resolver ?? "").font(.footnote.monospaced()).textSelection(.enabled)
                                    if let label = DNSProvider.label(for: result.resolver) {
                                        Text(label).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                Text(result.detail).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 0)
                            if result.verified, !model.dnsScanRunning {
                                Button("استفاده") { model.selectDNSResolver(result.resolver) }
                                    .disabled(!model.canEdit)
                            }
                        }
                        .environment(\.layoutDirection, .leftToRight)
                    }
                }
            }
            if !model.dnsLog.isEmpty { logView }
        }
        .sheet(isPresented: $editing) { editor }
    }

    private var logView: some View {
        DisclosureGroup("DNS diagnostic log", isExpanded: $showLog) {
            HStack {
                Toggle("Follow live", isOn: $followLog).toggleStyle(.switch).font(.caption)
                Button("Copy log") { UIPasteboard.general.string = model.dnsLog.joined(separator: "\n") }
                    .buttonStyle(.bordered)
            }
            ScrollViewReader { reader in
                ScrollView {
                    Text(model.dnsLog.joined(separator: "\n"))
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Color.clear.frame(height: 1).id("dns-log-bottom")
                }
                .frame(maxHeight: 190)
                .onChange(of: model.dnsLog.count) { _ in
                    if followLog { reader.scrollTo("dns-log-bottom", anchor: .bottom) }
                }
            }
        }
        .environment(\.layoutDirection, .leftToRight)
    }

    private var editor: some View {
        DNSResolverEditor(addresses: model.dnsCustom, timeout: Int(model.dnsTimeout)) { addresses, timeout in
            model.setDNSOptions(addresses, timeout: timeout)
        }
    }
}

private struct DNSResolverEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var addresses: String
    @State var timeout: Int
    @State private var invalid = false
    @State private var importing = false
    @State private var importMessage: String?
    @State private var reference = DNSResolverText.loadReference()
    @State private var referenceQuery = ""
    let save: (String, Int) -> Bool

    var body: some View {
        NavigationStack {
            Form {
                Section("آدرس‌های DNS") {
                    TextEditor(text: $addresses)
                        .font(.body.monospaced())
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .frame(minHeight: 100)
                        .environment(\.layoutDirection, .leftToRight)
                    Button { importing = true } label: {
                        Label("افزودن از فایل TXT", systemImage: "doc.badge.plus")
                    }
                    Menu {
                        ForEach(DNSProvider.iran) { provider in
                            Button(provider.name) { append(provider.addresses.joined(separator: "\n")) }
                        }
                    } label: {
                        Label("افزودن DNS ایرانی", systemImage: "list.bullet")
                    }
                    if let importMessage {
                        Text(importMessage).font(.footnote).foregroundStyle(.secondary)
                    }
                    Text("هر آدرس را در یک سطر بنویس. پورت پیش‌فرض ۵۳ است و سطرهای # توضیح‌اند.")
                        .font(.footnote).foregroundStyle(.secondary)
                    if invalid {
                        Text("حداکثر ۶۴ آدرس معتبر وارد کن.").foregroundStyle(.red)
                    }
                }
                if !reference.isEmpty {
                    Section("فهرست WhiteDNS و TXT · \(reference.count) آدرس") {
                        TextField("جست‌وجوی آدرس یا پیشوند", text: $referenceQuery)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .environment(\.layoutDirection, .leftToRight)
                        ForEach(referenceMatches, id: \.self) { address in
                            Button {
                                append(String(address))
                            } label: {
                                HStack {
                                    Text(address).font(.callout.monospaced())
                                    Spacer()
                                    Image(systemName: "plus.circle")
                                }
                                .environment(\.layoutDirection, .leftToRight)
                            }
                        }
                        if referenceMatches.isEmpty {
                            Text("آدرسی مطابق جست‌وجو پیدا نشد.").foregroundStyle(.secondary)
                        }
                        Text("تا ۳۰ نتیجهٔ جست‌وجو نمایش داده می‌شود. برای افزودن به لیست اسکن، آدرس را لمس کن.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                Section("اتصال") {
                    Stepper("مهلت هر DNS · \(timeout) ثانیه", value: $timeout, in: 5...45)
                }
            }
            .navigationTitle("تنظیم DNS")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("بستن") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("ذخیره") {
                        if save(addresses, timeout) { dismiss() } else { invalid = true }
                    }
                }
            }
        }
        .environment(\.layoutDirection, .rightToLeft)
        .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText], allowsMultipleSelection: true) { result in
            guard case .success(let urls) = result, !urls.isEmpty else { return }
            importFiles(urls)
        }
    }

    private var referenceMatches: [Substring] {
        let query = referenceQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        return Array(reference.lazy.filter { query.isEmpty || $0.localizedCaseInsensitiveContains(query) }.prefix(30))
    }

    private func importFiles(_ urls: [URL]) {
        var imported = ""
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let file = try FileHandle(forReadingFrom: url)
                defer { try? file.close() }
                let remaining = DNSResolverText.referenceBytes - imported.utf8.count
                guard remaining > 0, let data = try file.read(upToCount: remaining + 1),
                      data.count <= remaining, let value = String(data: data, encoding: .utf8) else {
                    importMessage = "فایل‌ها باید TXT با کدگذاری UTF-8 و در مجموع حداکثر ۱ مگابایت باشند."
                    return
                }
                imported += String(value.drop(while: { $0 == "\u{FEFF}" })) + "\n"
            } catch {
                importMessage = "خواندن فایل ممکن نشد."
                return
            }
        }
        guard let normalized = DNSResolverText.normalize(imported, reference: true), !normalized.isEmpty else {
            importMessage = "فایل باید آدرس‌های معتبر DNS داشته باشد؛ حداکثر ۲۰ هزار آدرس."
            return
        }
        if normalized.split(separator: "\n").count <= 64,
           DNSResolverText.normalize(addresses + "\n" + normalized) != nil {
            append(normalized)
            return
        }
        guard DNSResolverText.addPersonalReference(normalized) else {
            importMessage = "ذخیرهٔ مرجع ممکن نشد یا از ظرفیت فهرست بیشتر شد."
            return
        }
        reference = DNSResolverText.loadReference()
        importMessage = "\(reference.count) آدرس یکتا در مرجع ذخیره شد. DNSهای موردنظر را انتخاب کن."
    }

    private func append(_ value: String) {
        let trimmed = value.hasPrefix("\u{FEFF}") ? String(value.dropFirst()) : value
        let combined = addresses + "\n" + trimmed
        guard let merged = DNSResolverText.normalize(combined), !merged.isEmpty else {
            importMessage = "فهرست باید آدرس معتبر داشته باشد و از ۶۴ آدرس بیشتر نشود."
            return
        }
        addresses = merged
        importMessage = "\(merged.split(separator: "\n").count) آدرس در فهرست آمادهٔ ذخیره است."
        invalid = false
    }
}

enum DNSResolverText {
    static let referenceBytes = 1_048_576
    private static let referenceURL = URL.applicationSupportDirectory.appendingPathComponent("DNSTTResolverCatalog.txt")

    static func normalize(_ addresses: String, reference: Bool = false) -> String? {
        guard addresses.utf8.count <= (reference ? referenceBytes : 16_384), !addresses.contains("\0") else { return nil }
        let value = addresses.withCString { reference ? dnstt_reference_resolvers($0) : dnstt_normalize_resolvers($0) }
        guard let value else { return nil }
        defer { cloudflare_free(value) }
        return String(cString: value)
    }

    private static let bundledReference: [Substring] = {
        guard let url = Bundle.main.url(forResource: "WhiteDNS-resolvers", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(separator: "\n")
    }()
    private static let bundledSet = Set(bundledReference)

    private static func personalReference() -> [Substring] {
        guard let text = try? String(contentsOf: referenceURL, encoding: .utf8),
              let canonical = normalize(text, reference: true) else { return [] }
        return canonical.split(separator: "\n").filter { !bundledSet.contains($0) }
    }

    static func loadReference() -> [Substring] {
        bundledReference + personalReference()
    }

    static func addPersonalReference(_ text: String) -> Bool {
        let imported = text.split(separator: "\n").filter { !bundledSet.contains($0) }
        let combined = (personalReference() + imported).joined(separator: "\n")
        guard let canonical = normalize(combined, reference: true) else { return false }
        do {
            try FileManager.default.createDirectory(at: referenceURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(canonical.utf8).write(to: referenceURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            return true
        } catch {
            return false
        }
    }
}

enum DNSLogFile {
    static let url = URL.applicationSupportDirectory.appendingPathComponent("DNSTTDiagnostic.log")

    static func save(_ lines: [String]) {
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(lines.joined(separator: "\n").utf8).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            // The in-app log remains available if the archive cannot be written.
        }
    }
}
