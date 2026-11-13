import BackgroundTasks
import Foundation
import Network
import OSLog
import UIKit

@available(iOS 17.0, *)
enum ProxyHTTPSProbe {
    static let primary = URL(string: "https://www.apple.com/library/test/success.html")!
    static let secondary = URL(string: "https://speed.cloudflare.com/cdn-cgi/trace")!

    static func succeeds(port: UInt16, url: URL) async -> Bool {
        guard let port = NWEndpoint.Port(rawValue: port) else { return false }
        var proxy = ProxyConfiguration(socksv5Proxy: .hostPort(host: "127.0.0.1", port: port))
        proxy.allowFailover = false
        let configuration = URLSessionConfiguration.ephemeral
        configuration.proxyConfigurations = [proxy]
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 6
        configuration.timeoutIntervalForResource = 8
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (data, response) = try await session.data(from: url)
            return !data.isEmpty && response.url == url && (response as? HTTPURLResponse)?.statusCode == 200
        } catch {
            return false
        }
    }
}

@available(iOS 26.0, *)
@MainActor
final class BackgroundProxyTest {
    static let shared = BackgroundProxyTest()

    enum RunLength: Int {
        case fiveMinutes = 300
        case oneHour = 3600

        var sampleInterval: Int { self == .oneHour ? 30 : 15 }
        var sampleOffsets: [Int] {
            let regular = Array(stride(from: 0, through: rawValue, by: sampleInterval))
            return self == .oneHour ? [0, 15] + regular.dropFirst() : regular
        }
        var durationLabel: String { self == .oneHour ? "یک‌ساعته" : "پنج‌دقیقه‌ای" }
    }

    private let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "org.balevpn.ios", category: "BackgroundTest")
    private let title = "تست پس‌زمینهٔ BaleVPN"
    private var identifier: String?
    private var task: BGContinuedProcessingTask?
    private var proxyPort: NWEndpoint.Port?
    private var measurement: Task<Void, Never>?
    private var onFinish: ((String, Bool) -> Void)?
    private var successfulSamples = 0
    private var completedSamples = 0
    private var peakThermalLevel = 0

    func start(
        port: UInt16,
        length: RunLength,
        onBegin: @escaping () -> Void,
        onTrafficFailure: (() -> Void)? = nil,
        onFinish: @escaping (String, Bool) -> Void
    ) -> Bool {
        guard identifier == nil, let bundleID = Bundle.main.bundleIdentifier,
              let proxyPort = NWEndpoint.Port(rawValue: port) else { return false }
        let id = "\(bundleID).proxy-test.\(UUID().uuidString)"
        let scheduler = BGTaskScheduler.shared
        guard scheduler.register(forTaskWithIdentifier: id, using: .main, launchHandler: { task in
            MainActor.assumeIsolated {
                self.begin(task, id: id, port: proxyPort, length: length, onBegin: onBegin, onTrafficFailure: onTrafficFailure)
            }
        }) else { return false }
        identifier = id
        self.proxyPort = proxyPort
        self.onFinish = onFinish
        completedSamples = 0
        successfulSamples = 0
        peakThermalLevel = 0

        let request = BGContinuedProcessingTaskRequest(
            identifier: id, title: title, subtitle: "آزمون \(length.durationLabel) پروکسی محلی"
        )
        request.strategy = .fail
        Task {
            do {
                if #available(iOS 27.0, *) {
                    try await scheduler.submitTaskRequest(request)
                } else {
                    try scheduler.submit(request)
                }
            } catch {
                let code = (error as NSError).code
                log.notice("BaleVPN test rejected code=\(code, privacy: .public)")
                if identifier == id {
                    finish("iOS اجرای تست پس‌زمینه را نپذیرفت (کد \(code)).")
                }
            }
        }
        return true
    }

    private func begin(
        _ backgroundTask: BGTask, id: String, port: NWEndpoint.Port,
        length: RunLength, onBegin: () -> Void, onTrafficFailure: (() -> Void)?
    ) {
        guard id == identifier, let continued = backgroundTask as? BGContinuedProcessingTask else {
            backgroundTask.setTaskCompleted(success: false)
            return
        }
        task = continued
        let sampleOffsets = length.sampleOffsets
        continued.progress.totalUnitCount = Int64(sampleOffsets.count)
        continued.expirationHandler = { [weak self] in
            Task { @MainActor in
                guard let self, self.identifier == id else { return }
                self.log.notice("BaleVPN test expired")
                self.finish("iOS تست را متوقف کرد.")
            }
        }
        onBegin()
        log.notice("BaleVPN test started port=\(port.rawValue, privacy: .public) duration=\(length.rawValue, privacy: .public)")
        measurement = Task {
            let clock = ContinuousClock()
            let start = clock.now
            for (index, offset) in sampleOffsets.enumerated() {
                let due = start.advanced(by: .seconds(offset))
                do {
                    try await clock.sleep(until: due, tolerance: .seconds(1))
                } catch {
                    return
                }
                if index + 1 < sampleOffsets.count,
                   clock.now >= start.advanced(by: .seconds(sampleOffsets[index + 1])) {
                    continue
                }
                let thermal = ProcessInfo.processInfo.thermalState
                peakThermalLevel = max(peakThermalLevel, thermal.rawValue)
                if thermal == .critical {
                    log.notice("BaleVPN test stopped at critical thermal level")
                    finish("iOS دمای دستگاه را بحرانی گزارش کرد. نشست بسته شد.")
                    return
                }
                let sampledPort = proxyPort
                var succeeded = false
                if let sampledPort {
                    succeeded = await probe(port: sampledPort)
                    if !succeeded, onTrafficFailure != nil, !Task.isCancelled {
                        succeeded = await ProxyHTTPSProbe.succeeds(port: sampledPort.rawValue, url: ProxyHTTPSProbe.secondary)
                    }
                }
                guard !Task.isCancelled, identifier == id else { return }
                if !succeeded, let sampledPort, sampledPort == proxyPort { onTrafficFailure?() }
                completedSamples += 1
                if succeeded { successfulSamples += 1 }
                continued.progress.completedUnitCount = Int64(completedSamples)
                continued.updateTitle(title, subtitle: "\(successfulSamples) پاسخ موفق از \(completedSamples) آزمون")
                let elapsed = start.duration(to: clock.now).components.seconds
                let background = UIApplication.shared.applicationState == .background
                log.notice("BaleVPN test probe elapsed=\(elapsed, privacy: .public) background=\(background, privacy: .public) ok=\(succeeded, privacy: .public) thermal=\(thermal.rawValue, privacy: .public)")
            }
            finish("تست \(length.durationLabel) تمام شد.", completed: true)
        }
    }

    func updatePort(_ port: UInt16?) {
        proxyPort = port.flatMap(NWEndpoint.Port.init(rawValue:))
    }

    private func probe(port: NWEndpoint.Port) async -> Bool {
        await ProxyHTTPSProbe.succeeds(port: port.rawValue, url: ProxyHTTPSProbe.primary)
    }

    func finish(_ message: String, completed: Bool = false) {
        guard let id = identifier else { return }
        identifier = nil
        proxyPort = nil
        measurement?.cancel()
        measurement = nil
        let activeTask = task
        task = nil
        activeTask?.expirationHandler = nil
        if activeTask == nil {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: id)
        }
        let callback = onFinish
        onFinish = nil
        log.notice("BaleVPN test finished samples=\(self.completedSamples, privacy: .public) successes=\(self.successfulSamples, privacy: .public) peakThermal=\(self.peakThermalLevel, privacy: .public)")
        let result = completedSamples > 0 ? " \(successfulSamples) پاسخ موفق از \(completedSamples) آزمون." : ""
        callback?(message + result, activeTask != nil)
        activeTask?.setTaskCompleted(success: completed)
    }
}
