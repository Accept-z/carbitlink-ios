// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkOutput.swift
// 把 CarPlay 帧直接推给亿连（CarbitLink）仪表 —— tds-car-kit / CarWithin 的输出插件。
//
// 【拓扑差异，必须注意】
// Android 端：手机是 Wi-Fi Direct GO，手机**监听** 10920/10921/10922，仪表连进来。
// iOS 端：没有 Wi-Fi Direct API，只能让手机加入仪表热点，方向反过来 —— 我们主动连。
// 但「instrument 到底在哪个端口等我们」没有实测定论（Android 抓包里 10930 从未被连接，
// 因为那时手机是 GO 用不上它）。所以本版不赌单个端口，按候选表依次试，并在日志里
// 明确记录哪一个连上了 —— 这份日志本身就是下一次迭代的依据。
//
// 【本版能力边界（v0.2）】
//   · 能：连接仪表、发握手、请求开始镜像、解析仪表下发的采集参数、
//         按 0x0072 拉帧节奏推帧、把全部线上字节**分通道**转储到文件。
//   · 不保证出画面：仪表对「手机推帧」的响应指令码尚未实测确认（见 Code.videoFrame）。
//
// v0.2 修的两个坑：
//   1) 控制/视频两条 TCP 原先共用同一个 CarbitLinkWire 实例，两条流的半包会拼进
//      一个缓冲区，字节序必然错乱 —— 改为每条连接独立解析器。
//   2) 原先只试 10930 → 10921 两级，且把 NWConnection 的 .waiting 一律当失败
//      （连接被拒和「网络暂时不可用」都会走 .waiting）—— 改为枚举候选端口 +
//      只在 ECONNREFUSED 时立即换端口，其余情况等 8 秒兜底。

import Foundation
import Network

final class CarbitLinkOutput {

    // MARK: - 配置

    struct Configuration {
        /// 仪表 IP。iOS 加入其热点后一般是网关地址，例如 192.168.49.1。
        var host: String = ""
        /// 控制通道候选端口，按顺序尝试。
        /// 10930 = 仪表 mDNS 广播的那个口；10921/10920 = Android 端手机侧监听的端口，
        /// 万一仪表是客户端角色，就在这两个口上等我们。
        var controlPorts: [UInt16] = [10930, 10921, 10920]
        /// 视频通道候选端口。
        var dataPorts: [UInt16] = [10920, 10922]
        /// 采集参数，运行时被仪表下发值覆盖；这里是本车实测默认值。
        var width: Int = 1152
        var height: Int = 640
        var bitRate: Int = 3_145_728
        /// 仪表 huid（mDNS 给的仪表 MAC 十六进制），用于握手。
        var huid: String = ""
        var huName: String = ""
        /// 把收发的每个字节都记进 dump 文件，便于离线分析未知指令码。
        var dumpsBytes: Bool = true
    }

    // MARK: - 回调

    /// 仪表回传触摸（坐标已是视频像素空间），交给 NativeReceiver.touch。
    var onTouch: ((_ x: UInt16, _ y: UInt16, _ down: Bool) -> Void)?
    var onLog: ((String) -> Void)?
    var onStateChange: ((_ connected: Bool) -> Void)?
    /// 仪表下发了新的采集参数。
    var onCaptureConfig: ((CarbitLinkWire.CaptureConfig) -> Void)?

    // MARK: - 状态

    private var config = Configuration()
    private var control: NWConnection?
    private var data: NWConnection?
    /// 每条连接一个解析器：两条 TCP 流的半包绝不能混进同一个缓冲区。
    private var parsers: [ObjectIdentifier: CarbitLinkWire] = [:]
    private let queue = DispatchQueue(label: "carbitlink.output")
    private var isRunning = false
    private var controlReady = false
    private var controlIndex = 0
    private var dataIndex = 0
    /// 待发送的帧。拉模式下仪表每要一帧才推一次，只保留最新一帧。
    private var pendingFrame: Data?
    private var frameInFlight = false
    private var dumpHandle: FileHandle?
    /// 上一次上报给 UI 的连接状态。只在真实跃变时回调，
    /// 避免 stop() 每次都报一次"已断开"（日志里会和 Receiver stopped 成对出现，纯噪声）。
    private var reportedConnected = false

    // MARK: - 对外
    //
    // 所有公开入口都跳进 queue：NWConnection 的回调本来就在 queue 上跑，
    // 若 start/stop 直接从主线程改 parsers / dumpHandle / pendingFrame，
    // 就是典型的数据竞争（字典并发读写会直接崩）。

    func start(configuration: Configuration) {
        queue.async { [weak self] in self?.startLocked(configuration) }
    }

    func stop() {
        queue.async { [weak self] in self?.stopLocked() }
    }

    private func startLocked(_ configuration: Configuration) {
        stopLocked()
        config = configuration
        // dump 先开，哪怕 host 是空的也留一条记录，免得用户以为功能没跑。
        openDumpIfNeeded()
        guard !config.host.isEmpty else {
            log("未填仪表 IP。请先连上仪表热点，再填网关地址（一般 192.168.49.1）。")
            if let gw = Self.suggestedGateway() {
                log("按本机地址推断，网关应该是 \(gw)，可直接填进设置。")
            }
            stopLocked()
            return
        }
        isRunning = true
        log("开始连接仪表 \(config.host)，控制端口候选 \(portList(config.controlPorts))")
        connectControlResetting()
    }

    private func stopLocked() {
        isRunning = false
        control?.cancel(); control = nil
        data?.cancel(); data = nil
        parsers.removeAll()
        controlReady = false
        controlIndex = 0
        dataIndex = 0
        pendingFrame = nil
        frameInFlight = false
        if dumpHandle != nil {
            write("=== 会话结束 \(ISO8601DateFormatter().string(from: Date())) ===")
            log("dump 已写入 Documents/carbitlink-dump.log")
            try? dumpHandle?.close()
            dumpHandle = nil
        }
        setConnected(false)
    }

    /// 由 ReceiverViewController 的 onVideo 调用：送一帧 Annex-B。
    func submit(accessUnit: Data) {
        queue.async { [weak self] in
            guard let self, self.isRunning else { return }
            self.pendingFrame = accessUnit
            self.pumpFrameIfPossible()
        }
    }

    // MARK: - 连接（控制通道）

    private func connectControlResetting() {
        controlIndex = 0
        controlReady = false
        tryNextControlPort()
    }

    private func tryNextControlPort() {
        guard isRunning else { return }
        guard controlIndex < config.controlPorts.count else {
            log("控制端口全部连不上：\(portList(config.controlPorts))。确认手机已连仪表热点、仪表已进入配对界面。")
            return
        }
        let port = config.controlPorts[controlIndex]
        controlIndex += 1
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { tryNextControlPort(); return }

        log("尝试控制端口 \(port)")
        let connection = NWConnection(host: NWEndpoint.Host(config.host), port: nwPort, using: .tcp)
        control = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, self.control === connection else { return }
            switch state {
            case .ready:
                self.controlReady = true
                self.log("控制通道已连上 \(self.config.host):\(port) ★")
                self.setConnected(true)
                self.beginControlSession()
            case .failed(let error):
                self.log("控制通道 \(port) 失败：\(error.localizedDescription)")
                connection.cancel()
                self.tryNextControlPort()
            case .waiting(let error):
                if Self.isConnectionRefused(error) {
                    self.log("端口 \(port) 未监听，换下一个")
                    connection.cancel()
                    self.tryNextControlPort()
                } else {
                    self.log("控制通道 \(port) 等待中：\(error.localizedDescription)")
                }
            default:
                break
            }
        }
        connection.start(queue: queue)
        // 兜底：某些网络状态下 NWConnection 既不 ready 也不 failed，别死等。
        queue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, self.control === connection, !self.controlReady else { return }
            self.log("端口 \(port) 8 秒未就绪，换下一个")
            connection.cancel()
            self.tryNextControlPort()
        }
    }

    // MARK: - 连接（视频通道）

    private func connectDataResetting() {
        dataIndex = 0
        tryNextDataPort()
    }

    private func tryNextDataPort() {
        guard isRunning else { return }
        guard dataIndex < config.dataPorts.count else {
            log("视频端口全部连不上：\(portList(config.dataPorts))")
            return
        }
        let port = config.dataPorts[dataIndex]
        dataIndex += 1
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { tryNextDataPort(); return }

        log("尝试视频端口 \(port)")
        let connection = NWConnection(host: NWEndpoint.Host(config.host), port: nwPort, using: .tcp)
        data = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, self.data === connection else { return }
            switch state {
            case .ready:
                self.log("视频通道已连上 \(self.config.host):\(port) ★")
                self.receive(on: connection, tag: "data")
            case .failed(let error):
                self.log("视频通道 \(port) 失败：\(error.localizedDescription)")
                connection.cancel()
                self.tryNextDataPort()
            case .waiting(let error):
                if Self.isConnectionRefused(error) {
                    self.log("视频端口 \(port) 未监听，换下一个")
                    connection.cancel()
                    self.tryNextDataPort()
                } else {
                    self.log("视频通道 \(port) 等待中：\(error.localizedDescription)")
                }
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    // MARK: - 会话

    private func beginControlSession() {
        // 1) 握手（明文 JSON）。
        let huid = config.huid.uppercased()
        let handshake = CarbitLinkWire.handshakeJSON(huid: huid, huName: config.huName)
        log("握手：\(String(data: handshake, encoding: .utf8) ?? "-")")
        send(handshake, on: control, tag: "ctl")

        // 2) 请求开始镜像。实测该码发出后，仪表会连视频通道并发 cmd 0x0010。
        if let request = try? CarbitLinkWire().frame(code: .requestStart) {
            log("请求开始镜像 0x\(String(format: "%04X", CarbitLinkWire.Code.requestStart.rawValue))")
            send(request, on: control, tag: "ctl")
        }

        // 3) 视频通道
        connectDataResetting()

        if let connection = control { receive(on: connection, tag: "ctl") }
    }

    private func receive(on connection: NWConnection, tag: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] chunk, _, isComplete, error in
            guard let self else { return }
            if let chunk, !chunk.isEmpty {
                if self.config.dumpsBytes { self.dump(chunk, tag: tag) }
                let parser = self.parser(for: connection)
                for event in parser.consume(chunk) {
                    self.handle(event: event, tag: tag)
                }
            }
            if let error {
                self.log("[\(tag)] 接收中断：\(error.localizedDescription)")
                return
            }
            if isComplete {
                self.log("[\(tag)] 对端关闭了连接")
                return
            }
            self.receive(on: connection, tag: tag)
        }
    }

    private func handle(event: CarbitLinkWire.Event, tag: String) {
        switch event {
        case .start(let incoming):
            if let incoming {
                config.width = incoming.width
                config.height = incoming.height
                config.bitRate = incoming.bitRate
                let mode = incoming.isPullMode ? "，拉模式" : ""
                log("[\(tag)] 仪表下发采集参数：\(incoming.width)×\(incoming.height) @ \(incoming.bitRate)bps 编码 \(incoming.encoder) fps=\(incoming.wantFps)\(mode)")
                onCaptureConfig?(incoming)
            } else {
                log("[\(tag)] 收到 0x0010 启动指令，载荷未解析出字段（已转储原始字节）")
            }
        case .ready:
            log("[\(tag)] 视频通道就绪（0x0070）")
        case .frameRequest:
            pumpFrameIfPossible()
        case .heartbeat:
            if let beat = try? CarbitLinkWire().frame(code: .heartbeat) { send(beat, on: control, tag: "ctl") }
        case .unknown(let code, let payload):
            log("[\(tag)] 未知指令 0x\(String(format: "%04X", code))，\(payload.count) 字节：\(payload.hexDump(limit: 64))")
        }
    }

    // MARK: - 推帧

    private func pumpFrameIfPossible() {
        guard isRunning, !frameInFlight, let frame = pendingFrame else { return }
        pendingFrame = nil
        frameInFlight = true
        guard let packet = try? CarbitLinkWire().videoFrame(annexB: frame) else {
            frameInFlight = false
            return
        }
        if config.dumpsBytes { dump(packet, tag: "data-tx") }
        // 视频通道没连上时退回控制通道发，避免整条链路静默。
        let target = data ?? control
        target?.send(content: packet, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.frameInFlight = false
            // 换端口/停会话时连接被 cancel 会回 ECANCELED(89)，
            // 那不是故障，之前会把 dump 刷成几百行噪声。
            if let error, !Self.isCancellation(error) {
                self.log("推帧失败：\(error.localizedDescription)")
            }
        })
    }

    // MARK: - 发送

    private func send(_ payload: Data, on connection: NWConnection?, tag: String) {
        guard let connection else { return }
        if config.dumpsBytes { dump(payload, tag: "\(tag)-tx") }
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            if let error, !Self.isCancellation(error) { self?.log("[\(tag)] 发送失败：\(error.localizedDescription)") }
        })
    }

    /// 连接被主动 cancel 时下层会回 ECANCELED，不算错误。
    private static func isCancellation(_ error: Error) -> Bool {
        guard let nw = error as? NWError, case .posix(let code) = nw else { return false }
        return code == .ECANCELED
    }

    // MARK: - 解析器

    private func parser(for connection: NWConnection) -> CarbitLinkWire {
        let key = ObjectIdentifier(connection)
        if let existing = parsers[key] { return existing }
        let created = CarbitLinkWire()
        parsers[key] = created
        return created
    }

    // MARK: - 工具

    private static func isConnectionRefused(_ error: NWError) -> Bool {
        if case .posix(let code) = error, code == .ECONNREFUSED { return true }
        return false
    }

    private func portList(_ ports: [UInt16]) -> String {
        ports.map { String($0) }.joined(separator: "/")
    }

    // MARK: - 转储

    /// dump 文件固定落在 Documents 根目录，便于「文件」App 直接看到。
    static var dumpURL: URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
            .appendingPathComponent("carbitlink-dump.log")
    }

    /// App 一启动就把文件建出来（带表头）。
    /// 否则用户可能在"从没连上过"的情况下根本找不到这个文件，
    /// 误以为是功能没生效。
    @discardableResult
    static func ensureDumpFile() -> URL? {
        guard let url = dumpURL else { return nil }
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil)
        }
        let attributes = try? fm.attributesOfItem(atPath: url.path)
        let existingSize = (attributes?[.size] as? NSNumber)?.intValue ?? 0
        if existingSize > 0 { return url }
        let header = """
        === CarbitLink dump ===
        文件：Documents/carbitlink-dump.log
        说明：亿连输出启动后，这里记录每条 TCP 的收发字节（ctl/data/ctl-tx/data-tx）
              以及文字日志（以 # 开头）。没连上仪表时也会留下尝试记录。
        创建：\(ISO8601DateFormatter().string(from: Date()))

        """
        try? header.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    private func openDumpIfNeeded() {
        guard config.dumpsBytes, let url = Self.ensureDumpFile() else { return }
        dumpHandle = try? FileHandle(forWritingTo: url)
        dumpHandle?.seekToEndOfFile()
        let ip = Self.localWiFiAddress() ?? "未知"
        write("")
        write("=== 新会话 \(ISO8601DateFormatter().string(from: Date())) ===")
        write("# 目标 host=\(config.host)")
        write("# 控制端口候选=\(portList(config.controlPorts)) 视频端口候选=\(portList(config.dataPorts))")
        write("# 本机 Wi-Fi 地址=\(ip)")
        write("# 采集参数=\(config.width)x\(config.height) @\(config.bitRate)bps huid=\(config.huid.isEmpty ? "-" : config.huid)")
    }

    /// 当前 Wi-Fi 口地址，写进 dump 方便判断"手机到底在哪个网段"。
    static func localWiFiAddress() -> String? {
        ReceiverConfiguration.localIPv4Addresses().first
    }

    /// 由本机 Wi-Fi 地址推断仪表网关：192.168.49.2 → 192.168.49.1。
    /// 亿连的车机热点通常就是这个网段的 .1，省得用户手填错。
    static func suggestedGateway() -> String? {
        guard let ip = localWiFiAddress() else { return nil }
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return nil }
        return "\(parts[0]).\(parts[1]).\(parts[2]).1"
    }

    /// 直接往 dump 追加一行（诊断用，不依赖是否正在采集）。
    static func appendDumpLine(_ line: String) {
        guard let url = dumpURL else { return }
        if !FileManager.default.fileExists(atPath: url.path) { ensureDumpFile() }
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        handle.seekToEndOfFile()
        if let data = (line + "\n").data(using: .utf8) { try? handle.write(contentsOf: data) }
        try? handle.close()
    }

    /// 探测某个 host:port 是否有 TCP 服务在听。
    /// 语义上只判断「能建连」：.ready = 通，.failed / .waiting（含 ECONNREFUSED、不可达）= 不通。
    static func probe(host: String, port: UInt16, timeout: TimeInterval = 0.9) -> Bool {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return false }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var settled = false
        var reachable = false
        func settle(_ value: Bool) {
            lock.lock()
            if settled { lock.unlock(); return }
            settled = true
            reachable = value
            lock.unlock()
            semaphore.signal()
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: settle(true)
            case .failed, .waiting: settle(false)
            default: break
            }
        }
        connection.start(queue: DispatchQueue.global(qos: .utility))
        if semaphore.wait(timeout: .now() + timeout) == .timedOut { settle(false) }
        connection.cancel()
        return reachable
    }

    private func dump(_ data: Data, tag: String) {
        write("\(tag) \(data.count)B | \(data.hexDump())")
    }

    private func write(_ line: String) {
        guard let handle = dumpHandle, let encoded = (line + "\n").data(using: .utf8) else { return }
        try? handle.write(contentsOf: encoded)
    }

    /// 状态只在真实跃变时上报，避免 stop() 制造假的"已断开"。
    private func setConnected(_ connected: Bool) {
        guard connected != reportedConnected else { return }
        reportedConnected = connected
        onStateChange?(connected)
    }

    private func log(_ message: String) {
        // 文字日志同时进 dump：即使仪表一个字节都没回，也能看出卡在哪一步。
        write("# \(message)")
        onLog?("[亿连] " + message)
    }
}
