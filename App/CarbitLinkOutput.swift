// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkOutput.swift
// 亿连（CarbitLink）仪表输出 —— v0.7，按 libEPSDK.so 静态逆向修正握手层。
//
// 【拓扑（已由反汇编 + 实车双重确认）】
//   · iPhone 连仪表热点 kt_ap_xxxx（仪表即网关，实测 192.168.1.1）。
//   · 控制通道：手机主动连 仪表:10930，PXC 16 字节帧头。
//   · 镜像通道：仪表主动连回手机（Android 抓包：手机 GO 192.168.49.1 监听
//     10920/10921/10922，仪表连入；实车：仪表的 10920/10922 拒绝外连）。
//     所以 iOS 端必须在 10920/10921/10922 上【监听】而不是拨出。
//
// 【会话流程（v0.7 · 静态逆向重建，推翻 v0.1~v0.6）】
//   1. 连上 10930 → **第一帧必须发 CLIENT_INFO(0x000103F0, JSON 18 字段)**。
//      旧版发的是裸握手 / 0x000103B0 / 0x00010010 / 0x00020020，全都缺这一帧，
//      仪表一律回 0x70000011 {"status":false} + RST —— 六版失败的根因。
//   2. 仪表走 checkPermission(flavor,channel) → checkClientPXCAuth →
//      onRequestPXCPermission（首次连接可能需仪表屏确认）。
//   3. 若应答带回 token/challenge，才有后续 encryptedHUID 与镜像协商。
//   4. 仪表连入镜像通道 → 0x0072 拉帧，我们按 0x0071 推 H.264（TODO probe）。
//
// 【诚实的可行性边界】encryptedHUID 的 RSA 明文格式与 token 由车机侧下发，
// 静态不可复现；纯 iOS 侧载 App 能否过授权仍需一次实车观测（dump 会记录真实应答）。
//

import Foundation
import Network

final class CarbitLinkOutput {

    // MARK: - 配置

    struct Configuration {
        /// 仪表 IP。连上仪表热点后一般是网关地址（实车 192.168.1.1）。
        var host: String = ""
        /// PXC 控制通道端口（仪表监听，实测）。
        var controlPort: UInt16 = 10930
        /// 镜像通道端口（我方监听，仪表连入）。
        var listenPorts: [UInt16] = [10920, 10921, 10922]
        /// 采集参数：请求开始镜像时上报，运行时被仪表下发值覆盖。
        var width: Int = 1152
        var height: Int = 640
        var wantFps: Int = 0
        var bitRate: Int = 3_145_728
        /// 仪表 huid（仪表 MAC 十二位十六进制大写），用于身份校验。
        /// 本车实测值来自 Android 抓包（亿连骑行 logcat）——
        /// 54:78:C9:66:5F:12，与热点名 kt_ap_665F12 / 蓝牙名 BXEY_665F13 尾部吻合。
        /// v0.5 实车验证：空 HUID 会被仪表以 {"status":false} 拒绝并断连。
        var huid: String = "5478C9665F12"
        var huName: String = "ufCX"
        /// 【v0.7】CLIENT_INFO 字段（来自 mDNS TXT 实测与 handleClientInfo 校验链）。
        /// 车机端会拿这两个值和自己广播的 flavor/channel 比对，不匹配直接拒绝。
        var flavor: Int = 50
        var channel: Int = 44001
        var sdkVersion: String = "5.1.1"
        var phoneOsVersion: String = "26.4.1"
        var phoneModel: String = "iPhone"
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
    /// 镜像通道的入站连接（仪表连入），可能有多条。
    private var mirrors: [ObjectIdentifier: NWConnection] = [:]
    /// 镜像通道监听器。
    private var listeners: [UInt16: NWListener] = [:]
    /// 每条连接一个解析器：不同通道帧头不同，半包也绝不能混。
    private var parsers: [ObjectIdentifier: CarbitLinkWire] = [:]
    private let queue = DispatchQueue(label: "carbitlink.output")
    private var isRunning = false
    private var controlReady = false
    /// 待发送的帧。拉模式下仪表每要一帧才推一次，只保留最新一帧。
    private var pendingFrame: Data?
    private var frameInFlight = false
    private var dumpHandle: FileHandle?
    private var droppedFrameCount = 0
    /// 上一次上报给 UI 的连接状态。只在真实跃变时回调。
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
            log("未填仪表 IP。请先连上仪表热点，再填网关地址。")
            if let gw = Self.suggestedGateway() {
                log("按本机地址推断，网关应该是 \(gw)，可直接填进设置。")
            }
            stopLocked()
            return
        }
        isRunning = true
        log("连接仪表 \(config.host):\(config.controlPort)（PXC 控制通道）")
        startMirrorListeners()
        connectControl()
    }

    private func stopLocked() {
        isRunning = false
        for listener in listeners.values { listener.cancel() }
        listeners.removeAll()
        for mirror in mirrors.values { mirror.cancel() }
        mirrors.removeAll()
        control?.cancel(); control = nil
        parsers.removeAll()
        controlReady = false
        pendingFrame = nil
        frameInFlight = false
        droppedFrameCount = 0
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

    // MARK: - 控制通道（PXC，拨出）

    private func connectControl() {
        guard isRunning else { return }
        guard let port = NWEndpoint.Port(rawValue: config.controlPort) else { return }
        let connection = NWConnection(host: NWEndpoint.Host(config.host), port: port, using: .tcp)
        control = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, self.control === connection else { return }
            switch state {
            case .ready:
                self.controlReady = true
                self.log("控制通道已连上 \(self.config.host):\(self.config.controlPort) ★")
                self.setConnected(true)
                self.beginControlSession()
            case .failed(let error):
                self.log("控制通道失败：\(error.localizedDescription)")
                connection.cancel()
            case .waiting(let error):
                self.log("控制通道等待中：\(error.localizedDescription)")
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, self.control === connection, !self.controlReady else { return }
            self.log("控制通道 8 秒未就绪")
            connection.cancel()
        }
    }

    private func beginControlSession() {
        // 【v0.7 · 静态逆向结论】10930 会话第一帧必须是 0x000103F0 CLIENT_INFO。
        // 旧实现（v0.1~v0.6）分别发过裸握手 JSON / 0x000103B0 / 0x00010010 /
        // 0x00020020，全都缺这一帧，仪表一律回 {"status":false} 然后 RST ——
        // 六版失败的根本原因。字段全表来自 handleClientInfo(@0x1bebec) 的字符串交叉引用。
        let info = CarbitLinkWire.clientInfoJSON(
            huid: config.huid, huName: config.huName,
            flavor: config.flavor, channel: config.channel,
            sdkVersion: config.sdkVersion,
            phoneOsVersion: config.phoneOsVersion, phoneModel: config.phoneModel
        )
        log("发送 CLIENT_INFO 0x000103F0（第一帧）：\(String(data: info, encoding: .utf8) ?? "-")")
        if let frame = try? CarbitLinkWire.pxcFrame(cmd: CarbitLinkWire.PXC.clientInfo, payload: info) {
            send(frame, on: control, tag: "ctl")
        }

        // 仪表应答观测点：
        //   · 回 ClientInfoRly（0x70000011 或 ...3F1）带 token/challenge → 授权链已启动，
        //     dump 里会有真实字段，可据此决定下一步（encryptedHUID 复现 / 仪表侧确认）。
        //   · 仍回 {"status":false} + RST → 说明 flavor/channel/加密HUID 未过校验，
        //     或仪表侧首次授权未确认。所有字节都会进 dump，不需要再猜。
        if let connection = control {
            receive(on: connection, tag: "ctl")
        }
    }

    // MARK: - 镜像通道（监听，仪表连入）

    private func startMirrorListeners() {
        for port in config.listenPorts {
            guard let nwPort = NWEndpoint.Port(rawValue: port) else { continue }
            // 快速 Stop/Start 重开会撞 EADDRINUSE（上一轮监听的关闭是异步的），
            // 允许端口复用。
            let parameters = NWParameters.tcp
            parameters.allowLocalEndpointReuse = true
            let listener: NWListener
            do {
                listener = try NWListener(using: parameters, on: nwPort)
            } catch {
                log("无法监听 \(port)：\(error.localizedDescription)")
                continue
            }
            listener.newConnectionHandler = { [weak self] connection in
                guard let self, self.isRunning else { connection.cancel(); return }
                self.log("镜像通道：仪表连入本地端口 \(port) ★")
                self.acceptMirror(connection, localPort: port)
            }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                if case .failed(let error) = state {
                    self.log("监听 \(port) 失败：\(error.localizedDescription)")
                }
            }
            listener.start(queue: queue)
            listeners[port] = listener
            log("已在 \(port) 监听，等待仪表连入")
        }
    }

    private func acceptMirror(_ connection: NWConnection, localPort: UInt16) {
        let tag = "mir\(localPort % 100)"
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.mirrors[ObjectIdentifier(connection)] = connection
                self.log("[\(tag)] 镜像通道就绪 ★")
                self.receive(on: connection, tag: tag)
            case .failed(let error):
                self.log("[\(tag)] 镜像连接失败：\(error.localizedDescription)")
                self.mirrors.removeValue(forKey: ObjectIdentifier(connection))
            case .cancelled:
                self.mirrors.removeValue(forKey: ObjectIdentifier(connection))
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    // MARK: - 收包

    private func receive(on connection: NWConnection, tag: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] chunk, _, isComplete, error in
            guard let self else { return }
            if let chunk, !chunk.isEmpty {
                if self.config.dumpsBytes { self.dump(chunk, tag: tag) }
                let parser = self.parser(for: connection)
                for event in parser.consume(chunk) {
                    self.handle(event: event, on: connection, tag: tag)
                }
            }
            if let error {
                self.log("[\(tag)] 接收中断：\(error.localizedDescription)")
                return
            }
            if isComplete {
                self.log("[\(tag)] 对端关闭了连接")
                self.mirrors.removeValue(forKey: ObjectIdentifier(connection))
                return
            }
            self.receive(on: connection, tag: tag)
        }
    }

    private func handle(event: CarbitLinkWire.Event, on connection: NWConnection, tag: String) {
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
                log("[\(tag)] 收到启动指令，载荷未解析出采集字段（已转储原始字节）")
            }
        case .ready:
            log("[\(tag)] 视频通道就绪（0x0070）")
        case .frameRequest:
            pumpFrameIfPossible()
        case .heartbeat(let code, let framing):
            // 心跳应答码未实测（TODO probe）：先按同一通道原样回显。
            if framing == .pxc {
                if let reply = try? CarbitLinkWire.pxcFrame(cmd: code) {
                    send(reply, on: connection, tag: "\(tag)-hb")
                }
            } else {
                if let reply = try? CarbitLinkWire.mirrorFrame(code: UInt16(code & 0xFFFF)) {
                    send(reply, on: connection, tag: "\(tag)-hb")
                }
            }
        case .unknown(let code, let payload, let framing):
            let kind = framing == .pxc ? "PXC" : "镜像"
            var text = "[\(tag)] \(kind)指令 0x\(String(format: "%08X", code))，\(payload.count) 字节：\(payload.hexDump(limit: 64))"
            // 载荷常是 JSON 状态（实车收到 {"status": false}），直接打文本更好读。
            if payload.first == UInt8(ascii: "{"),
               let json = String(data: payload, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !json.isEmpty {
                text += "  JSON: \(json)"
                let flat = json.filter { !$0.isWhitespace }
                if code == CarbitLinkWire.PXC.clientInfoReply, flat.contains("\"status\":false") {
                    log("⚠️ 仪表在授权层拒绝本次连接（CLIENT_INFO 未通过 checkPermission / checkClientPXCAuth）。"
                        + " 可能原因：flavor/channel 与仪表不匹配、encryptedHUID 为空、或首次连接需在仪表屏确认授权。")
                }
            }
            log(text)
        }
    }

    // MARK: - 推帧

    private func pumpFrameIfPossible() {
        guard isRunning, !frameInFlight, let frame = pendingFrame else { return }
        pendingFrame = nil
        // 镜像通道一条都没建立时不能硬发——发到 PXC 控制通道上语义就错了。
        guard let target = mirrors.values.first else {
            droppedFrameCount += 1
            if droppedFrameCount == 1 || droppedFrameCount % 120 == 0 {
                log("暂无镜像通道，已丢弃 \(droppedFrameCount) 帧（仪表连入 10920/10921/10922 后才会推帧）")
            }
            return
        }
        frameInFlight = true
        guard let packet = try? CarbitLinkWire.mirrorFrame(code: CarbitLinkWire.MirrorCode.videoFrame.rawValue, payload: frame) else {
            frameInFlight = false
            return
        }
        if config.dumpsBytes { dump(packet, tag: "mir-tx") }
        target.send(content: packet, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.frameInFlight = false
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
            if let error, !(self?.isCancellationSafe(error) ?? false) {
                self?.log("[\(tag)] 发送失败：\(error.localizedDescription)")
            }
        })
    }

    private func isCancellationSafe(_ error: Error) -> Bool {
        Self.isCancellation(error)
    }

    /// 连接被主动 cancel 时下层会回 ECANCELED，不算错误。
    static func isCancellation(_ error: Error) -> Bool {
        guard let nw = error as? NWError, case .posix(let code) = nw else { return false }
        return code == .ECANCELED
    }

    // MARK: - 解析器

    private func parser(for connection: NWConnection) -> CarbitLinkWire {
        let key = ObjectIdentifier(connection)
        if let existing = parsers[key] { return existing }
        // 控制通道是 PXC；仪表连入的镜像通道用 8 字节头。
        let created = connection === control
            ? CarbitLinkWire(framing: .pxc)
            : CarbitLinkWire(framing: .mirror)
        parsers[key] = created
        return created
    }

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
        说明：亿连输出启动后，这里记录每条 TCP 的收发字节（ctl/mirN/…-tx）
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
        let listenText = portList(config.listenPorts)
        write("")
        write("=== 新会话 \(ISO8601DateFormatter().string(from: Date())) ===")
        write("# 目标 host=\(config.host):\(config.controlPort)（PXC 控制通道）")
        write("# 镜像通道监听=\(listenText)（等待仪表连入）")
        write("# 本机 Wi-Fi 地址=\(ip)")
        write("# 采集参数=\(config.width)x\(config.height) @\(config.bitRate)bps huid=\(config.huid.isEmpty ? "-" : config.huid)")
    }

    /// 当前 Wi-Fi 口地址，写进 dump 方便判断"手机到底在哪个网段"。
    static func localWiFiAddress() -> String? {
        ReceiverConfiguration.localIPv4Addresses().first
    }

    /// 由本机 Wi-Fi 地址推断仪表网关：192.168.49.2 → 192.168.49.1。
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
