// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkOutput.swift
// 亿连（CarbitLink）仪表输出 —— v0.9，按 APK 静态逆向 + 原厂 logcat 重建握手。
//
// 【拓扑（已由反汇编 + 实车双重确认）】
//   · iPhone 连仪表热点 kt_ap_665F12（仪表即网关，实测 192.168.1.1）。
//   · 控制通道：手机主动连 仪表:10930，PXC 16 字节帧头。
//   · 镜像通道：iOS 端在 10920/10921/10922 上【监听】，等待仪表连入。
//
// 【v0.9 决定性纠错（dump(5) + libEPSDK.so 反汇编 + 原厂 logcat）】
//   · 0x70000011 {"status":false} 来自【PXC 会话准入层】，不是 handleClientInfo：
//     handleClientInfo(@0x1bebec) 失败只回 0x80000030、成功回 0x00010011，
//     函数体内没有 "status" 字符串、没有 0x70000011 常量，也不调用
//     checkPermission / checkClientPXCAuth。所以 v0.1~v0.8 六种载荷都没被解析。
//   · 准入层 checkClientPXCAuth(channel, uuid) 查本地 pxc_auth_file 的
//     channel&&uuid 记录 → 授权的是【原厂 App 的 (channel, phoneUUID) 组合】。
//     v0.8 用 channel=9975 + 随机 32 位 UUID，永远命中不了。
//   · 原厂真实身份（用户此前抓的 logcat，静态可得，无需再测）：
//       Link(channel)=44001 / LinkFlavor=50
//       phoneUUID=45f68d78-cd77-4c1a-a8cd-080249272b48（★ 带连字符）
//       Xiaomi / 2206122SC / Android / 35 / versionCode=37
//   · dump(5) 两次会话 3 秒静默实证：车机【从不主动发首帧】，它在等手机先上报。
//     v0.8「先静默等待车机 CLIENT_INFO」的假设被证伪 → v0.9 连上立即发。
//
// 【会话流程 v0.9】
//   1. 连上 10930 → 立即发 0x000103F0 + 原厂身份 + RSA 凭证。
//   2. 若车机先发带 HUID 的 CLIENT_INFO（本车未观察到）→ 回 0x00010011。
//   3. 准入通过后车机连入镜像通道 → 0x0072 拉帧，按 0x0071 推 H.264。
//
// 【RSA 凭证】见 CarbitLinkIdentity.swift。密钥本地生成并长期复用，
// 不需要蓝牙 / 热点 / 定位（ClientVerify.clearRefuseList 只清手机本地名单）。
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
        /// 【v0.9】准入层校验的是 (channel, phoneUUID)，必须照搬原厂 App：
        /// logcat `Link:44001 / LinkFlavor:50 / phoneUUID:45f68d78-…`。
        /// v0.8 的 channel=9975 + 随机 32 位 UUID 是致命回归，已废弃。
        var clientIdentity = CarbitLinkWire.ClientIdentity()
        /// 车机 HUID（二维码 sn=ehCs）。
        var huid: String = "ehCs"
        var huName: String = "ufCX"
        /// 本车实测 channel（logcat `Link:44001` / mDNS TXT / 二维码 modelid）。
        var flavor: Int = 50
        var channel: Int = 44001
        var sdkVersion: String = "5.1.1"
        var phoneOsVersion: String = "35"
        var phoneModel: String = "2206122SC"
        /// 二维码原文参数（本车实测，qr-decoded.txt）。
        var sn: String = "ehCs"
        var modelId: String = "44001"
        var wifiMac: String = "4B:F8:5F:0A:B2:E3"
        var qrAction: Int = 128
        /// 【v0.9】车机不主动发首帧，此值只用于「立即发送失败后」的兜底重试窗口。
        var carInfoWaitSeconds: Double = 3.0
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
    /// 【v0.8】本地 RSA 身份（跨会话复用，见 CarbitLinkIdentity）。
    private var identity: CarbitLinkIdentity?
    /// 是否已经对车机下发的 CLIENT_INFO 做过应答，避免重复回帧。
    private var didReplyToCarInfo = false
    /// 是否已发出兜底的主动 CLIENT_INFO。
    private var didSendProactiveInfo = false
    /// 本轮控制通道的代号，用于让「3 秒兜底」在断开/重连后自动失效。
    private var controlGeneration = 0

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
        didReplyToCarInfo = false
        didSendProactiveInfo = false
        controlGeneration += 1
        // dump 先开，哪怕 host 是空的也留一条记录，免得用户以为功能没跑。
        openDumpIfNeeded()
        // 【v0.8】本地 RSA-1024 身份（对齐 Android RSAUtil 的 SharedPreferences 复用）。
        if identity == nil {
            do {
                identity = try CarbitLinkIdentity()
                log("RSA-1024 身份已就绪，pubkey \(identity?.publicKeyBase64.count ?? 0) 字符")
            } catch {
                log("⚠️ RSA 身份创建失败：\(error.localizedDescription)")
            }
        }
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
        // 让尚未触发的「3 秒兜底」失效，避免旧会话往新连接发帧。
        controlGeneration += 1
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
        // 【v0.9】dump(5) 两次会话实证：车机在 10930 上【从不主动发首帧】，
        // 它在等手机先上报 CLIENT_INFO。v0.8「先静默等 3 秒」的假设被证伪。
        // 静态证据一致：0x70000011 {"status":false} 来自 PXC 准入层
        // （checkClientPXCAuth），不是 handleClientInfo 的任何失败分支。
        log("控制通道就绪：v0.9 立即上报 CLIENT_INFO（车机不主动发首帧，dump(5) 实证）")
        if let connection = control {
            receive(on: connection, tag: "ctl")
        }
        sendProactiveClientInfo()

        // 保留一次兜底：仅当立即发送因 RSA 身份未就绪等原因没发成时重试。
        // didSendProactiveInfo 已置位时这里直接返回，不会重复发帧。
        let generation = controlGeneration
        let wait = config.carInfoWaitSeconds
        queue.asyncAfter(deadline: .now() + wait) { [weak self] in
            guard let self = self, self.isRunning, self.controlGeneration == generation else { return }
            if self.didReplyToCarInfo || self.didSendProactiveInfo { return }
            self.sendProactiveClientInfo()
        }
    }

    /// 【v0.9】连上 10930 立即上报：0x000103F0 + 原厂身份 + 真实 RSA 凭证。
    private func sendProactiveClientInfo() {
        guard let identity = identity else {
            log("⚠️ 无 RSA 身份，CLIENT_INFO 未发送（等待兜底重试）")
            return
        }
        didSendProactiveInfo = true
        let who = config.clientIdentity
        let encrypted: String
        do {
            encrypted = try identity.encryptedHUID(who.huid)
        } catch {
            log("⚠️ HUID 加密失败：\(error.localizedDescription)")
            return
        }
        let info = CarbitLinkWire.clientInfoJSON(
            identity: who,
            pubkey: identity.publicKeyBase64, encryptedHUID: encrypted
        )
        log("上报 CLIENT_INFO 0x000103F0（channel=\(who.channel) phoneUUID=\(who.phoneUUID)）："
            + "\(String(data: info, encoding: .utf8) ?? "-")")
        if let frame = try? CarbitLinkWire.pxcFrame(cmd: CarbitLinkWire.PXC.clientInfo, payload: info) {
            send(frame, on: control, tag: "ctl")
        }
    }

    /// 收到车机下发的 CLIENT_INFO → 回 0x00010011（u0() 字段集）。
    /// 【v0.9】若已经主动上报过，就不再回，避免一会话发两帧。
    private func replyToCarClientInfo(_ carHUID: String, channel: String, flavor: Int,
                                     sdkVersion: String, on connection: NWConnection,
                                     requestCode: UInt32) {
        guard !didReplyToCarInfo, !didSendProactiveInfo, let identity = identity else {
            log("⚠️ 无 RSA 身份 / 已应答 / 已主动上报，跳过 CLIENT_INFO 应答")
            return
        }
        didReplyToCarInfo = true
        let who = config.clientIdentity
        let encrypted: String
        do {
            encrypted = try identity.encryptedHUID(carHUID)
        } catch {
            log("⚠️ 车机 HUID 加密失败：\(error.localizedDescription)")
            return
        }
        let reply = CarbitLinkWire.clientInfoReplyJSON(
            identity: who, carHUID: carHUID,
            pubkey: identity.publicKeyBase64, encryptedHUID: encrypted
        )
        let replyCode = CarbitLinkWire.PXC.carClientInfoReply
        log("★ 收到车机 CLIENT_INFO（cmd=0x\(String(format: "%08X", requestCode))，"
            + "HUID=\(carHUID) channel=\(channel) flavor=\(flavor) sdk=\(sdkVersion)）"
            + " → 回 0x\(String(format: "%08X", replyCode))：\(String(data: reply, encoding: .utf8) ?? "-")")
        if let frame = try? CarbitLinkWire.pxcFrame(cmd: replyCode, payload: reply) {
            send(frame, on: connection, tag: "ctl")
        }
    }

    /// 【v0.9】原厂 App 的 phoneUUID（logcat `phoneUUID : 45f68d78-…`）。
    /// 准入层 checkClientPXCAuth 查的就是它，绝不能随机生成。
    static func stablePhoneUUID() -> String {
        CarbitLinkWire.ClientIdentity().phoneUUID
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
            if payload.first == UInt8(ascii: "{"),
               let json = String(data: payload, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !json.isEmpty {
                text += "  JSON: \(json)"
                // 【v0.8 被动路径】车机下发的 CLIENT_INFO 一定带 HUID；
                // {"status":false} 不含 HUID，不会误触发。
                if let car = CarbitLinkWire.parseCarClientInfo(payload) {
                    log(text)
                    replyToCarClientInfo(car.huid, channel: car.channel, flavor: car.flavor,
                                         sdkVersion: car.sdkVersion, on: connection,
                                         requestCode: code)
                    return
                }
                let flat = json.filter { !$0.isWhitespace }
                if code == CarbitLinkWire.PXC.clientInfoReply, flat.contains("\"status\":false") {
                    log("⚠️ 车机准入层回 0x70000011 {\"status\":false}（不是 handleClientInfo 的应答）。"
                        + " 反汇编实证：handleClientInfo 失败只回 0x80000030、成功回 0x00010011，"
                        + " 函数体内无 status 串也无 0x70000011，且不调用 checkClientPXCAuth。"
                        + " → 载荷根本没被解析，卡在 PXC 会话准入（pxc_auth_file 的 channel&&uuid）。"
                        + " v0.9 已改用原厂 (channel=44001, phoneUUID=45f68d78-…) 身份；"
                        + " 若仍是这一帧，则仪表授权文件里没有该记录，纯侧载无法自证。")
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
        write("# 采集参数=\(config.width)x\(config.height) @\(config.bitRate)bps huid=\(config.clientIdentity.huid)")
        write("# 客户端身份 v0.9：channel=\(config.clientIdentity.channel) phoneUUID=\(config.clientIdentity.phoneUUID) flavor=\(config.clientIdentity.flavor)")
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
