// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkOutput.swift
// 亿连（CarbitLink）仪表输出 —— v1.0，第一帧命令码定案（PLT→GOT→符号铁证）。
//
// 【拓扑（已由反汇编 + 实车双重确认）】
//   · iPhone 连仪表热点 kt_ap_665F12（仪表即网关，实测 192.168.1.1）。
//   · 控制通道：手机主动连 仪表:10930，PXC 16 字节帧头。
//   · 镜像通道：iOS 端在 10920/10921/10922 上【监听】，等待仪表连入。
//
// 【v1.0 决定性纠错（dump(6) + libEPSDK.so PLT/GOT 全链解析）】
//   · v0.1~v0.9 一直用 0x000103F0 发 CLIENT_INFO，但那个码的真实 handler 是
//     C2PMainService::handleOpenPage（打开页面）；真正的 CLIENT_INFO 是
//     0x00010010 → handleClientInfo。载荷从未被解析 → 车机永远回同一帧
//     0x70000011 {"status":false} + RST，与字段 / 身份 / RSA 全部无关。
//   · handleClientInfo 成功回 0x00010011、失败回 0x80000030；这两个码在
//     v0.1~v0.9 的 dump 里从未出现过，正是「载荷没进门」的旁证。
//   · v1.0 只把首帧命令码改成 0x00010010，其余（原厂身份、立即发送时序、
//     RSA 凭证）全部沿用 v0.9 已证实正确的部分。
//
// 【会话流程 v1.0】
//   1. 连上 10930 → 立即发 0x00010010 + 原厂身份 + RSA 凭证。
//   2. 车机 handleClientInfo → 0x00010011 成功 / 0x80000030 失败。
//   3. 通过后车机连入镜像通道 → 0x0072 拉帧，按 0x0071 推 H.264。
//
// 【RSA 凭证】见 CarbitLinkIdentity.swift。密钥本地生成并长期复用，
// 不需要蓝牙 / 热点 / 定位（ClientVerify.clearRefuseList 只清手机本地名单）。
//

import Foundation
import Network

final class CarbitLinkOutput {

    // MARK: - 配置

    struct Configuration {
        /// 仪表 IP。保留供「主动连」的旧路径与诊断用；v1.1 默认不再拨出。
        var host: String = ""
        /// 【v1.1】不再主动拨这个端口。10930 只是 mDNS TXT 里的广播值，不是 TCP 口。
        var controlPort: UInt16 = 10930
        /// 【v1.1】仪表会主动连入的端口。原厂实测：10922 = PXC 控制口
        /// （`PXCService: accept pxc ... localPort=10922` ×4），10920 = 镜像通道。
        /// 10921 原厂日志里没出现（v1.0 是我方猜的），先保留监听但标低优先级。
        var controlListenPort: UInt16 = 10922
        /// 镜像通道端口（我方监听，仪表连入）。
        var listenPorts: [UInt16] = [10920, 10921]
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
        /// 【v1.1】等仪表下发 CLIENT_INFO 的窗口。原厂实测仪表连上后 ~50ms 就发，
        /// 给 8 秒足够；超时只记录、不主动发帧（主动发就是 v1.0 那个错误）。
        var carInfoWaitSeconds: Double = 8.0
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
    /// 【v1.1】是否已按仪表下发的 CLIENT_INFO 做过应答 + 发过手机侧首帧。
    private var didCompleteHandshake = false
    /// 【v1.1】控制通道监听器（10922，仪表连入）。
    private var controlListener: NWListener?
    /// 本轮控制通道的代号，用于让定时任务在断开/重连后自动失效。
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
        didCompleteHandshake = false
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
        // 【v1.1】不再要求填仪表 IP，也不因为暂时没 Wi-Fi 地址就拒绝启动：
        // 方向改成「我方监听，仪表连入」。没有地址只提示，监听照开——
        // 手机可能比仪表热点晚一步拿到 IP，先绑端口不会有坏处。
        isRunning = true
        if let ip = Self.localWiFiAddress() {
            log("本机地址 \(ip)。v1.1 监听模式：等仪表连入，不主动拨出。")
        } else {
            log("⚠️ 暂时没拿到 Wi-Fi 地址。监听仍会开启，但请确认已连上仪表热点（kt_ap_xxxxxx），"
                + "否则仪表连不进来。")
        }
        startMirrorListeners()
        startControlListener()
    }

    private func stopLocked() {
        isRunning = false
        // 让尚未触发的定时任务失效，避免旧会话往新连接发帧。
        controlGeneration += 1
        for listener in listeners.values { listener.cancel() }
        listeners.removeAll()
        controlListener?.cancel(); controlListener = nil
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

    // MARK: - 控制通道（PXC，v1.1 改为监听 10922）
    //
    // 【v1.1 方向定案】原厂 App 会话（easyride-log/ec_pid.txt 实测）：
    //   `PXCService: listening client {…localport=10922}` → `accept pxc` ×4
    //   → `PXCForCar-C2P: receive <<< 0x00010010:ECP_C2P_CLIENT_INFO`
    // 即：**手机监听、仪表拨入、仪表先发**。
    // v0.1~v1.0 十版都反着做（手机拨 10930 并抢先发 0x00010010），
    // 所以每版都收到 `0x70000011 {"status":false}`（对未识别命令的 NAK）后 RST。

    private func startControlListener() {
        let port = config.controlListenPort
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            log("控制端口 \(port) 非法")
            return
        }
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        let listener: NWListener
        do {
            listener = try NWListener(using: parameters, on: nwPort)
        } catch {
            log("无法监听控制端口 \(port)：\(error.localizedDescription)")
            return
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self, self.isRunning else { connection.cancel(); return }
            self.acceptControl(connection)
        }
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .failed(let error) = state {
                self.log("控制端口 \(port) 监听失败：\(error.localizedDescription)")
            }
        }
        listener.start(queue: queue)
        controlListener = listener
        log("已在 \(port) 监听（PXC 控制口），等仪表连入")
    }

    private func acceptControl(_ connection: NWConnection) {
        control = connection
        controlGeneration += 1
        let generation = controlGeneration
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, self.control === connection else { return }
            switch state {
            case .ready:
                self.controlReady = true
                self.setConnected(true)
                self.beginControlSession(generation: generation)
            case .failed(let error):
                self.log("[ctl] 控制通道失败：\(error.localizedDescription)")
                connection.cancel()
            case .cancelled:
                self.controlReady = false
                if self.control === connection { self.control = nil }
                self.setConnected(false)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// 【v1.1】连上后**不发任何帧**，只挂接收。
    /// 原厂时序：仪表连入后约 50ms 就发 `0x00010010`，我方等它即可。
    private func beginControlSession(generation: Int) {
        guard let connection = control else { return }
        log("[ctl] 仪表已连入控制通道，v1.1 静默等待它下发 CLIENT_INFO（不自报）")
        receive(on: connection, tag: "ctl")

        // 超时只提示，**不兜底发帧**——主动发就是 v1.0 那个错误。
        let wait = config.carInfoWaitSeconds
        queue.asyncAfter(deadline: .now() + wait) { [weak self] in
            guard let self, self.isRunning, self.controlGeneration == generation else { return }
            if self.didCompleteHandshake { return }
            self.log("⚠️ \(Int(wait)) 秒内没收到仪表 CLIENT_INFO（0x00010010）。"
                + "查：仪表是否真的主动连入、端口 10922 是否被占用。")
        }
    }

    /// 【v1.1】收到仪表下发的 `0x00010010` 后的完整应答序列。
    /// 顺序照搬原厂 logcat 的 `PXCForCar-P2C: process >>>` 时序：
    /// 能力应答 → 启动音频(0x20490) → 屏幕信息(0x20020) → 音频状态(0x20310)
    /// → 缓冲控制(0x20050) → 请求开始镜像(0x201C0)。
    private func handleCarClientInfo(_ payload: Data, on connection: NWConnection) {
        guard !didCompleteHandshake else {
            log("[ctl] 已握手过，忽略重复的 CLIENT_INFO")
            return
        }
        guard let cap = CarbitLinkWire.parseCarCapability(payload) else {
            log("[ctl] ⚠️ 0x00010010 载荷解析不出能力位（channel/flavor 都空），原始字节已转储")
            return
        }
        didCompleteHandshake = true

        log("★ 收到仪表 CLIENT_INFO：HUID=\(cap.huid) HUName=\(cap.huName) "
            + "channel=\(cap.channel) flavor=\(cap.flavor) sdk=\(cap.sdkVersion) "
            + "productType=\(cap.productType) supportConnect=\(cap.supportConnect) "
            + "mirror=\(cap.supportScreenMirroring) touch=\(cap.supportScreenTouch) "
            + "mirrorMode=\(cap.mirrorMode)")

        // 1. 能力应答：仪表声明什么就回什么，channel 保持字符串。
        sendOptional(CarbitLinkWire.PXC.carClientInfoReply,
                     payload: capabilityReplyJSON(cap), on: connection,
                     note: "能力应答 0x00010011")

        // 2. 启动音频
        sendOptional(CarbitLinkWire.PXC.startAudio, payload: nil, on: connection,
                     note: "启动音频 0x00020490")

        // 3. 屏幕信息
        let screen = Self.phoneScreenSize()
        let screenJSON = CarbitLinkWire.phoneScreenJSON(
            displayRotation: 0, width: screen.width, height: screen.height,
            enableAccessibility: false)
        sendOptional(CarbitLinkWire.PXC.screenInfo, payload: screenJSON, on: connection,
                     note: "屏幕信息 0x00020020（\(screen.width)×\(screen.height)）")

        // 4. 音频状态
        sendOptional(CarbitLinkWire.PXC.audioStatus,
                     payload: CarbitLinkWire.audioStatusJSON(isMute: false, isLogin: false),
                     on: connection, note: "音频状态 0x00020310")

        // 5. 缓冲控制
        sendOptional(CarbitLinkWire.PXC.queueControl, payload: nil, on: connection,
                     note: "缓冲控制 0x00020050")

        // 6. 请求开始镜像
        sendOptional(CarbitLinkWire.PXC.requestStartMirror, payload: nil, on: connection,
                     note: "请求开始镜像 0x000201C0")

        log("[ctl] 握手序列已发完。等镜像通道（10920）连入并下发 0x0010 采集参数。")
    }

    /// 能力应答载荷。仪表声明什么就回什么。
    private func capabilityReplyJSON(_ cap: CarbitLinkWire.CarCapability) -> Data {
        let who = config.clientIdentity
        let object: [String: Any] = [
            "sdkVersion": who.sdkVersion,
            "pxcVersion": who.pxcVersion,
            "flavor": cap.flavor != 0 ? cap.flavor : who.flavor,
            // ★ 原厂是字符串 "44001"，不是整数。
            "channel": cap.channel.isEmpty ? String(who.channel) : cap.channel,
            "HUID": cap.huid,
            "HUName": who.huName,
            "phoneUUID": who.phoneUUID,
            "phoneBrand": who.phoneBrand,
            "phoneModel": who.phoneModel,
            "phoneOs": who.phoneOs,
            "phoneOsVersion": who.phoneOsVersion,
            "package_name": who.packageName,
            "versionCode": who.versionCode,
            "screenType": 1,
            "productType": cap.productType != 0 ? cap.productType : 3,
            "supportFunction": who.action,
            "supportMic": false,
            "supportBackDesktop": true,
            "wakeupWord": ""
        ]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    /// 发一帧 PXC；失败只记日志，不中断后续步骤。
    private func sendOptional(_ cmd: UInt32, payload: Data?, on connection: NWConnection, note: String) {
        let body = payload ?? Data()
        guard let frame = try? CarbitLinkWire.pxcFrame(cmd: cmd, payload: body) else {
            log("[ctl] ⚠️ \(note) 组包失败")
            return
        }
        log("[ctl] 发送 \(note)，\(body.count) 字节载荷")
        send(frame, on: connection, tag: "ctl")
    }

    /// 手机屏幕像素尺寸。原厂实测 1440×3200，与真机一致时直接可用。
    static func phoneScreenSize() -> (width: Int, height: Int) {
        (1440, 3200)
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
        case .carClientInfo(let payload):
            // 【v1.1】仪表在控制通道下发的 CLIENT_INFO —— 真正握手的起点。
            guard tag == "ctl" else {
                log("[\(tag)] 非控制通道收到 carClientInfo，忽略")
                return
            }
            handleCarClientInfo(payload, on: connection)
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
            let raw = String(data: payload, encoding: .utf8) ?? ""
            let flat = raw.filter { !$0.isWhitespace }

            // 【v1.1】判据按真实方向重写：
            //   收 0x00010010 → 仪表能力通告（已由 .carClientInfo 事件单独处理）
            //   收 0x70000011 → 仪表对未识别命令的 NAK（说明我方发错了码）
            switch code {
            case CarbitLinkWire.PXC.unsupportedNack:
                log("⚠️ 仪表回了 0x70000011 NAK（{\"status\":false}）："
                    + "说明我方发了它不认识的命令码。v1.1 不应再出现——"
                    + "若出现，查是否还有 0x0001xxxx 段的主动发送。")
            case CarbitLinkWire.PXC.clientInfoNack:
                log("⚠️ 仪表回了 0x80000030：载荷进门但 flavor/channel 校验不过。")
            default:
                break
            }

            if payload.first == UInt8(ascii: "{"),
               let json = String(data: payload, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !json.isEmpty {
                text += "  JSON: \(json)"
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
        write("# 客户端身份 v1.0：首帧 cmd=0x00010010 (handleClientInfo) channel=\(config.clientIdentity.channel) phoneUUID=\(config.clientIdentity.phoneUUID) flavor=\(config.clientIdentity.flavor)")
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
