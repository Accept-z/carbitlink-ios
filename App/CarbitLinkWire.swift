// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkWire.swift
// 亿连（CarbitLink）线上格式 —— v1.0，第一帧命令码定案（PLT→GOT→符号铁证）。
//
// 【v1.0 决定性纠错 —— dump(6) + libEPSDK.so PLT/GOT 全链解析】
//   v0.1~v0.9 九个版本都把 CLIENT_INFO 载荷装在 0x000103F0 里发出去。
//   C2PMainService::handleCMD(@0x1be944) 的 case 分支经 PLT 桩 → GOT 重定位
//   → .dynsym 解析后，真实映射是：
//       0x00010010 → PLT 0x3706e0 → GOT 0x3b21b8 → handleClientInfo  ★
//       0x000103F0 → PLT 0x3706d0 → GOT 0x3b21b0 → handleOpenPage    ✗
//   即 0x000103F0 是「打开页面」，不是 CLIENT_INFO。车机按 openPage 处理，
//   收到一整包身份 JSON 参数对不上，直接回通用拒绝 0x70000011
//   {"status":false} 并 RST —— 载荷从未被 handleClientInfo 解析过一次。
//   这解释了为什么 378B / 1060B / 1070B 三种载荷、Apple / Xiaomi 两种身份、
//   channel 9975 / 44001、有无 RSA，回车全是字节级相同的同一帧。
//
//   handleClientInfo(@0x1bebec) 解析的键正是我们构造的字段：
//     sdkVersion / flavor / channel / productType / supportMic / …，
//   成功回 0x00010011（= 0x10010 + 1；函数内 0x1beee4 构造），
//   失败（JSON 格式错 / flavor|channel 缺失 / checkPermission 不过）回 0x80000030，
//   日志前缀 `[P2CService]handleClientInfo: flavor or channel is not exist`。
//   → 手机第一帧必须是 0x00010010，既不是 0x000103F0，也不是「等车机先发」。
//
// 【完整 case 表（PLT→GOT→符号，静态实锤，推翻 v0.9 旧表）】
//   0x00010010 handleClientInfo         0x00010020 handleEnableDownloadPhoneAudio
//   0x00010060 handleMicRecordData      0x00010200 handleNightMode
//   0x00010350 handleBtnEvent           0x000103B0 handleCheckCarUUID (→0x103B1)
//   0x000103E0 handleCheckSN (→0x103E1)
//   0x000103F0 handleOpenPage           ← 前 9 版误用
//   0x00010410 handleCheckNetwork      0x00010430 handleQueryGPS
//   0x00010450 handleQueryTime         0x00010750 handleCheckAppNetworkCapability
//   0x00010780 handleRunningLog
//
// 【0x70000011 的真身】C2PService::handleCMD(@0x1c1b08) 只处理心跳 0x70000001；
//   handleUnSupport(@0x1c1cd0) 无 status 串；全 so 里 "status" 的 4 处 xref 落在
//   handleCheckNetwork / handleQueryGPS / handleCheckAppNetworkCapability /
//   notifyPageStatusChanged，均不生成 0x70000011。0x3addd 起是
//   0x??000011 一族「服务号 + 通用操作码 0x0011」的码表。
//   → 该帧出自【仪表固件】，不在手机 APK 内，是非法命令/会话准入的通用拒绝。
//
// 【v0.9 保留的正确部分】原厂身份（channel=44001、带连字符 phoneUUID、
//   Xiaomi/2206122SC/Android/35、versionCode=37）、连上立即发的时序、
//   RSA-1024 SPKI pubkey + encryptedHUID —— 全部保留，只换命令码。
//
// 【帧格式（静态 + 实车双重确认，两端 libEPSDK.so MD5 完全相同）】
//   · PXC 控制通道 10930：16 字节头
//       [0..3]  cmd   u32 LE   指令码（高 16 位服务号，低 16 位操作码）
//       [4..7]  total u32 LE   = 16 + 载荷长度
//       [8..11] cmd ^ total    校验字
//       [12..15] version u32   版本（回复时原样带回）
//     实车：仪表回 `11 00 00 70 | 24 00 00 00 | 35 00 00 70 | 00 00 00 00`
//     = cmd 0x70000011 / total 36 / 校验 0x70000035，0x70000011^0x24=0x70000035 ✓
//   · MirrorService::sendCMD（@0x1d5a38）：镜像通道帧头 8 字节 ——
//       [0..1] code u16 LE   [2..3] len u16 LE   [4..7] param u32 LE
//
// 【v1.0 判据（装包后 dump 一眼可判，不再迭代）】
//   · 出现 0x00010011 = handleClientInfo 成功，握手推进 ✅
//   · 出现 0x80000030 = 载荷已被解析但 checkPermission 不过 → 字段问题，静态可再查
//   · 仍是 0x70000011 {"status":false} = 仪表固件层拒绝，纯侧载无法自证 → 收敛路线 A
//   · 手机推帧的镜像码：暂定 0x0071（TODO probe）；心跳应答码：先原样回显。
//

import Foundation

enum CarbitLinkWireError: Error, LocalizedError {
    case malformed(String)
    var errorDescription: String? {
        if case .malformed(let m) = self { return m }
        return nil
    }
}

final class CarbitLinkWire {

    // MARK: - 通道与指令码

    /// 两条通道各自一套帧头。
    enum Framing {
        /// 控制通道（10922）：16 字节头。
        case pxc
        /// 镜像通道（10920/10921）：8 字节头。
        case mirror
    }

    /// PXC 控制通道指令（32 位）。低 16 位是操作码，高 16 位是服务号。
    ///
    /// 【v1.1 方向定案 —— dump(7) + 原厂 logcat 双证】
    /// `C2P` = Car → Phone（仪表发给手机），`P2C` = Phone → Car。
    /// 原厂实测（easyride-log/ec_pid.txt，整场会话统计）：
    ///   收：仅 `0x00010010 ECP_C2P_CLIENT_INFO`  ×2
    ///   发：`0x00020030` ×94 / `0x00020020` ×47 / `0x000201D0` ×3 /
    ///       `0x00020050` ×3 / `0x00020310` ×2 / `0x00020490` ×2 /
    ///       `0x000204B0` ×2 / `0x000201C0` ×1
    /// 即：**手机只收 0x0001xxxx，只发 0x0002xxxx**。
    /// v0.1~v1.0 十版都把 `0x00010010` 当手机上报帧主动发出去，方向反了，
    /// 仪表按「未识别命令」回 `0x70000011 {"status":false}` 并 RST。
    enum PXC {
        /// 【仪表 → 手机】CLIENT_INFO 能力通告，手机侧**只收不发**。
        /// 对应 `C2PMainService::handleClientInfo`（@0x1bebec）在仪表侧被调用。
        static let carClientInfo: UInt32 = 0x00010010
        /// 手机 → 仪表：能力应答，`0x00010010 + 1`（handleClientInfo 成功码）。
        /// 原厂 logcat 里没观测到（手机不回它），保留常量供实验对照。
        static let carClientInfoReply: UInt32 = 0x00010011
        /// 仪表 → 手机：CLIENT_INFO 失败码（仅当手机错误地发 0x00010010 时出现）。
        static let clientInfoNack: UInt32 = 0x80000030
        // MARK: 手机 → 仪表（P2C，0x0002xxxx），全部取自原厂实测

        /// 屏幕信息，载荷是 JSON（含 displayRotation/width/height）。
        static let screenInfo: UInt32 = 0x00020020
        /// 屏幕信息（周期性重发版，原厂 94 次，最高频）。
        static let screenInfoRepeat: UInt32 = 0x00020030
        /// 队列/缓冲控制（原厂载荷 `rst:0 queue size:N`）。
        static let queueControl: UInt32 = 0x00020050
        /// 请求开始镜像。
        static let requestStartMirror: UInt32 = 0x000201C0
        /// 请求亿连切到前台。
        static let requestForeground: UInt32 = 0x000201D0
        /// 音频状态（载荷 `ismute:false,isLogin:false`）。
        static let audioStatus: UInt32 = 0x00020310
        /// 启动音频通道。
        static let startAudio: UInt32 = 0x00020490
        /// 触发 ECP_C2P_ENABLE_DOWNLOAD_PHONE_HUD。
        static let enableDownloadPhoneHud: UInt32 = 0x000204B0

        /// 仪表回给错误命令码的通用 NAK：`0x70000000 | 0x11`。
        /// `0x70000000` 是 C2PService 服务基址（C2PService::handleCMD @0x1c1b24
        /// 里有 `mov w9, #0x70000000`），0x11 是状态操作码。
        static let unsupportedNack: UInt32 = 0x70000011

        /// 校验回复码规律：请求 +1。
        static let checkCarUUID: UInt32 = 0x000103B0
        static let checkCarUUIDReply: UInt32 = 0x000103B1
        static let checkSN: UInt32 = 0x000103E0
        /// 【v1.0 留档】0x000103F0 = handleOpenPage，前 9 版误用它发身份包。
        static let openPage: UInt32 = 0x000103F0
        /// v1.0 修正后的 case 表常量（旧表把 0x10010 标成 nightMode 是错的）。
        /// 属 C2P 段，手机不主动发。
        static let nightMode: UInt32 = 0x00010200
        static let btnEvent: UInt32 = 0x00010350
    }

    /// 镜像通道指令（16 位）。
    /// 全部取自原厂会话实测（`Protocol: ... sixteenBitSize(1152,640)` 及镜像通道日志）。
    enum MirrorCode: UInt16 {
        /// 仪表下发采集参数（镜像启动）。
        case start        = 0x0010
        /// 视频通道就绪。
        case ready        = 0x0070
        /// 仪表拉帧：每要一帧发一条（拉模式）。
        case frameRequest = 0x0072
        /// 心跳。
        case heartbeat    = 0x0040
        /// 手机推帧。原厂反汇编里 `sendCMD` 的推帧分支用 0x71（0x0072 的应答码），
        /// 属「请求+1」规律；仍标 TODO(probe)，第一次上车以 dump 里是否断流为准。
        case videoFrame   = 0x0071
    }

    // MARK: - 【v0.9】客户端身份（原厂 App 实测值，准入层按 channel+phoneUUID 校验）

    /// 全部取自用户此前抓取的原厂 logcat（AppCommonInfoPrinter）与二维码。
    /// 车机 EPSDKContext::checkClientPXCAuth(channel, uuid) 查 pxc_auth_file 时
    /// 用的就是 channel 与 phoneUUID，所以这里必须【照搬原厂】，不能自己随机生成。
    struct ClientIdentity {
        /// 二维码 sn=ehCs（WiFiDirectReceiver.saveConnectInfo → ClientVerify.setCarUUID(sn)）。
        var huid: String = "ehCs"
        var huName: String = "ufCX"
        /// logcat: LinkFlavor: 50
        var flavor: Int = 50
        /// logcat: Link:44001 —— 也是二维码 modelid、mDNS TXT channel。
        /// v0.8 误改成 9975 是错的，v0.9 恢复。
        var channel: Int = 44001
        var sdkVersion: String = "5.1.1"
        var pxcVersion: String = "1.0.2"
        /// logcat: phoneUUID : 45f68d78-cd77-4c1a-a8cd-080249272b48
        /// ★ 带连字符的 36 字符标准 UUID，不是 32 位无连字符随机串。
        var phoneUUID: String = "45f68d78-cd77-4c1a-a8cd-080249272b48"
        var phoneBrand: String = "Xiaomi"
        var phoneModel: String = "2206122SC"
        var phoneOs: String = "Android"
        /// logcat: phoneOsVersion: 35（Build.VERSION.SDK_INT 的字符串）
        var phoneOsVersion: String = "35"
        var packageName: String = "net.easyconn.carman.easyride"
        /// logcat: versionCode: 37
        var versionCode: Int = 37
        /// logcat: speechEngine：IFY_FREE, engine = 2
        var speechEngineType: Int = 2
        var sn: String = "ehCs"
        var modelId: String = "44001"
        var wifiMac: String = "4B:F8:5F:0A:B2:E3"
        var action: Int = 128
    }

    // MARK: - 采集参数

    struct CaptureConfig: Equatable {
        var width: Int = 1152
        var height: Int = 640
        var wantFps: Int = 0
        var encoder: Int = 2
        var bitRate: Int = 3_145_728
        var physicalWidth: Int = 0
        var physicalHeight: Int = 0
        var dpi: Int = 0
        var quality: Int = 0
        var isPullMode: Bool { wantFps == 0 }
    }

    enum Event {
        case start(CaptureConfig?)
        case ready
        case frameRequest
        case heartbeat(code: UInt32, framing: Framing)
        /// 【v1.1】仪表在控制通道下发的 CLIENT_INFO（`0x00010010`），载荷是 JSON。
        /// 这是手机侧**唯一**该等的握手帧；收到后按原厂字段集回能力 + 发 0x0002xxxx 首帧。
        case carClientInfo(Data)
        case unknown(code: UInt32, payload: Data, framing: Framing)
    }

    // MARK: - 常量

    static let pxcHeaderSize = 16
    static let mirrorHeaderSize = 8
    /// 镜像通道单帧载荷上限（MirrorService::sendCMD 里缓冲 0x2800）。
    static let maxPayload = 10240

    // MARK: - 状态

    private let framing: Framing
    private var buffer = Data()
    private(set) var config = CaptureConfig()

    init(framing: Framing = .mirror) {
        self.framing = framing
    }

    // MARK: - 组包（发送）

    /// PXC 帧：16 字节头 + 载荷。
    static func pxcFrame(cmd: UInt32, payload: Data = Data(), version: UInt32 = 0) throws -> Data {
        let total = UInt32(pxcHeaderSize + payload.count)
        var out = Data(capacity: Int(total))
        out.appendLE32(cmd)
        out.appendLE32(total)
        out.appendLE32(cmd ^ total)
        out.appendLE32(version)
        out.append(payload)
        return out
    }

    /// 镜像帧：8 字节头 + 载荷。
    static func mirrorFrame(code: UInt16, param: UInt32 = 0, payload: Data = Data()) throws -> Data {
        guard payload.count <= maxPayload else {
            throw CarbitLinkWireError.malformed("载荷 \(payload.count) 超过镜像帧上限 \(maxPayload)")
        }
        var out = Data(capacity: mirrorHeaderSize + payload.count)
        out.appendLE16(code)
        out.appendLE16(UInt16(payload.count))
        out.appendLE32(param)
        out.append(payload)
        return out
    }

    /// 推一帧 H.264（Annex-B）。TODO(probe) 响应码与 param 含义待实测。
    func videoFrame(annexB: Data) throws -> Data {
        try Self.mirrorFrame(code: MirrorCode.videoFrame.rawValue, payload: annexB)
    }
    /// 【v1.1】手机侧屏幕信息帧（P2C `0x00020020` / `0x00020030`）。
    /// 字段照搬原厂 logcat：
    /// `{"displayRotation":0,"width":1440,"height":3200,"enableAccessibility":false,
    ///   "enableAOAHid…}`（原厂只打印了前 100 字符，实测出现的键都在这里）。
    /// `width/height` 是**手机屏幕**像素，不是采集分辨率；采集参数走镜像通道。
    static func phoneScreenJSON(
        displayRotation: Int, width: Int, height: Int, enableAccessibility: Bool
    ) -> Data {
        let object: [String: Any] = [
            "displayRotation": displayRotation,
            "width": width,
            "height": height,
            "enableAccessibility": enableAccessibility
        ]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    /// 【v1.1】音频状态帧（P2C `0x00020310`）。
    /// 原厂载荷原文：`ismute:false,isLogin:false`。
    static func audioStatusJSON(isMute: Bool, isLogin: Bool) -> Data {
        let object: [String: Any] = ["ismute": isMute, "isLogin": isLogin]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    /// 【v1.1】队列控制帧（P2C `0x00020050`），原厂载荷 `e`，无 JSON 体。
    /// 这里只返回空体，调用方用 `pxcFrame(cmd:)` 直接组包。

    /// 【v1.1】判断仪表下发的 CLIENT_INFO 里声明的能力。
    /// 只读我方真正会用到的键；其余 40 个键照原样留在 dump 里备查。
    struct CarCapability {
        var huid: String = ""
        var huName: String = ""
        /// 原厂是**字符串** `"44001"`，不是整数。
        var channel: String = ""
        var flavor: Int = 0
        var sdkVersion: String = ""
        var pxcVersion: String = ""
        var productType: Int = 0
        /// 原厂 256。决定可用连接方式位图。
        var supportConnect: Int = 0
        var supportScreenMirroring: Bool = false
        var supportScreenTouch: Bool = false
        var mirrorMode: Int = 0
        /// 原厂 20（秒）。镜像/控制通道的读超时。
        var socketTimeoutPeriodWifi: Int = 20
        /// 原厂 23821，仪表当前运行毫秒数。
        var currentHUTime: Int = 0
    }

    /// 解析仪表下发的 `0x00010010` 载荷。
    /// 与 v1.0 的 `parseCarClientInfo` 的区别：**HUID 非必需**——
    /// 原厂日志里 `HUName` 是空串、HUID 一定有；但我方只需要能力位，
    /// 缺 HUID 也要能把 channel/flavor 读出来，别整帧丢掉。
    static func parseCarCapability(_ payload: Data) -> CarCapability? {
        guard let object = (try? JSONSerialization.jsonObject(with: payload, options: [])) as? [String: Any] else {
            return nil
        }
        var cap = CarCapability()
        cap.huid = (object["HUID"] as? String) ?? ""
        cap.huName = (object["HUName"] as? String) ?? ""
        // channel 原厂是字符串；老固件可能给数字，两种都收。
        if let text = object["channel"] as? String {
            cap.channel = text
        } else if let number = object["channel"] as? NSNumber {
            cap.channel = number.stringValue
        }
        cap.flavor = (object["flavor"] as? NSNumber)?.intValue ?? 0
        cap.sdkVersion = (object["sdkVersion"] as? String) ?? ""
        cap.pxcVersion = (object["pxcVersion"] as? String) ?? ""
        cap.productType = (object["productType"] as? NSNumber)?.intValue ?? 0
        cap.supportConnect = (object["supportConnect"] as? NSNumber)?.intValue ?? 0
        cap.supportScreenMirroring = (object["supportScreenMirroring"] as? NSNumber)?.boolValue ?? false
        cap.supportScreenTouch = (object["supportScreenTouch"] as? NSNumber)?.boolValue ?? false
        cap.mirrorMode = (object["mirrorMode"] as? NSNumber)?.intValue ?? 0
        cap.socketTimeoutPeriodWifi = (object["socketTimeoutPeriodWifi"] as? NSNumber)?.intValue ?? 20
        cap.currentHUTime = (object["currentHUTime"] as? NSNumber)?.intValue ?? 0
        // 至少要能判断出「这是能力通告」：channel 或 flavor 有一个非零。
        guard !cap.channel.isEmpty || cap.flavor != 0 else { return nil }
        return cap
    }
    // MARK: - 拆包（接收）

    func consume(_ data: Data) -> [Event] {
        buffer.append(data)
        switch framing {
        case .pxc: return consumePXC()
        case .mirror: return consumeMirror()
        }
    }

    private func consumePXC() -> [Event] {
        var events: [Event] = []
        while buffer.count >= Self.pxcHeaderSize {
            let cmd = buffer.le32(at: 0)
            let total = buffer.le32(at: 4)
            let checksum = buffer.le32(at: 8)
            let version = buffer.le32(at: 12)
            // 帧头自校验：cmd ^ total 必须等于校验字；total 至少等于头长。
            if total < UInt32(Self.pxcHeaderSize) || total > 0x40000 || (cmd ^ total) != checksum {
                let raw = buffer.prefix(Self.pxcHeaderSize)
                events.append(.unknown(code: cmd, payload: Data(raw), framing: .pxc))
                buffer.removeFirst(Self.pxcHeaderSize)
                continue
            }
            guard buffer.count >= Int(total) else { break }
            let payload = buffer.subdata(in: Self.pxcHeaderSize ..< Int(total))
            buffer.removeFirst(Int(total))
            events.append(contentsOf: Self.classify(low16: UInt16(cmd & 0xFFFF), fullCode: cmd, payload: payload, framing: .pxc, version: version))
        }
        return events
    }

    private func consumeMirror() -> [Event] {
        var events: [Event] = []
        while buffer.count >= Self.mirrorHeaderSize {
            let code = buffer.le16(at: 0)
            let length = Int(buffer.le16(at: 2))
            guard length <= Self.maxPayload else {
                let raw = buffer.prefix(Self.mirrorHeaderSize)
                events.append(.unknown(code: UInt32(code), payload: Data(raw), framing: .mirror))
                buffer.removeFirst(Self.mirrorHeaderSize)
                continue
            }
            guard buffer.count >= Self.mirrorHeaderSize + length else { break }
            let payload = buffer.subdata(in: Self.mirrorHeaderSize ..< Self.mirrorHeaderSize + length)
            buffer.removeFirst(Self.mirrorHeaderSize + length)
            events.append(contentsOf: Self.classify(low16: code, fullCode: UInt32(code), payload: payload, framing: .mirror, version: 0))
        }
        return events
    }

    /// 低 16 位操作码 → 事件。
    ///
    /// 【v1.1 关键】`low16 == 0x0010` 必须按 `fullCode` 区分两个完全不同的东西：
    ///   · `0x00010010`：**PXC 控制通道**上仪表下发的 CLIENT_INFO（JSON）→ .carClientInfo
    ///   · `0x00000010`：**镜像通道**的 start（protobuf MirrorConfig）→ .start
    /// v1.0 把两者混在同一个 case 里，导致控制通道的 CLIENT_INFO 被当镜像启动帧解析。
    private static func classify(low16: UInt16, fullCode: UInt32, payload: Data, framing: Framing, version: UInt32) -> [Event] {
        switch low16 {
        case 0x0010:
            if framing == .pxc, fullCode == PXC.carClientInfo {
                // 仪表下发的能力通告：永远是 JSON，绝不能喂 protobuf 解码器。
                return [.carClientInfo(payload)]
            }
            if framing == .mirror {
                let cfg = decodeMirrorConfig(payload)
                if let cfg { return [.start(cfg)] }
                return [.start(nil)]
            }
            // 控制通道上其它 0x0010 变体：交给上层看原始字节。
            return [.unknown(code: fullCode, payload: payload, framing: framing)]
        case 0x0011:
            // 0x00010011 = handleClientInfo 成功应答；
            // 0x70000011 = 仪表对未识别命令的通用 NAK（{"status":false}）。
            return [.unknown(code: fullCode, payload: payload, framing: framing)]
        case MirrorCode.ready.rawValue:
            return [.ready]
        case MirrorCode.frameRequest.rawValue:
            return [.frameRequest]
        case MirrorCode.heartbeat.rawValue:
            return [.heartbeat(code: fullCode, framing: framing)]
        default:
            return [.unknown(code: fullCode, payload: payload, framing: framing)]
        }
    }

    // MARK: - MirrorConfig（protobuf 线格式）

    /// 字段号来自车机端 dex 常量 `ECTinyPlus$MirrorConfig`：
    /// 1 宽 2 高 3 WANTFPS 4 编码器 5 画质 6 码率 7 物理宽 8 物理高 9 DPI。
    static func decodeMirrorConfig(_ data: Data) -> CaptureConfig? {
        var cfg = CaptureConfig()
        var hit = false
        var index = 0
        let bytes = [UInt8](data)
        while index < bytes.count {
            guard let (key, next) = readVarint(bytes, index) else { break }
            index = next
            let field = Int(key >> 3)
            let wireType = Int(key & 0x7)
            if wireType != 0 {
                guard let skipped = skipField(bytes, index, wireType: wireType) else { break }
                index = skipped
                continue
            }
            guard let (value, after) = readVarint(bytes, index) else { break }
            index = after
            switch field {
            case 1: cfg.width = Int(value); hit = true
            case 2: cfg.height = Int(value); hit = true
            case 3: cfg.wantFps = Int(value); hit = true
            case 4: cfg.encoder = Int(value); hit = true
            case 5: cfg.quality = Int(value)
            case 6: cfg.bitRate = Int(value); hit = true
            case 7: cfg.physicalWidth = Int(value)
            case 8: cfg.physicalHeight = Int(value)
            case 9: cfg.dpi = Int(value)
            default: break
            }
        }
        return hit ? cfg : nil
    }

    /// 请求开始镜像时上报我方期望的采集参数（protobuf，字段号同上）。
    static func encodeMirrorConfig(_ cfg: CaptureConfig) -> Data {
        var out = Data()
        appendField(1, UInt64(max(1, cfg.width)), to: &out)
        appendField(2, UInt64(max(1, cfg.height)), to: &out)
        appendField(3, UInt64(cfg.wantFps), to: &out)
        appendField(4, UInt64(cfg.encoder), to: &out)
        appendField(5, UInt64(cfg.quality), to: &out)
        appendField(6, UInt64(cfg.bitRate), to: &out)
        if cfg.physicalWidth > 0 { appendField(7, UInt64(cfg.physicalWidth), to: &out) }
        if cfg.physicalHeight > 0 { appendField(8, UInt64(cfg.physicalHeight), to: &out) }
        if cfg.dpi > 0 { appendField(9, UInt64(cfg.dpi), to: &out) }
        return out
    }

    private static func appendVarint(_ value: UInt64, to data: inout Data) {
        var v = value
        repeat {
            var byte = UInt8(v & 0x7F)
            v >>= 7
            if v != 0 { byte |= 0x80 }
            data.append(byte)
        } while v != 0
    }

    private static func appendField(_ number: Int, _ value: UInt64, to data: inout Data) {
        appendVarint(UInt64(number) << 3, to: &data)   // wire type 0
        appendVarint(value, to: &data)
    }

    private static func readVarint(_ bytes: [UInt8], _ start: Int) -> (UInt64, Int)? {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var index = start
        while index < bytes.count, shift < 64 {
            let byte = bytes[index]
            result |= UInt64(byte & 0x7F) << shift
            index += 1
            if byte & 0x80 == 0 { return (result, index) }
            shift += 7
        }
        return nil
    }

    private static func skipField(_ bytes: [UInt8], _ start: Int, wireType: Int) -> Int? {
        switch wireType {
        case 1: return start + 8 <= bytes.count ? start + 8 : nil
        case 2:
            guard let (length, after) = readVarint(bytes, start) else { return nil }
            let end = after + Int(length)
            return end <= bytes.count ? end : nil
        case 5: return start + 4 <= bytes.count ? start + 4 : nil
        default: return nil
        }
    }

    // MARK: - mDNS TXT

    /// 解析 `_EasyConn._tcp` 的 TXT 记录。实测键：huid / port / flavor / packagename / channel。
    static func parseTXT(_ records: [String: String]) -> (huid: String, port: UInt16, flavor: Int, channel: Int) {
        let huid = records["huid"] ?? ""
        let port = UInt16(records["port"] ?? "") ?? 0
        let flavor = Int(records["flavor"] ?? "") ?? 0
        let channel = Int(records["channel"] ?? "") ?? 0
        return (huid, port, flavor, channel)
    }

    /// 把 mDNS 的 12 位十六进制 huid 还原成 MAC 形式，便于人工比对。
    static func formatHUID(_ huid: String) -> String {
        guard huid.count == 12 else { return huid }
        var parts: [String] = []
        var index = huid.startIndex
        for _ in 0 ..< 6 {
            let end = huid.index(index, offsetBy: 2)
            parts.append(String(huid[index ..< end]).uppercased())
            index = end
        }
        return parts.joined(separator: ":")
    }
}

// MARK: - Data 小工具

extension Data {
    mutating func appendLE16(_ value: UInt16) {
        append(contentsOf: [UInt8(value & 0xFF), UInt8(value >> 8 & 0xFF)])
    }

    mutating func appendLE32(_ value: UInt32) {
        append(contentsOf: [UInt8(value & 0xFF), UInt8(value >> 8 & 0xFF),
                            UInt8(value >> 16 & 0xFF), UInt8(value >> 24 & 0xFF)])
    }

    func le16(at offset: Int) -> UInt16 {
        guard offset + 1 < count else { return 0 }
        let bytes = [UInt8](self[offset ... offset + 1])
        return UInt16(bytes[0]) | (UInt16(bytes[1]) << 8)
    }

    func le32(at offset: Int) -> UInt32 {
        guard offset + 3 < count else { return 0 }
        let bytes = [UInt8](self[offset ... offset + 3])
        return UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) | (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)
    }

    /// 十六进制转储，用于记录线上原始字节。
    func hexDump(limit: Int = 512) -> String {
        let slice = prefix(limit)
        let hex = slice.map { String(format: "%02X", $0) }.joined(separator: " ")
        return count > limit ? hex + " …(\(count) 字节)" : hex
    }
}
