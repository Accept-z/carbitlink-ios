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
        /// 控制通道（10930）：16 字节头。
        case pxc
        /// 镜像通道（10920/10921/10922）：8 字节头。
        case mirror
    }

    /// PXC 控制通道指令（32 位）。低 16 位是操作码，高 16 位是服务号。
    enum PXC {
        /// 【v1.0 核心修正】手机 → 车机：CLIENT_INFO。
        /// C2PMainService::handleCMD case 0x00010010 → PLT 0x3706e0
        /// → GOT 0x3b21b8 → C2PMainService::handleClientInfo。
        /// 前 9 版误用 0x000103F0（handleOpenPage），载荷从未被解析。
        static let clientInfo: UInt32 = 0x00010010

        /// 车机 → 手机：handleClientInfo 成功应答（请求码 +1，0x1beee4 构造）。
        static let clientInfoAck: UInt32 = 0x00010011
        /// 车机 → 手机：handleClientInfo 失败应答（JSON 格式错 /
        /// flavor|channel 缺失 / checkPermission 不过），0x1bef0c 构造 0x80000030。
        static let clientInfoNack: UInt32 = 0x80000030

        /// 兼容 v0.8 被动路径命名（车机下发 CLIENT_INFO 请求 / 手机应答）。
        static let carClientInfoRequest: UInt32 = 0x00010010
        static let carClientInfoReply: UInt32 = 0x00010011

        /// 校验回复码规律：请求 +1。
        static let checkCarUUID: UInt32 = 0x000103B0
        static let checkCarUUIDReply: UInt32 = 0x000103B1
        static let checkSN: UInt32 = 0x000103E0
        /// 【v1.0 留档】0x000103F0 = handleOpenPage，前 9 版误用它发身份包。
        static let openPage: UInt32 = 0x000103F0
        /// v1.0 修正后的 case 表常量（旧表把 0x10010 标成 nightMode 是错的）。
        static let nightMode: UInt32 = 0x00010200
        static let btnEvent: UInt32 = 0x00010350
        /// 手机 → 仪表：屏幕信息（P2C，P2CMainService::notifyAppStatusChanged）。
        static let screenInfo: UInt32 = 0x00020020
        static let requestStartMirror: UInt32 = 0x000201C0
        /// 仪表 → 手机：准入层 / 非法命令通用拒绝（实车 0x70000011，{"status":false}）。
        static let clientInfoReply: UInt32 = 0x70000011
    }

    /// 镜像通道指令（16 位）。
    enum MirrorCode: UInt16 {
        case start        = 0x0010
        case ready        = 0x0070
        case frameRequest = 0x0072
        case heartbeat    = 0x0040
        case videoFrame   = 0x0071   // TODO(probe)：手机推帧码，暂定
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

    /// 【v0.9】主动上报的「合并字段集」CLIENT_INFO。
    /// 身份字段全部照搬原厂 App（准入层校验 channel + phoneUUID），
    /// 同时覆盖三套静态证据，避免再靠猜：
    ///   A. native C2PMainService::handleClientInfo(@0x1bebec) 解析侧 18 字段
    ///   B. Java ECP_C2P_CLIENT_INFO.u0(Map) 发送侧字段（pxcVersion/pubkey/...）
    ///   C. 二维码解出的本车参数（modelid / sn / bm / action）
    /// token 是【整数 0】（u0() 里 JSONObject.put("token", 0)），不是空串。
    static func clientInfoJSON(
        identity: ClientIdentity, pubkey: String, encryptedHUID: String
    ) -> Data {
        let object: [String: Any] = [
            // A. native 解析侧（原厂身份，非 iOS 自称）
            "sdkVersion": identity.sdkVersion,
            "flavor": identity.flavor,
            "channel": identity.channel,
            "HUID": identity.huid,
            "HUName": identity.huName,
            "encryptedHUID": encryptedHUID,
            "token": 0,
            "supportFunction": identity.action,
            "productType": 0,
            "supportMic": false,
            "package_name": identity.packageName,
            "screenType": 1,
            "wakeupWord": "",
            "supportBackDesktop": false,
            "phoneOs": identity.phoneOs,
            "phoneOsVersion": identity.phoneOsVersion,
            "phoneModel": identity.phoneModel,
            "phoneBrand": identity.phoneBrand,
            // B. u0() 发送侧
            "pxcVersion": identity.pxcVersion,
            "phoneUUID": identity.phoneUUID,
            "package": identity.packageName,
            "versionCode": identity.versionCode,
            "pubkey": pubkey,
            "bluetoothName": "",
            "supportH264IFrame": true,
            "appVersionFingerPrint": "",
            "speechEngineType": identity.speechEngineType,
            // C. 二维码真实参数（本车：modelid=44001 sn=ehCs action=128）
            "modelid": identity.modelId,
            "sn": identity.sn,
            "bm": identity.wifiMac,
            "action": identity.action
        ]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    /// 【v1.0 保留的被动路径】本车实测车机不主动发 CLIENT_INFO，且 0x00010011
    /// 实为 handleClientInfo 的【车机→手机】成功应答，正常流程不会调用本函数
    /// （Output 里 didSendProactiveInfo 已守卫）。若换仪表会主动下发，
    /// 仍按 ECP_C2P_CLIENT_INFO.u0(Map) 构造。
    /// `carHUID` 必须用【车机下发的 HUID】——车机拿 pubkey 还原
    /// encryptedHUID 后要和这个自己发的值比对，填错必被拒。
    static func clientInfoReplyJSON(
        identity: ClientIdentity, carHUID: String,
        pubkey: String, encryptedHUID: String
    ) -> Data {
        let object: [String: Any] = [
            "pxcVersion": identity.pxcVersion,
            "phoneUUID": identity.phoneUUID,
            "phoneBrand": identity.phoneBrand,
            "phoneModel": identity.phoneModel,
            "phoneOsVersion": identity.phoneOsVersion,
            "phoneOs": identity.phoneOs,
            "package": identity.packageName,
            "versionCode": identity.versionCode,
            "token": 0,
            "pubkey": pubkey,
            "encryptedHUID": encryptedHUID,
            "bluetoothName": "",
            "supportH264IFrame": true,
            "supportFunction": identity.action,
            "appVersionFingerPrint": "",
            "speechEngineType": identity.speechEngineType,
            // 回显车机身份，供 native handleClientInfo 侧校验
            "HUID": carHUID,
            "sdkVersion": identity.sdkVersion,
            "flavor": identity.flavor,
            "channel": identity.channel
        ]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    /// 从车机下发的 CLIENT_INFO JSON 里抽 HUID / channel / flavor / sdkVersion。
    /// HUID 非空才认定是「车机能力通告」，避免把 {"status":false} 误当请求。
    static func parseCarClientInfo(_ payload: Data) -> (huid: String, channel: String, flavor: Int, sdkVersion: String)? {
        guard let object = (try? JSONSerialization.jsonObject(with: payload, options: [])) as? [String: Any] else {
            return nil
        }
        let huid = (object["HUID"] as? String) ?? (object["huid"] as? String) ?? ""
        guard !huid.isEmpty else { return nil }
        let channel: String
        if let text = object["channel"] as? String {
            channel = text
        } else if let number = object["channel"] as? NSNumber {
            channel = number.stringValue
        } else {
            channel = ""
        }
        let flavor = (object["flavor"] as? NSNumber)?.intValue ?? 0
        let sdkVersion = object["sdkVersion"] as? String ?? ""
        return (huid, channel, flavor, sdkVersion)
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
    /// 【v1.0】low16=0x0011 有两种：0x00010011 是 handleClientInfo 成功应答，
    /// 0x70000011 是仪表固件的通用拒绝帧；都归入 unknown 让上层按 fullCode 判定。
    private static func classify(low16: UInt16, fullCode: UInt32, payload: Data, framing: Framing, version: UInt32) -> [Event] {
        switch low16 {
        case 0x0010:
            // 0x00010010 = handleClientInfo（手机上报 CLIENT_INFO），载荷是 JSON，
            // 绝不能先喂给 protobuf 解码器。
            if payload.first == UInt8(ascii: "{") {
                return [.unknown(code: fullCode, payload: payload, framing: framing)]
            }
            let cfg = decodeMirrorConfig(payload)
            if let cfg { return [.start(cfg)] }
            return [.start(nil)]
        case 0x0011:
            // 0x00010011 = handleClientInfo 成功应答；
            // 0x70000011 = 仪表固件通用拒绝（{"status":false}）。
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
