// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkWire.swift
// 亿连（CarbitLink）线上格式 —— v0.4，按 libEPSDK.so 反汇编重写。
//
// 【证据链（2026-11-21，easyride APK 内 libEPSDK.so，与车机端同一二进制）】
//   · PXCService::sendCMD / recvCMD / checkCMD（@0x1bdcd0 / 0x1be044 / 0x1bdc84）：
//     控制通道（10930）的帧头固定 16 字节 ——
//       [0..3]  cmd   u32 LE   指令码（高 16 位服务号，低 16 位操作码）
//       [4..7]  total u32 LE   = 16 + 载荷长度
//       [8..11] cmd ^ total    校验字
//       [12..15] version u32   版本（回复时原样带回）
//     实车验证：仪表回复 `11 00 00 70 | 24 00 00 00 | 35 00 00 70 | 00 00 00 00`
//     = cmd 0x70000011 / total 36 / 校验 0x70000035，且 0x70000011^0x24=0x70000035 ✓
//   · MirrorService::sendCMD（@0x1d5a38）：镜像通道帧头 8 字节 ——
//       [0..1] code u16 LE   [2..3] len u16 LE   [4..7] param u32 LE
//     与 Android logcat `rec First 0 [72,00,00,00,00,00,00,00]` 完全吻合。
//   · C2PMainService::handleCMD（@0x1be944）的 switch：仪表接受 19 个 0x0001xxxx 指令，
//     其中 0x00010010（开始镜像）、0x000103B0（CheckCarUUID，回 0x000103B1）、
//     0x000103E0（CheckSN）。PXCService::getCheckUUIDCmd=0x000103B0 交叉验证一致。
//   · 仪表→手机的推送走 0x7000xxxx 服务号（实车收到过 0x70000011）。
//
// 【仍未确认 —— dump 里会直接看到】
//   · 手机推帧的镜像码：暂定 0x0071（TODO probe）。
//   · 心跳应答码：先原样回显。
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
        /// 手机 → 仪表：请求开始镜像。
        static let startMirror: UInt32 = 0x00010010
        /// 手机 → 仪表：身份校验，负载为 JSON {"HUID":…,"HUName":…}。
        static let checkCarUUID: UInt32 = 0x000103B0
        /// 仪表 → 手机：身份校验回复。
        static let checkCarUUIDReply: UInt32 = 0x000103B1
        /// 手机 → 仪表：序列号校验。
        static let checkSN: UInt32 = 0x000103E0
        /// 屏幕触摸。
        static let screenTouch: UInt32 = 0x00010020
    }

    /// 镜像通道指令（16 位）。
    enum MirrorCode: UInt16 {
        case start        = 0x0010   // 启动/采集参数（低 16 位，PXC 里 0x11 也是它的回复形态）
        case ready        = 0x0070
        case frameRequest = 0x0072
        case heartbeat    = 0x0040
        case videoFrame   = 0x0071   // TODO(probe)：手机推帧码，暂定
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

    /// 握手 JSON（CheckCarUUID 的负载）。HUID 用仪表 MAC 的十六进制大写形式。
    static func handshakeJSON(huid: String, huName: String) -> Data {
        let object: [String: Any] = ["HUID": huid, "HUName": huName]
        return (try? JSONSerialization.data(withJSONObject: object, options: [])) ?? Data()
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
    /// 注意 0x0011 不是采集参数：实车验证它是 0x10 的「状态回复」形态，
    /// 载荷是 JSON（v0.5 实测收到 {"status": false}），归入 unknown 让上层打文本。
    private static func classify(low16: UInt16, fullCode: UInt32, payload: Data, framing: Framing, version: UInt32) -> [Event] {
        switch low16 {
        case 0x0010:
            // CLIENT_INFO（仪表能力上报）是 JSON；只有真解析出 protobuf 采集参数才算 start。
            let cfg = decodeMirrorConfig(payload)
            if let cfg { return [.start(cfg)] }
            if payload.first == UInt8(ascii: "{") {
                return [.unknown(code: fullCode, payload: payload, framing: framing)]
            }
            return [.start(nil)]
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

    /// 把 mDNS 的 huid（如 5478C9665F12）还原成 MAC 形式，便于人工比对。
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
