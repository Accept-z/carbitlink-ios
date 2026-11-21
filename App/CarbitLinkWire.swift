// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkWire.swift
// 亿连（CarbitLink）线上格式 —— 按 2026-11-21 真机实测重写。
//
// 【实测来源】小米 12S Pro / 亿连骑行 v5.1.1 / HyperOS 3.0.4.0 / Android 15，
// 仪表 IP 192.168.49.108，两次完整会话（17:39:24-17:40:38、17:41:04-17:42:05）。
// 证据链：手机端 logcat（亿连进程 pid 9586）+ 每 2 秒一次的 /proc/net/tcp 快照。
//
// 【已确认】
//   · 帧头固定 8 字节：偏移 0 = 指令码(uint16 LE)，偏移 2 = 载荷长度(uint16 LE)，
//     偏移 4-7 实测恒为 0（保留位）。单帧载荷上限 10240（0x2800）。
//     直接证据：日志原文 `rec First 0 [72,00,00,00,00,00,00,00]`。
//   · 端口：手机侧监听 10920(视频) / 10921(控制) / 10922(PXC)；仪表侧广播 10930。
//   · 采集参数由仪表下发（cmd 0x0010，204 字节），本车实测 1152x640 / 3Mbps / H.264 /
//     wantFps=0（拉模式）。
//   · 拉模式：仪表每帧发一次 0x0072（载荷长度 0），手机收到后推一帧。
//   · 握手明文字段：{"HUID":"<仪表 MAC 十六进制大写>","HUName":"<型号串>"}，
//     HUID 与 mDNS TXT 里的 huid 一致（例 5478C9665F12 = 54:78:C9:66:5F:12）。
//
// 【仍未确认 —— 因此标 TODO(probe)】
//   · 手机回帧的指令码与封装（响应 0x0072 时发什么）。本文件默认按 0x0071 + 8 字节头
//     + 裸 Annex-B 发送，并允许在 Probe 中枚举候选指令码。
//   · PXC 通道（10922）的帧格式：日志里是 32 位码（0x00010010），与镜像通道的
//     16 位码不同，故单独实现，标 TODO(probe)。
//   · 205 字节 MirrorStart 的各字段：protobuf 字段号已知（见 MirrorConfig），
//     但值为运行时内容，由 decodeMirrorConfig 按线格式解析，不硬编码偏移。

import Foundation

enum CarbitLinkWireError: Error, LocalizedError {
    case malformed(String)
    var errorDescription: String? {
        if case .malformed(let m) = self { return m }
        return nil
    }
}

final class CarbitLinkWire {

    // MARK: - 指令码（实测）

    enum Code: UInt16 {
        /// 仪表 → 手机：镜像启动，载荷 204 字节（含 MirrorConfig）
        case start        = 0x0010
        /// 仪表 → 手机：视频通道就绪（载荷长度 0）
        case ready        = 0x0070
        /// 仪表 → 手机：请求下一帧（拉模式，载荷长度 0）
        case frameRequest = 0x0072
        /// 双向：心跳
        case heartbeat    = 0x0040
        /// 手机 → 仪表：请求开始镜像（随后仪表连 10921 并发 start）
        case requestStart = 0x01C0   // 完整码 0x000201C0，PXC 空间低 16 位
        /// 手机 → 仪表：推帧。TODO(probe) 实测未捕获响应码，暂定为 0x0071。
        case videoFrame   = 0x0071
    }

    // MARK: - 采集参数（仪表下发）

    /// 本车实测值：1152x640 / 3145728 / H.264 / pull。
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
        case heartbeat
        case unknown(code: UInt16, payload: Data)
    }

    // MARK: - 常量

    /// 单帧载荷上限，来自 `MirrorService::onRecv` 反汇编（0x2800）。
    static let maxPayload = 10240
    static let headerSize = 8

    // MARK: - 状态

    private var buffer = Data()
    private(set) var config = CaptureConfig()

    // MARK: - 组包（发送）

    /// 8 字节头 + 载荷。长度超上限直接抛错，避免发出仪表无法解析的帧。
    func frame(code: Code, payload: Data = Data()) throws -> Data {
        guard payload.count <= Self.maxPayload else {
            throw CarbitLinkWireError.malformed("载荷 \(payload.count) 超过上限 \(Self.maxPayload)")
        }
        var out = Data(capacity: Self.headerSize + payload.count)
        out.appendLE16(code.rawValue)
        out.appendLE16(UInt16(payload.count))
        out.append(contentsOf: [0, 0, 0, 0])   // 偏移 4-7 实测恒 0
        out.append(payload)
        return out
    }

    /// 推一帧 H.264（Annex-B）。TODO(probe) 响应码与是否需要时间戳前缀待实测。
    func videoFrame(annexB: Data) throws -> Data {
        try frame(code: .videoFrame, payload: annexB)
    }

    /// 握手 JSON（明文）。HUID 用仪表 MAC 的十六进制大写形式。
    static func handshakeJSON(huid: String, huName: String) -> Data {
        let object: [String: Any] = ["HUID": huid, "HUName": huName]
        return (try? JSONSerialization.data(withJSONObject: object, options: [])) ?? Data()
    }

    // MARK: - 拆包（接收）

    /// 把到达的字节流切成事件。按「8 字节头 + uint16 长度」定长解析，不做启发式猜测。
    func consume(_ data: Data) -> [Event] {
        buffer.append(data)
        var events: [Event] = []
        while buffer.count >= Self.headerSize {
            let code = buffer.le16(at: 0)
            let length = Int(buffer.le16(at: 2))
            guard length <= Self.maxPayload else {
                // 长度非法说明字节流已错位，或对端帧头布局与我方假设不同。
                // 早先这里直接丢弃、什么都不留，实车上表现为「连上了但毫无反应」。
                // 现在把 8 字节原始头部当未知指令抛出去，至少能在日志/dump 里看到。
                let raw = buffer.prefix(Self.headerSize)
                events.append(.unknown(code: code, payload: Data(raw)))
                buffer.removeFirst(Self.headerSize)
                continue
            }
            guard buffer.count >= Self.headerSize + length else { break }
            let payload = buffer.subdata(in: Self.headerSize ..< Self.headerSize + length)
            buffer.removeFirst(Self.headerSize + length)

            switch Code(rawValue: code) {
            case .start:
                let cfg = Self.decodeMirrorConfig(payload)
                if let cfg { config = cfg }
                events.append(.start(cfg))
            case .ready:
                events.append(.ready)
            case .frameRequest:
                events.append(.frameRequest)
            case .heartbeat:
                events.append(.heartbeat)
            case .videoFrame, .requestStart:
                // 这两个是「我方发出」的码，正常不会从对端收到；真收到就按未知处理并转储。
                events.append(.unknown(code: code, payload: payload))
            case nil:
                events.append(.unknown(code: code, payload: payload))
            }
        }
        return events
    }

    // MARK: - MirrorConfig（protobuf 线格式）

    /// 字段号来自车机端 dex 常量 `ECTinyPlus$MirrorConfig`：
    /// 1 宽 2 高 3 WANTFPS 4 编码器 5 画质 6 码率 7 物理宽 8 物理高 9 DPI。
    /// 按变长整数逐字段解析，不假设偏移，字段缺失保持默认值。
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
            if wireType != 0 {                 // 只关心 varint 字段，其余跳过
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
    struct ServiceInfo {
        var host: String
        var port: UInt16
        var huid: String
        var flavor: Int
        var channel: Int
    }

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

    func le16(at offset: Int) -> UInt16 {
        guard offset + 1 < count else { return 0 }
        let bytes = [UInt8](self[offset ... offset + 1])
        return UInt16(bytes[0]) | (UInt16(bytes[1]) << 8)
    }

    /// 十六进制转储，用于 probe 模式记录线上原始字节。
    func hexDump(limit: Int = 512) -> String {
        let slice = prefix(limit)
        let hex = slice.map { String(format: "%02X", $0) }.joined(separator: " ")
        return count > limit ? hex + " …(\(count) 字节)" : hex
    }
}
