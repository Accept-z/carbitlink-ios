// SPDX-License-Identifier: GPL-3.0-or-later
//
// CarbitLinkIdentity.swift
// 亿连（CarbitLink）客户端 RSA 身份凭证 —— v0.8
//
// 【静态证据：easyride APK classes2.dex, Lnet/easyconn/carman/utils/RSAUtil;】
//   getPrivateKey(Context): KeyPairGenerator("RSA").initialize(1024)，
//     PrivateKey.getEncoded() / PublicKey.getEncoded() 各自
//     Base64.encodeToString(..., 2 = NO_WRAP) 存 SharedPreferences，长期复用。
//   encryptHUID(Context, String huid):
//     Cipher.getInstance("RSA/ECB/PKCS1Padding").init(ENCRYPT_MODE=1, privateKey)
//     doFinal(huid.getBytes(UTF_8)) → Base64.encodeToString(..., NO_WRAP)
//   decryptHuid(Context, String):
//     X509EncodedKeySpec 还原公钥 → Cipher.init(DECRYPT_MODE=2, publicKey)
//     → doFinal → 还原 HUID 明文（UTF-8）。
//   ECP_C2P_CLIENT_INFO.u0(Map) 把 pubkey + encryptedHUID 放进 CLIENT_INFO 应答；
//   车机用 pubkey "解密"后与自己的 HUID 比对，用来验证手机确实持有私钥。
//   明文 = 车机下发的 HUID（g() 里 optString("HUID") → 字段 r → encryptHUID 入参）。
//
// 【iOS 等价实现】
//   · SecKeyCreateRandomKey(RSA 1024)，密钥长期复用（对齐 Android SharedPreferences）。
//   · 公钥：SecKeyCopyExternalRepresentation 通常返回 PKCS#1 RSAPublicKey DER，
//     需包成 X.509 SubjectPublicKeyInfo（rsaEncryption OID）才是 Android
//     PublicKey.getEncoded() 的格式；此处自适应判断，已是 X.509 则原样使用。
//   · 私钥加密：SecKeyAlgorithm.rsaSignatureRaw = 「PKCS#1 v1.5 type-1 填充 +
//     私钥幂运算、不附加 DigestInfo」，与 Android
//     Cipher(ENCRYPT_MODE, privateKey, "RSA/ECB/PKCS1Padding") 逐字节等价。
//   · Data.base64EncodedString() 无换行 == Android Base64.NO_WRAP。
//

import Foundation
import Security

enum CarbitLinkIdentityError: Error, LocalizedError {
    case keyGeneration(String)
    case publicKeyExport
    case encryption(String)

    var errorDescription: String? {
        switch self {
        case .keyGeneration(let m): return "RSA 密钥生成失败：\(m)"
        case .publicKeyExport: return "RSA 公钥导出失败"
        case .encryption(let m): return "HUID 加密失败：\(m)"
        }
    }
}

/// 一台设备一份、跨会话复用的 RSA-1024 身份。
final class CarbitLinkIdentity {

    /// Android `PublicKey.getEncoded()` 的 Base64（X.509 SubjectPublicKeyInfo DER）。
    let publicKeyBase64: String

    private let privateKey: SecKey

    private static let defaultsPrivateKey = "carbitlink.rsa.private.b64"
    private static let defaultsPublicKey = "carbitlink.rsa.public.b64"

    init() throws {
        let defaults = UserDefaults.standard

        // 1) 复用上次生成的密钥对（与 Android SharedPreferences 行为一致，
        //    避免每次重连换密钥导致车机侧缓存的授权信息失配）。
        if let saved = defaults.string(forKey: Self.defaultsPrivateKey),
           let der = Data(base64Encoded: saved),
           let restored = Self.makePrivateKey(from: der) {
            privateKey = restored
            if let cached = defaults.string(forKey: Self.defaultsPublicKey), !cached.isEmpty {
                publicKeyBase64 = cached
            } else if let pub = SecKeyCopyPublicKey(restored),
                      let spki = Self.x509PublicKeyDER(pub) {
                publicKeyBase64 = spki.base64EncodedString()
                defaults.set(publicKeyBase64, forKey: Self.defaultsPublicKey)
            } else {
                throw CarbitLinkIdentityError.publicKeyExport
            }
            return
        }

        // 2) 首次生成。
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 1024
        ]
        var error: Unmanaged<CFError>?
        guard let generated = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw CarbitLinkIdentityError.keyGeneration(Self.errorText(error))
        }
        guard let pub = SecKeyCopyPublicKey(generated),
              let spki = Self.x509PublicKeyDER(pub) else {
            throw CarbitLinkIdentityError.publicKeyExport
        }
        privateKey = generated
        publicKeyBase64 = spki.base64EncodedString()

        if let privateDER = SecKeyCopyExternalRepresentation(generated, &error) as Data? {
            defaults.set(privateDER.base64EncodedString(), forKey: Self.defaultsPrivateKey)
        }
        defaults.set(publicKeyBase64, forKey: Self.defaultsPublicKey)
    }

    /// `RSAUtil.encryptHUID(Context, huid)` 的 iOS 等价实现。
    /// - Parameter huid: 车机 HUID 明文（UTF-8）。
    /// - Returns: Base64（NO_WRAP）的 PKCS#1 v1.5 私钥运算结果。
    func encryptedHUID(_ huid: String) throws -> String {
        guard let plain = huid.data(using: .utf8), !plain.isEmpty else {
            throw CarbitLinkIdentityError.encryption("HUID 为空")
        }
        var error: Unmanaged<CFError>?
        // rsaSignatureRaw == Android Cipher(ENCRYPT_MODE, privateKey, RSA/ECB/PKCS1Padding)
        guard let result = SecKeyCreateSignature(privateKey, .rsaSignatureRaw,
                                                 plain as CFData, &error) as Data? else {
            throw CarbitLinkIdentityError.encryption(Self.errorText(error))
        }
        return result.base64EncodedString()
    }

    // MARK: - DER / ASN.1 处理

    /// 从 PKCS#1 RSAPrivateKey DER 恢复 SecKey。
    private static func makePrivateKey(from der: Data) -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 1024
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error)
    }

    /// 返回 Android `PublicKey.getEncoded()` 同格式的 X.509 SubjectPublicKeyInfo DER。
    private static func x509PublicKeyDER(_ publicKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return nil
        }
        if isX509SubjectPublicKeyInfo(external) { return external }
        return wrapPKCS1IntoX509(external)
    }

    /// 外层 SEQUENCE 的第一个子元素：
    ///   0x30 (SEQUENCE = AlgorithmIdentifier) → 已是 X.509 SPKI
    ///   0x02 (INTEGER = modulus)              → 是 PKCS#1 RSAPublicKey
    private static func isX509SubjectPublicKeyInfo(_ der: Data) -> Bool {
        let bytes = [UInt8](der)
        guard bytes.count > 6, bytes[0] == 0x30 else { return false }
        var index = 1
        if bytes[index] & 0x80 != 0 {
            let lengthBytes = Int(bytes[index] & 0x7F)
            index += 1 + lengthBytes
        } else {
            index += 1
        }
        guard index < bytes.count else { return false }
        return bytes[index] == 0x30
    }

    /// SEQUENCE {
    ///   SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL },
    ///   BIT STRING { 0x00, <PKCS#1 RSAPublicKey DER> }
    /// }
    private static func wrapPKCS1IntoX509(_ pkcs1: Data) -> Data {
        let algorithmIdentifier: [UInt8] = [
            0x30, 0x0D,
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00
        ]
        var bitString = Data([0x03])
        bitString.append(contentsOf: derLength(pkcs1.count + 1))
        bitString.append(contentsOf: [UInt8(0x00)])   // unused bits
        bitString.append(pkcs1)

        var body = Data(algorithmIdentifier)
        body.append(bitString)

        var out = Data([0x30])
        out.append(contentsOf: derLength(body.count))
        out.append(body)
        return out
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 0x80 { return [UInt8(length)] }
        if length < 0x100 { return [0x81, UInt8(length)] }
        return [0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
    }

    private static func errorText(_ error: Unmanaged<CFError>?) -> String {
        guard let value = error?.takeRetainedValue() else { return "未知错误" }
        return String(describing: value)
    }
}
