import Foundation
import CryptoKit
import CryptoSwift
import BigInt

struct ECPoint {
    var x: BigUInt?
    var y: BigUInt?
    static let infinity = ECPoint(x: nil, y: nil)
    var isInfinity: Bool { x == nil || y == nil }
}

enum TrackerCrypto {
    private static let p = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", radix: 16)!
    private static let a = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", radix: 16)!
    private static let b = BigUInt("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", radix: 16)!
    private static let n = BigUInt("0100000000000000000001F4C8F927AED3CA752257", radix: 16)!
    private static let g = ECPoint(
        x: BigUInt("4A96B5688EF573284664698968C38BB913CBFC82", radix: 16)!,
        y: BigUInt("23A628553168947D59DCC912042351377AC5FB32", radix: 16)!
    )

    static func decryptLocations(deviceUpdate: Data, ownerKey: Data) throws -> [TrackerLocation] {
        let update = try ProtoReader.read(deviceUpdate)
        let metadata = update.first(3)?.message ?? []
        let information = metadata.first(4)?.message ?? []
        let registration = information.first(1)?.message ?? []
        let secrets = registration.first(19)?.message ?? []
        guard let encryptedIdentityKey = secrets.first(1)?.bytes else { throw FindHubError.protobuf("Encrypted identity key missing") }
        let modelID = registration.first(21)?.string ?? ""
        let identityKey = try decryptIdentityKey(encryptedIdentityKey, ownerKey: ownerKey)

        let reportsWrapper = information.first(2)?.message.first(3)?.message.first(4)?.message ?? []
        var pairs: [(ProtoField, ProtoField)] = []
        if let recent = reportsWrapper.first(1), let time = reportsWrapper.first(2) { pairs.append((recent, time)) }
        let network = reportsWrapper.all(5), times = reportsWrapper.all(6)
        for i in 0..<min(network.count, times.count) { pairs.append((network[i], times[i])) }

        var result: [TrackerLocation] = []
        for (reportField, timeField) in pairs {
            let report = reportField.message
            let statusRaw = Int(report.first(11)?.varint ?? 0)
            let time = Date(timeIntervalSince1970: TimeInterval(timeField.message.first(1)?.varint ?? 0))
            let source = TrackerLocation.Source(rawValue: statusRaw) ?? .lastKnown
            if statusRaw == 0 {
                let name = report.first(5)?.message.first(1)?.string ?? "Saved place"
                result.append(TrackerLocation(latitude: nil, longitude: nil, altitude: nil, accuracy: 0, timestamp: time, source: .semantic, isOwnReport: true, semanticName: name))
                continue
            }

            let geo = report.first(10)?.message ?? []
            let encryptedReport = geo.first(1)?.message ?? []
            guard let encrypted = encryptedReport.first(2)?.bytes else { continue }
            let publicRandom = encryptedReport.first(1)?.bytes ?? Data()
            let isOwn = encryptedReport.first(3)?.varint == 1
            let accuracyBits = geo.first(3)?.fixed32 ?? 0
            let accuracy = Double(Float(bitPattern: accuracyBits))

            let plain: Data
            if publicRandom.isEmpty {
                let hash = Data(SHA256.hash(data: identityKey))
                plain = try aesGCMDecrypt(encrypted, key: hash)
            } else {
                let offset = modelID == "003200" ? 0 : UInt32(truncatingIfNeeded: geo.first(2)?.varint ?? 0)
                plain = try decryptCrowdsourced(identityKey: identityKey, encryptedAndTag: encrypted, sxData: publicRandom, beaconCounter: offset)
            }

            let loc = try ProtoReader.read(plain)
            guard let latBits = loc.first(1)?.fixed32, let lonBits = loc.first(2)?.fixed32 else { continue }
            let lat = Double(Int32(bitPattern: latBits)) / 1e7
            let lon = Double(Int32(bitPattern: lonBits)) / 1e7
            let altitude = loc.first(3)?.varint.map { Double(Int32(truncatingIfNeeded: $0)) }
            result.append(TrackerLocation(latitude: lat, longitude: lon, altitude: altitude, accuracy: accuracy, timestamp: time, source: source, isOwnReport: isOwn, semanticName: nil))
        }

        return result.sorted { $0.timestamp > $1.timestamp }
    }

    static func aesGCMDecrypt(_ encrypted: Data, key: Data, ivLength: Int = 12) throws -> Data {
        guard encrypted.count > ivLength + 16 else { throw FindHubError.crypto("AES-GCM payload too short") }
        let nonceData = encrypted.prefix(ivLength)
        let body = encrypted.dropFirst(ivLength)
        let ciphertext = body.dropLast(16), tag = body.suffix(16)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: SymmetricKey(data: key))
    }

    private static func decryptIdentityKey(_ encrypted: Data, ownerKey: Data) throws -> Data {
        switch encrypted.count {
        case 48:
            let iv = [UInt8](encrypted.prefix(16)), body = [UInt8](encrypted.dropFirst(16))
            let aes = try CryptoSwift.AES(key: [UInt8](ownerKey), blockMode: CBC(iv: iv), padding: .noPadding)
            return Data(try aes.decrypt(body))
        case 60:
            return try aesGCMDecrypt(encrypted, key: ownerKey)
        default:
            throw FindHubError.crypto("Unsupported encrypted identity key length \(encrypted.count)")
        }
    }

    private static func decryptCrowdsourced(identityKey: Data, encryptedAndTag: Data, sxData: Data, beaconCounter: UInt32) throws -> Data {
        guard identityKey.count == 32, sxData.count == 20, encryptedAndTag.count >= 16 else { throw FindHubError.crypto("Invalid crowdsourced report") }
        let r = try calculateR(identityKey: identityKey, timestamp: beaconCounter)
        let rPoint = multiply(r, g)
        guard let rx = rPoint.x else { throw FindHubError.crypto("Invalid ephemeral point") }

        let sx = BigUInt(sxData)
        let sy = try evenY(forX: sx)
        let sPoint = ECPoint(x: sx, y: sy)
        let shared = multiply(r, sPoint)
        guard let sharedX = shared.x else { throw FindHubError.crypto("ECDH failed") }

        let sharedBytes = fixed(sharedX, length: 20)
        let key = hkdf(input: sharedBytes, count: 32)
        var nonce = Data(fixed(rx, length: 20).suffix(8))
        nonce.append(fixed(sx, length: 20).suffix(8))
        return try eaxDecrypt(ciphertextAndTag: encryptedAndTag, key: key, nonce: nonce)
    }

    private static func calculateR(identityKey: Data, timestamp: UInt32) throws -> BigUInt {
        let masked = timestamp & ~UInt32((1 << 10) - 1)
        let ts = [UInt8((masked >> 24) & 0xff), UInt8((masked >> 16) & 0xff), UInt8((masked >> 8) & 0xff), UInt8(masked & 0xff)]
        var block = [UInt8](repeating: 0, count: 32)
        for i in 0..<11 { block[i] = 0xff }
        block[11] = 10
        for i in 0..<4 { block[12 + i] = ts[i] }
        block[27] = 10
        for i in 0..<4 { block[28 + i] = ts[i] }

        let aes = try CryptoSwift.AES(key: [UInt8](identityKey), blockMode: ECB(), padding: .noPadding)
        return BigUInt(Data(try aes.encrypt(block))) % n
    }

    private static func eaxDecrypt(ciphertextAndTag: Data, key: Data, nonce: Data) throws -> Data {
        let ciphertext = Data(ciphertextAndTag.dropLast(16)), suppliedTag = Data(ciphertextAndTag.suffix(16))
        let nonceTag = try cmac(domain: 0, message: nonce, key: key)
        let headerTag = try cmac(domain: 1, message: Data(), key: key)
        let cipherTag = try cmac(domain: 2, message: ciphertext, key: key)
        let expected = Data(zip(zip(nonceTag, headerTag), cipherTag).map { ($0.0.0 ^ $0.0.1) ^ $0.1 })
        guard expected == suppliedTag else { throw FindHubError.crypto("AES-EAX authentication failed") }

        let aes = try CryptoSwift.AES(key: [UInt8](key), blockMode: CTR(iv: [UInt8](nonceTag)), padding: .noPadding)
        return Data(try aes.decrypt([UInt8](ciphertext)))
    }

    private static func cmac(domain: UInt8, message: Data, key: Data) throws -> Data {
        let zero = [UInt8](repeating: 0, count: 16)
        let aes = try CryptoSwift.AES(key: [UInt8](key), blockMode: ECB(), padding: .noPadding)
        let l = try aes.encrypt(zero)
        let k1 = dbl(l), k2 = dbl(k1)
        var prefixed = Data([UInt8](repeating: 0, count: 15) + [domain])
        prefixed.append(message)
        let bytes = [UInt8](prefixed)
        let complete = !bytes.isEmpty && bytes.count % 16 == 0
        let blocks = max(1, (bytes.count + 15) / 16)
        var x = [UInt8](repeating: 0, count: 16)

        for idx in 0..<(blocks - 1) {
            let block = Array(bytes[(idx * 16)..<(idx * 16 + 16)])
            x = try aes.encrypt(xor(x, block))
        }

        var last: [UInt8]
        if complete {
            last = Array(bytes[((blocks - 1) * 16)..<(blocks * 16)])
            last = xor(last, k1)
        } else {
            let start = (blocks - 1) * 16
            var tail = start < bytes.count ? Array(bytes[start..<bytes.count]) : []
            tail.append(0x80)
            while tail.count < 16 { tail.append(0) }
            last = xor(tail, k2)
        }

        return Data(try aes.encrypt(xor(x, last)))
    }

    private static func dbl(_ input: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 16), carry: UInt8 = 0
        for i in stride(from: 15, through: 0, by: -1) {
            let nextCarry: UInt8 = (input[i] & 0x80) == 0 ? 0 : 1
            out[i] = (input[i] << 1) | carry
            carry = nextCarry
        }
        if carry != 0 { out[15] ^= 0x87 }
        return out
    }

    private static func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        zip(a, b).map { $0.0 ^ $0.1 }
    }

    private static func hkdf(input: Data, count: Int) -> Data {
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: input), salt: Data(), info: Data(), outputByteCount: count)
        return key.withUnsafeBytes { Data($0) }
    }

    private static func evenY(forX x: BigUInt) throws -> BigUInt {
        let rhs = (modPow(x, 3, p) + (a * x) + b) % p
        var y = modPow(rhs, (p + 1) / 4, p)
        guard (y * y) % p == rhs else { throw FindHubError.crypto("Invalid SECP160R1 point") }
        if (y & 1) == 1 { y = p - y }
        return y
    }

    private static func add(_ lhs: ECPoint, _ rhs: ECPoint) -> ECPoint {
        if lhs.isInfinity { return rhs }
        if rhs.isInfinity { return lhs }
        let x1 = lhs.x!, y1 = lhs.y!, x2 = rhs.x!, y2 = rhs.y!
        if x1 == x2 && (y1 != y2 || y1 == 0) { return .infinity }

        let lambda: BigUInt
        if x1 == x2 && y1 == y2 {
            let numerator = (3 * ((x1 * x1) % p) + a) % p
            lambda = (numerator * inverse((2 * y1) % p)) % p
        } else {
            lambda = (modSub(y2, y1, p) * inverse(modSub(x2, x1, p))) % p
        }

        let x3 = modSub(modSub((lambda * lambda) % p, x1, p), x2, p)
        let y3 = modSub((lambda * modSub(x1, x3, p)) % p, y1, p)
        return ECPoint(x: x3, y: y3)
    }

    private static func multiply(_ scalar: BigUInt, _ point: ECPoint) -> ECPoint {
        var k = scalar, result = ECPoint.infinity, addend = point
        while k > 0 {
            if (k & 1) == 1 { result = add(result, addend) }
            addend = add(addend, addend)
            k >>= 1
        }
        return result
    }

    private static func inverse(_ x: BigUInt) -> BigUInt {
        modPow(x, p - 2, p)
    }

    private static func modPow(_ base: BigUInt, _ exponent: BigUInt, _ modulus: BigUInt) -> BigUInt {
        var b = base % modulus, e = exponent, result = BigUInt(1)
        while e > 0 {
            if (e & 1) == 1 { result = (result * b) % modulus }
            e >>= 1
            b = (b * b) % modulus
        }
        return result
    }

    private static func modSub(_ x: BigUInt, _ y: BigUInt, _ m: BigUInt) -> BigUInt {
        x >= y ? (x - y) % m : (m - ((y - x) % m)) % m
    }

    private static func fixed(_ value: BigUInt, length: Int) -> Data {
        let raw = value.serialize()
        if raw.count >= length { return Data(raw.suffix(length)) }
        return Data(repeating: 0, count: length - raw.count) + raw
    }
}
