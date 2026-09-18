import Foundation
import Network
import CryptoKit

final class MCSClient: @unchecked Sendable {
    private let credentials: PushCredentials
    private let queue = DispatchQueue(label: "FindHub.MCS")
    private var connection: NWConnection?
    private var buffer = Data()
    private var firstIncoming = true
    private var firstOutgoing = true
    private var connectContinuation: CheckedContinuation<Void, Error>?
    private var payloadContinuation: CheckedContinuation<Data, Error>?
    private var desiredRequestUUID: String?
    private var completedPayload = false

    init(credentials: PushCredentials) {
        self.credentials = credentials
    }

    func connect() async throws {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.connectContinuation = continuation
                let conn = NWConnection(host: "mtalk.google.com", port: 5228, using: .tls)
                self.connection = conn
                conn.stateUpdateHandler = { [weak self] state in self?.handle(state: state) }
                conn.start(queue: self.queue)
            }
        }
    }

    func waitForFindHubPayload(requestUUID: String, timeout: TimeInterval = 30) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.desiredRequestUUID = requestUUID
                self.payloadContinuation = continuation
                self.completedPayload = false
                self.queue.asyncAfter(deadline: .now() + timeout) {
                    guard !self.completedPayload else { return }
                    self.completedPayload = true
                    self.payloadContinuation?.resume(throwing: FindHubError.timeout)
                    self.payloadContinuation = nil
                }
            }
        }
    }

    func close() {
        queue.async {
            self.connection?.cancel()
            self.connection = nil
        }
    }

    private func handle(state: NWConnection.State) {
        switch state {
        case .ready:
            do {
                try sendLogin()
                receive()
            } catch {
                connectContinuation?.resume(throwing: error)
                connectContinuation = nil
            }
        case .failed(let error):
            if let c = connectContinuation { c.resume(throwing: error); connectContinuation = nil }
            if !completedPayload, let c = payloadContinuation { completedPayload = true; c.resume(throwing: error); payloadContinuation = nil }
        case .cancelled:
            if let c = connectContinuation { c.resume(throwing: FindHubError.network("MCS connection cancelled")); connectContinuation = nil }
        default:
            break
        }
    }

    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] content, _, complete, error in
            guard let self else { return }
            if let content {
                self.buffer.append(content)
                self.consumeFrames()
            }
            if let error {
                if !self.completedPayload, let c = self.payloadContinuation {
                    self.completedPayload = true
                    c.resume(throwing: error)
                    self.payloadContinuation = nil
                }
                return
            }
            if !complete { self.receive() }
        }
    }

    private func consumeFrames() {
        while true {
            let prefix = firstIncoming ? 2 : 1
            guard buffer.count >= prefix else { return }
            let bytes = [UInt8](buffer)
            var index = 0
            let tag: UInt8

            if firstIncoming {
                let version = bytes[0]
                guard version == 41 || version == 38 else {
                    failPayload(FindHubError.protobuf("Unsupported MCS version \(version)"))
                    return
                }
                tag = bytes[1]
                index = 2
            } else {
                tag = bytes[0]
                index = 1
            }

            guard let (length, varintBytes) = decodeVarint(bytes, start: index) else { return }
            index += varintBytes
            guard buffer.count >= index + length else { return }
            let payload = Data(buffer[index..<(index + length)])
            buffer.removeSubrange(..<(index + length))
            firstIncoming = false
            handle(tag: tag, payload: payload)
        }
    }

    private func handle(tag: UInt8, payload: Data) {
        do {
            switch tag {
            case 0:
                try sendFrame(tag: 1, payload: Data())
            case 3:
                let fields = try ProtoReader.read(payload)
                if fields.first(3) != nil {
                    throw FindHubError.auth("MCS login rejected")
                }
                if let c = connectContinuation {
                    c.resume()
                    connectContinuation = nil
                }
            case 8:
                try handleDataMessage(payload)
            default:
                break
            }
        } catch {
            if connectContinuation != nil {
                connectContinuation?.resume(throwing: error)
                connectContinuation = nil
            } else {
                failPayload(error)
            }
        }
    }

    private func handleDataMessage(_ payload: Data) throws {
        let fields = try ProtoReader.read(payload)
        var appData: [String: String] = [:]
        for app in fields.all(7) {
            let item = app.message
            if let key = item.first(1)?.string, let value = item.first(2)?.string {
                appData[key] = value
            }
        }

        guard let raw = fields.first(21)?.bytes,
              let cryptoHeader = appData["crypto-key"],
              let encryptionHeader = appData["encryption"] else { return }

        let decrypted = try LegacyWebPush.decrypt(
            rawData: raw,
            cryptoKeyHeader: cryptoHeader,
            encryptionHeader: encryptionHeader,
            credentials: credentials
        )

        guard let object = try JSONSerialization.jsonObject(with: decrypted) as? [String: Any],
              let dataObject = object["data"] as? [String: Any],
              let encoded = dataObject["com.google.android.apps.adm.FCM_PAYLOAD"] as? String,
              let findHub = Data(base64Encoded: encoded) else { return }

        let update = try ProtoReader.read(findHub)
        let requestUUID = update.first(1)?.message.first(2)?.string
        guard requestUUID == desiredRequestUUID else { return }
        guard !completedPayload, let c = payloadContinuation else { return }

        completedPayload = true
        payloadContinuation = nil
        c.resume(returning: findHub)
    }

    private func failPayload(_ error: Error) {
        guard !completedPayload, let c = payloadContinuation else { return }
        completedPayload = true
        payloadContinuation = nil
        c.resume(throwing: error)
    }

    private func sendLogin() throws {
        var w = ProtoWriter()
        w.string(1, "131.0.0.0")
        w.string(2, "mcs.android.com")
        w.string(3, credentials.androidID)
        w.string(4, credentials.androidID)
        w.string(5, credentials.securityToken)
        if let id = UInt64(credentials.androidID) {
            w.string(6, "android-" + String(id, radix: 16))
        }
        w.message(8) { setting in
            setting.string(1, "new_vc")
            setting.string(2, "1")
        }
        w.bool(12, false)
        w.bool(14, true)
        w.varint(16, 2)
        w.varint(17, 1)
        try sendFrame(tag: 2, payload: w.data)
    }

    private func sendFrame(tag: UInt8, payload: Data) throws {
        guard let connection else { throw FindHubError.network("MCS is not connected") }
        var packet = Data()
        if firstOutgoing {
            packet.append(41)
            firstOutgoing = false
        }
        packet.append(tag)
        packet.append(encodeVarint(payload.count))
        packet.append(payload)
        connection.send(content: packet, completion: .contentProcessed { _ in })
    }

    private func encodeVarint(_ value: Int) -> Data {
        var v = UInt64(value), out = Data()
        repeat {
            var b = UInt8(v & 0x7f)
            v >>= 7
            if v != 0 { b |= 0x80 }
            out.append(b)
        } while v != 0
        return out
    }

    private func decodeVarint(_ bytes: [UInt8], start: Int) -> (Int, Int)? {
        var result: UInt64 = 0, shift: UInt64 = 0, i = start
        while i < bytes.count && shift < 70 {
            let b = bytes[i]
            result |= UInt64(b & 0x7f) << shift
            i += 1
            if b & 0x80 == 0 { return (Int(result), i - start) }
            shift += 7
        }
        return nil
    }
}

enum LegacyWebPush {
    static func decrypt(
        rawData: Data,
        cryptoKeyHeader: String,
        encryptionHeader: String,
        credentials: PushCredentials
    ) throws -> Data {
        guard let dhString = parameter("dh", in: cryptoKeyHeader),
              let senderPublic = Data.fromBase64URL(dhString),
              let saltString = parameter("salt", in: encryptionHeader),
              let salt = Data.fromBase64URL(saltString),
              salt.count == 16 else {
            throw FindHubError.crypto("Invalid WebPush headers")
        }

        let rs = Int(parameter("rs", in: encryptionHeader) ?? "4096") ?? 4096
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: credentials.privateKeyRaw)
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: senderPublic)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peer)
        let sharedData = shared.withUnsafeBytes { Data($0) }

        var context = Data("P-256\0".utf8)
        context.append(be16(credentials.publicKeyX963.count))
        context.append(credentials.publicKeyX963)
        context.append(be16(senderPublic.count))
        context.append(senderPublic)

        let authInfo = Data("Content-Encoding: auth\0".utf8)
        let authKey = hkdf(input: sharedData, salt: credentials.authSecret, info: authInfo, count: 32)

        var keyInfo = Data("Content-Encoding: aesgcm\0".utf8)
        keyInfo.append(context)
        var nonceInfo = Data("Content-Encoding: nonce\0".utf8)
        nonceInfo.append(context)

        let key = hkdf(input: authKey, salt: salt, info: keyInfo, count: 16)
        let baseNonce = hkdf(input: authKey, salt: salt, info: nonceInfo, count: 12)

        let chunkSize = rs + 16
        var plaintext = Data()
        var offset = 0
        var counter: UInt64 = 0

        while offset < rawData.count {
            let end = min(rawData.count, offset + chunkSize)
            let chunk = Data(rawData[offset..<end])
            guard chunk.count > 16 else { throw FindHubError.crypto("Truncated WebPush record") }
            let ciphertext = chunk.dropLast(16)
            let tag = chunk.suffix(16)
            let nonce = try AES.GCM.Nonce(data: counterNonce(baseNonce, counter: counter))
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let record = try AES.GCM.open(box, using: SymmetricKey(data: key))
            guard record.count >= 2 else { throw FindHubError.crypto("Bad WebPush padding") }

            let bytes = [UInt8](record)
            let pad = Int(bytes[0]) << 8 | Int(bytes[1])
            guard 2 + pad <= record.count else { throw FindHubError.crypto("Bad WebPush pad length") }
            plaintext.append(record.dropFirst(2 + pad))
            offset = end
            counter += 1
        }

        return plaintext
    }

    private static func parameter(_ name: String, in header: String) -> String? {
        for part in header.split(separator: ";") {
            let pair = part.trimmingCharacters(in: .whitespaces)
                .split(separator: "=", maxSplits: 1)
                .map(String.init)
            if pair.count == 2, pair[0] == name { return pair[1] }
        }
        return nil
    }

    private static func hkdf(input: Data, salt: Data, info: Data, count: Int) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: input),
            salt: salt,
            info: info,
            outputByteCount: count
        )
        return key.withUnsafeBytes { Data($0) }
    }

    private static func counterNonce(_ base: Data, counter: UInt64) -> Data {
        var bytes = [UInt8](base)
        for i in 0..<8 {
            let shift = UInt64((7 - i) * 8)
            bytes[4 + i] ^= UInt8((counter >> shift) & 0xff)
        }
        return Data(bytes)
    }
}
