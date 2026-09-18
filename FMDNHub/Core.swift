import Foundation
import Security
import CoreLocation

// MARK: - Models

struct TrackerDevice: Identifiable, Hashable, Codable, Sendable {
    enum Kind: Int, Codable, Sendable, CaseIterable {
        case unknown = 0, beacon = 1, headphones = 2, keys = 3, watch = 4, wallet = 5
        case bag = 7, laptop = 8, car = 9, remoteControl = 10, badge = 11, bike = 12
        case camera = 13, cat = 14, charger = 15, clothing = 16, dog = 17, notebook = 18
        case passport = 19, phone = 20, speaker = 21, tablet = 22, toy = 23, umbrella = 24
        case stylus = 25, earbuds = 26

        var symbol: String {
            switch self {
            case .keys: return "key.fill"
            case .headphones, .earbuds: return "headphones"
            case .watch: return "watch.analog"
            case .wallet: return "wallet.bifold.fill"
            case .bag: return "backpack.fill"
            case .laptop: return "laptopcomputer"
            case .car: return "car.fill"
            case .bike: return "bicycle"
            case .camera: return "camera.fill"
            case .cat: return "cat.fill"
            case .dog: return "dog.fill"
            case .phone: return "iphone"
            case .speaker: return "hifispeaker.fill"
            case .tablet: return "ipad"
            case .umbrella: return "umbrella.fill"
            case .stylus: return "pencil.tip"
            default: return "location.fill"
            }
        }
    }

    let id: String
    var name: String
    var manufacturer: String
    var model: String
    var imageURL: URL?
    var kind: Kind
    var isOwner: Bool
    var lastLocation: TrackerLocation?
}

struct TrackerLocation: Hashable, Codable, Sendable {
    enum Source: Int, Codable, Sendable {
        case semantic = 0, lastKnown = 1, crowdsourced = 2, aggregated = 3
    }

    var latitude: Double?
    var longitude: Double?
    var altitude: Double?
    var accuracy: Double
    var timestamp: Date
    var source: Source
    var isOwnReport: Bool
    var semanticName: String?

    var coordinate: CLLocationCoordinate2D? {
        guard let latitude, let longitude else { return nil }
        return CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }
}

struct ImportedSecrets: Codable, Sendable {
    var username: String
    var aasToken: String
    var authAndroidID: String
    var sharedKeyHex: String?
    var ownerKeyHex: String?
}

struct PushCredentials: Codable, Sendable {
    var androidID: String
    var securityToken: String
    var gcmAppID: String
    var gcmToken: String
    var installationToken: String
    var installationRefreshToken: String
    var fid: String
    var registrationToken: String
    var privateKeyRaw: Data
    var publicKeyX963: Data
    var authSecret: Data
}

struct SequenceState: Codable, Sendable {
    var clientUUID: String = UUID().uuidString.lowercased()
    var requestCounter: UInt64 = 0
}

// MARK: - Generic JSON

indirect enum JSONValue: Codable, Sendable {
    case string(String), number(Double), bool(Bool), object([String: JSONValue]), array([JSONValue]), null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([String: JSONValue].self) { self = .object(v) }
        else { self = .array(try c.decode([JSONValue].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }

    var string: String? { if case .string(let v) = self { return v }; return nil }
    var object: [String: JSONValue]? { if case .object(let v) = self { return v }; return nil }
}

enum SecretsImporter {
    static func decode(_ data: Data) throws -> ImportedSecrets {
        let root = try JSONDecoder().decode(JSONValue.self, from: data)
        guard let obj = root.object else { throw FindHubError.invalidSecrets("Root JSON is not an object.") }

        let username = obj["username"]?.string ?? obj["email"]?.string ?? ""
        let aas = obj["aas_token"]?.string ?? obj["aasToken"]?.string ?? ""
        let shared = obj["shared_key"]?.string ?? obj["sharedKey"]?.string
        let owner = obj["owner_key"]?.string ?? obj["ownerKey"]?.string

        var androidID = obj["android_id"]?.string ?? ""
        if androidID.isEmpty,
           let fcm = obj["fcm_credentials"]?.object,
           let gcm = fcm["gcm"]?.object {
            androidID = gcm["android_id"]?.string ?? gcm["androidId"]?.string ?? ""
        }

        guard !username.isEmpty else { throw FindHubError.invalidSecrets("Missing username/email.") }
        guard !aas.isEmpty else { throw FindHubError.invalidSecrets("Missing aas_token.") }
        guard !androidID.isEmpty else { throw FindHubError.invalidSecrets("Missing fcm_credentials.gcm.android_id.") }
        guard shared != nil || owner != nil else {
            throw FindHubError.invalidSecrets("Missing shared_key/owner_key. Run GoogleFindMyTools through its E2EE key-unlock flow once, then import the updated secrets.json.")
        }

        return ImportedSecrets(username: username, aasToken: aas, authAndroidID: androidID, sharedKeyHex: shared, ownerKeyHex: owner)
    }

    static func export(_ secrets: ImportedSecrets, push: PushCredentials?) throws -> Data {
        var root: [String: Any] = [
            "username": secrets.username,
            "aas_token": secrets.aasToken,
            "android_id": secrets.authAndroidID
        ]
        if let shared = secrets.sharedKeyHex { root["shared_key"] = shared }
        if let owner = secrets.ownerKeyHex { root["owner_key"] = owner }
        if let push {
            root["ios_fcm_credentials"] = [
                "android_id": push.androidID,
                "security_token": push.securityToken,
                "gcm_app_id": push.gcmAppID,
                "gcm_token": push.gcmToken,
                "fid": push.fid,
                "registration_token": push.registrationToken,
                "private_key_raw": push.privateKeyRaw.base64EncodedString(),
                "public_key_x963": push.publicKeyX963.base64EncodedString(),
                "auth_secret": push.authSecret.base64EncodedString()
            ]
        }
        return try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
    }
}

// MARK: - Keychain

enum SecureStore {
    private static let service = "de.robin9094707.fmdnhub"

    static func save<T: Encodable>(_ value: T, key: String) throws {
        let data = try JSONEncoder().encode(value)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: key]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw FindHubError.keychain(status) }
    }

    static func load<T: Decodable>(_ type: T.Type, key: String) -> T? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: key,
                                    kSecReturnData as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    static func delete(_ key: String) {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: key]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Protobuf mini codec

struct ProtoField: Sendable {
    var number: Int
    var wireType: Int
    var varint: UInt64?
    var bytes: Data?
    var fixed32: UInt32?
    var fixed64: UInt64?

    var string: String? { bytes.flatMap { String(data: $0, encoding: .utf8) } }
    var message: [ProtoField] { (try? ProtoReader.read(bytes ?? Data())) ?? [] }
}

struct ProtoWriter {
    var data = Data()

    mutating func varint(_ field: Int, _ value: UInt64) {
        appendVarint(UInt64(field << 3))
        appendVarint(value)
    }

    mutating func int32(_ field: Int, _ value: Int32) {
        varint(field, UInt64(bitPattern: Int64(value)))
    }

    mutating func bool(_ field: Int, _ value: Bool) { varint(field, value ? 1 : 0) }

    mutating func bytes(_ field: Int, _ value: Data) {
        appendVarint(UInt64((field << 3) | 2))
        appendVarint(UInt64(value.count))
        data.append(value)
    }

    mutating func string(_ field: Int, _ value: String) { bytes(field, Data(value.utf8)) }

    mutating func message(_ field: Int, _ build: (inout ProtoWriter) -> Void) {
        var w = ProtoWriter(); build(&w); bytes(field, w.data)
    }

    private mutating func appendVarint(_ value: UInt64) {
        var v = value
        while true {
            if v < 0x80 { data.append(UInt8(v)); return }
            data.append(UInt8(v & 0x7f) | 0x80)
            v >>= 7
        }
    }
}

enum ProtoReader {
    static func read(_ data: Data) throws -> [ProtoField] {
        var i = 0
        var out: [ProtoField] = []
        let bytes = [UInt8](data)
        while i < bytes.count {
            let key = try readVarint(bytes, &i)
            let field = Int(key >> 3), wire = Int(key & 7)
            switch wire {
            case 0:
                out.append(ProtoField(number: field, wireType: wire, varint: try readVarint(bytes, &i)))
            case 1:
                guard i + 8 <= bytes.count else { throw FindHubError.protobuf("Truncated fixed64") }
                var v: UInt64 = 0
                for shift in 0..<8 { v |= UInt64(bytes[i + shift]) << UInt64(shift * 8) }
                i += 8
                out.append(ProtoField(number: field, wireType: wire, fixed64: v))
            case 2:
                let len = Int(try readVarint(bytes, &i))
                guard len >= 0, i + len <= bytes.count else { throw FindHubError.protobuf("Truncated bytes") }
                let d = Data(bytes[i..<(i + len)]); i += len
                out.append(ProtoField(number: field, wireType: wire, bytes: d))
            case 5:
                guard i + 4 <= bytes.count else { throw FindHubError.protobuf("Truncated fixed32") }
                let v = UInt32(bytes[i]) | UInt32(bytes[i+1]) << 8 | UInt32(bytes[i+2]) << 16 | UInt32(bytes[i+3]) << 24
                i += 4
                out.append(ProtoField(number: field, wireType: wire, fixed32: v))
            default:
                throw FindHubError.protobuf("Unsupported wire type \(wire)")
            }
        }
        return out
    }

    private static func readVarint(_ bytes: [UInt8], _ i: inout Int) throws -> UInt64 {
        var result: UInt64 = 0, shift: UInt64 = 0
        while i < bytes.count && shift < 70 {
            let b = bytes[i]; i += 1
            result |= UInt64(b & 0x7f) << shift
            if b & 0x80 == 0 { return result }
            shift += 7
        }
        throw FindHubError.protobuf("Invalid varint")
    }
}

extension Array where Element == ProtoField {
    func first(_ number: Int) -> ProtoField? { first { $0.number == number } }
    func all(_ number: Int) -> [ProtoField] { filter { $0.number == number } }
}

// MARK: - Utilities

extension Data {
    init?(hex: String) {
        let clean = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.count % 2 == 0 else { return nil }
        var data = Data(capacity: clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            guard let b = UInt8(clean[idx..<next], radix: 16) else { return nil }
            data.append(b); idx = next
        }
        self = data
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
    var base64URL: String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }

    static func fromBase64URL(_ s: String) -> Data? {
        var v = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while v.count % 4 != 0 { v.append("=") }
        return Data(base64Encoded: v)
    }
}

func be16(_ n: Int) -> Data { Data([UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]) }
func be32(_ n: Int) -> Data { Data([UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]) }

// MARK: - Errors

enum FindHubError: LocalizedError {
    case invalidSecrets(String), network(String), auth(String), protobuf(String), crypto(String), timeout, keychain(OSStatus), notReady(String)

    var errorDescription: String? {
        switch self {
        case .invalidSecrets(let s): return "Secrets: \(s)"
        case .network(let s): return "Network: \(s)"
        case .auth(let s): return "Authentication: \(s)"
        case .protobuf(let s): return "Protocol: \(s)"
        case .crypto(let s): return "Crypto: \(s)"
        case .timeout: return "The Find Hub request timed out."
        case .keychain(let s): return "Keychain error \(s)."
        case .notReady(let s): return s
        }
    }
}
