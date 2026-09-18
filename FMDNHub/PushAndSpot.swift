import Foundation
import CryptoKit
import Security

// MARK: - FCM/GCM registration

enum PushRegistrationService {
    static let projectID = "google.com:api-project-289722593072"
    static let appID = "1:289722593072:android:3cfcf5bc359f0308"
    static let apiKey = "AIzaSyD_gko3P392v6how2H7UpdeXQ0v2HLettc"
    static let package = "com.google.android.apps.adm"
    static let certificateSHA1 = AndroidAuthService.clientSignature
    static let gcmServerKey = "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4"

    static func register() async throws -> PushCredentials {
        let checkin = try await gcmCheckin()
        let appID = "wp:\(package)#\(UUID().uuidString)"
        let gcmToken = try await gcmRegister(androidID: checkin.androidID, securityToken: checkin.securityToken, appID: appID)
        let installation = try await firebaseInstall()

        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey.x963Representation
        var random = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else { throw FindHubError.crypto("Random generation failed") }
        let authSecret = Data(random)

        let registration = try await firebaseRegister(gcmToken: gcmToken,
                                                      installationToken: installation.token,
                                                      publicKey: publicKey,
                                                      authSecret: authSecret)
        return PushCredentials(androidID: checkin.androidID,
                               securityToken: checkin.securityToken,
                               gcmAppID: appID,
                               gcmToken: gcmToken,
                               installationToken: installation.token,
                               installationRefreshToken: installation.refreshToken,
                               fid: installation.fid,
                               registrationToken: registration,
                               privateKeyRaw: privateKey.rawRepresentation,
                               publicKeyX963: publicKey,
                               authSecret: authSecret)
    }

    private static func gcmCheckin() async throws -> (androidID: String, securityToken: String) {
        var chrome = ProtoWriter(); chrome.varint(1, 3); chrome.string(2, "131.0.0.0"); chrome.varint(3, 1)
        var checkin = ProtoWriter(); checkin.varint(12, 3); checkin.bytes(13, chrome.data)
        var reqProto = ProtoWriter(); reqProto.bytes(4, checkin.data); reqProto.varint(14, 3); reqProto.varint(22, 0)

        var req = URLRequest(url: URL(string: "https://android.clients.google.com/checkin")!)
        req.httpMethod = "POST"; req.httpBody = reqProto.data; req.timeoutInterval = 30
        req.setValue("application/x-protobuf", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw FindHubError.network("GCM check-in failed") }
        let fields = try ProtoReader.read(data)
        guard let android = fields.first(7)?.fixed64, let sec = fields.first(8)?.fixed64 else { throw FindHubError.protobuf("GCM check-in IDs missing") }
        return (String(android), String(sec))
    }

    private static func gcmRegister(androidID: String, securityToken: String, appID: String) async throws -> String {
        let body = formEncoded([
            "app": "org.chromium.linux",
            "X-subtype": appID,
            "device": androidID,
            "sender": gcmServerKey
        ])
        var req = URLRequest(url: URL(string: "https://android.clients.google.com/c2dm/register3")!)
        req.httpMethod = "POST"; req.httpBody = body; req.timeoutInterval = 30
        req.setValue("AidLogin \(androidID):\(securityToken)", forHTTPHeaderField: "Authorization")
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: req)
        let text = String(decoding: data, as: UTF8.self)
        guard (response as? HTTPURLResponse)?.statusCode == 200, text.hasPrefix("token=") else { throw FindHubError.network("GCM registration failed: \(text)") }
        return String(text.dropFirst(6))
    }

    private static func firebaseInstall() async throws -> (token: String, refreshToken: String, fid: String) {
        var fidBytes = [UInt8](repeating: 0, count: 17)
        guard SecRandomCopyBytes(kSecRandomDefault, fidBytes.count, &fidBytes) == errSecSuccess else { throw FindHubError.crypto("Random generation failed") }
        fidBytes[0] = 0x70 | (fidBytes[0] & 0x0f)
        let fid = Data(fidBytes).base64EncodedString()
        let payload: [String: Any] = ["appId": appID, "authVersion": "FIS_v2", "fid": fid, "sdkVersion": "w:0.6.6"]
        var req = URLRequest(url: URL(string: "https://firebaseinstallations.googleapis.com/v1/projects/\(projectID)/installations")!)
        req.httpMethod = "POST"; req.httpBody = try JSONSerialization.data(withJSONObject: payload); req.timeoutInterval = 30
        req.setValue(apiKey, forHTTPHeaderField: "x-goog-api-key")
        req.setValue(package, forHTTPHeaderField: "X-Android-Package")
        req.setValue(certificateSHA1, forHTTPHeaderField: "X-Android-Cert")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let auth = obj["authToken"] as? [String: Any],
              let token = auth["token"] as? String,
              let refresh = obj["refreshToken"] as? String,
              let returnedFID = obj["fid"] as? String else {
            throw FindHubError.network("Firebase installation failed: \(String(decoding: data, as: UTF8.self))")
        }
        return (token, refresh, returnedFID)
    }

    private static func firebaseRegister(gcmToken: String, installationToken: String, publicKey: Data, authSecret: Data) async throws -> String {
        let payload: [String: Any] = ["web": [
            "auth": authSecret.base64URL,
            "endpoint": "https://fcm.googleapis.com/fcm/send/\(gcmToken)",
            "p256dh": publicKey.base64URL
        ]]
        var req = URLRequest(url: URL(string: "https://fcmregistrations.googleapis.com/v1/projects/\(projectID)/registrations")!)
        req.httpMethod = "POST"; req.httpBody = try JSONSerialization.data(withJSONObject: payload); req.timeoutInterval = 30
        req.setValue(apiKey, forHTTPHeaderField: "x-goog-api-key")
        req.setValue(installationToken, forHTTPHeaderField: "x-goog-firebase-installations-auth")
        req.setValue(package, forHTTPHeaderField: "X-Android-Package")
        req.setValue(certificateSHA1, forHTTPHeaderField: "X-Android-Cert")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw FindHubError.network("FCM registration failed: \(String(decoding: data, as: UTF8.self))")
        }
        if let token = obj["token"] as? String { return token }
        if let name = obj["name"] as? String { return name.components(separatedBy: "/").last ?? name }
        throw FindHubError.network("FCM registration token missing")
    }

    private static func formEncoded(_ dict: [String: String]) -> Data {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
        let text = dict.map { key, value in
            "\(key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key)=\(value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value)"
        }.joined(separator: "&")
        return Data(text.utf8)
    }
}

// MARK: - Spot owner-key retrieval

enum SpotService {
    static func ownerKey(secrets: ImportedSecrets) async throws -> (Data, Int) {
        if let hex = secrets.ownerKeyHex, let key = Data(hex: hex) { return (key, -1) }
        guard let sharedHex = secrets.sharedKeyHex, let shared = Data(hex: sharedHex) else { throw FindHubError.notReady("A shared_key or owner_key is required.") }
        let token = try await AndroidAuthService.token(secrets: secrets, scope: "spot", playServices: true)

        var p = ProtoWriter(); p.int32(1, -1); p.bool(2, true)
        var grpc = Data([0]); grpc.append(be32(p.data.count)); grpc.append(p.data)
        var req = URLRequest(url: URL(string: "https://spot-pa.googleapis.com/google.internal.spot.v1.SpotService/GetEidInfoForE2eeDevices")!)
        req.httpMethod = "POST"; req.httpBody = grpc; req.timeoutInterval = 30
        req.setValue("com.google.android.gms/244433022 grpc-java-cronet/1.69.0-SNAPSHOT", forHTTPHeaderField: "User-Agent")
        req.setValue("application/grpc", forHTTPHeaderField: "Content-Type")
        req.setValue("trailers", forHTTPHeaderField: "Te")
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("gzip", forHTTPHeaderField: "Grpc-Accept-Encoding")
        let (data, response) = try await URLSession.shared.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200, data.count >= 5 else { throw FindHubError.network("Spot owner-key request failed") }
        let payload = Data(data.dropFirst(5))
        let fields = try ProtoReader.read(payload)
        let meta = fields.first(4)?.message ?? []
        guard let encrypted = meta.first(1)?.bytes else { throw FindHubError.protobuf("Encrypted owner key missing") }
        let version = Int(Int32(truncatingIfNeeded: meta.first(2)?.varint ?? 0))
        let owner = try TrackerCrypto.aesGCMDecrypt(encrypted, key: shared)
        return (owner, version)
    }
}
