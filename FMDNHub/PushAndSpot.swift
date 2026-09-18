import Foundation
import CryptoKit
import Security

// MARK: - FCM/GCM registration

struct PushBootstrapIdentity: Codable, Sendable {
    let androidID: String
    let securityToken: String
}

enum PushRegistrationService {
    static let projectID = "google.com:api-project-289722593072"
    static let appID = "1:289722593072:android:3cfcf5bc359f0308"
    static let apiKey = "AIzaSyD_gko3P392v6how2H7UpdeXQ0v2HLettc"
    static let package = "com.google.android.apps.adm"
    static let certificateSHA1 = AndroidAuthService.clientSignature
    static let gcmServerKey = "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4"

    static func bootstrapIdentity() async throws -> PushBootstrapIdentity {
        let checkin = try await gcmCheckin()
        return PushBootstrapIdentity(
            androidID: checkin.androidID,
            securityToken: checkin.securityToken
        )
    }

    static func register() async throws -> PushCredentials {
        let identity = try await bootstrapIdentity()
        return try await register(
            identity: identity
        )
    }

    static func register(
        identity: PushBootstrapIdentity
    ) async throws -> PushCredentials {
        let appID = "wp:\(package)#\(UUID().uuidString)"
        let gcmToken = try await gcmRegister(
            androidID: identity.androidID,
            securityToken: identity.securityToken,
            appID: appID
        )
        let installation = try await firebaseInstall()

        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey.x963Representation
        var random = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            throw FindHubError.crypto("Random generation failed")
        }
        let authSecret = Data(random)

        let registration = try await firebaseRegister(
            gcmToken: gcmToken,
            installationToken: installation.token,
            publicKey: publicKey,
            authSecret: authSecret
        )

        return PushCredentials(
            androidID: identity.androidID,
            securityToken: identity.securityToken,
            gcmAppID: appID,
            gcmToken: gcmToken,
            installationToken: installation.token,
            installationRefreshToken: installation.refreshToken,
            fid: installation.fid,
            registrationToken: registration,
            privateKeyRaw: privateKey.rawRepresentation,
            publicKeyX963: publicKey,
            authSecret: authSecret
        )
    }

    private static func gcmCheckin() async throws -> (androidID: String, securityToken: String) {
        func makePayload() -> Data {
            var chrome = ProtoWriter()
            chrome.varint(1, 3)
            chrome.string(2, "94.0.4606.51")
            chrome.varint(3, 1)

            var checkin = ProtoWriter()
            checkin.varint(12, 3)
            checkin.bytes(13, chrome.data)

            var request = ProtoWriter()
            request.bytes(4, checkin.data)
            request.varint(14, 3)
            request.varint(22, 0)
            return request.data
        }

        var lastError = "Unknown GCM check-in error"

        // Match the working fork: GCM check-in is deliberately very patient.
        // Google sometimes rejects or times out several initial requests before
        // issuing a valid android_id/security_token pair.
        for attempt in 1...100 {
            var req = URLRequest(
                url: URL(
                    string: "https://android.clients.google.com/checkin"
                )!
            )
            req.httpMethod = "POST"
            req.httpBody = makePayload()
            req.timeoutInterval = 30
            req.setValue(
                "application/x-protobuf",
                forHTTPHeaderField: "Content-Type"
            )

            do {
                let (data, response) =
                    try await URLSession.shared.data(for: req)

                let status =
                    (response as? HTTPURLResponse)?
                        .statusCode
                    ?? -1

                if status == 200 {
                    let fields =
                        try ProtoReader.read(data)

                    if let android =
                            fields.first(7)?.fixed64,
                       let security =
                            fields.first(8)?.fixed64
                    {
                        return (
                            String(android),
                            String(security)
                        )
                    }

                    lastError =
                        "HTTP 200 but GCM check-in IDs were missing"
                } else {
                    lastError =
                        "HTTP \(status): "
                        + String(
                            decoding: data,
                            as: UTF8.self
                        )
                }
            } catch {
                lastError =
                    error.localizedDescription
            }

            guard attempt < 100 else {
                break
            }

            try await Task.sleep(
                for: .seconds(1)
            )
        }

        throw FindHubError.network(
            "GCM check-in failed after retries: \(lastError)"
        )
    }

    private static func gcmRegister(
        androidID: String,
        securityToken: String,
        appID: String
    ) async throws -> String {
        let body = formEncoded([
            "app": "org.chromium.linux",
            "X-subtype": appID,
            "device": androidID,
            "sender": gcmServerKey
        ])

        var lastError =
            "Unknown GCM registration error"

        // The working fork retries *every* GCM Error response and network
        // failure up to 100 times with the same legacy sender key.
        for attempt in 1...100 {
            var req = URLRequest(
                url: URL(
                    string:
                        "https://android.clients.google.com/c2dm/register3"
                )!
            )
            req.httpMethod = "POST"
            req.httpBody = body
            req.timeoutInterval = 30
            req.setValue(
                "AidLogin \(androidID):\(securityToken)",
                forHTTPHeaderField:
                    "Authorization"
            )
            req.setValue(
                "application/x-www-form-urlencoded",
                forHTTPHeaderField:
                    "Content-Type"
            )

            do {
                let (data, response) =
                    try await URLSession.shared.data(
                        for: req
                    )

                let text =
                    String(
                        decoding: data,
                        as: UTF8.self
                    )
                    .trimmingCharacters(
                        in: .whitespacesAndNewlines
                    )

                let status =
                    (response as? HTTPURLResponse)?
                        .statusCode
                    ?? -1

                for line in text.split(
                    whereSeparator: { $0.isNewline }
                ) {
                    let value = String(line)

                    if value.hasPrefix("token=") {
                        return String(
                            value.dropFirst(6)
                        )
                    }
                }

                lastError = text.isEmpty
                    ? "HTTP \(status)"
                    : text
            } catch {
                lastError =
                    error.localizedDescription
            }

            guard attempt < 100 else {
                break
            }

            try await Task.sleep(
                for: .seconds(1)
            )
        }

        throw FindHubError.network(
            "GCM registration failed after retries: \(lastError)"
        )
    }

    private static func firebaseInstall() async throws -> (token: String, refreshToken: String, fid: String) {
        var lastError =
            "Unknown Firebase installation error"

        for attempt in 1...8 {
            var fidBytes =
                [UInt8](
                    repeating: 0,
                    count: 17
                )

            guard
                SecRandomCopyBytes(
                    kSecRandomDefault,
                    fidBytes.count,
                    &fidBytes
                ) == errSecSuccess
            else {
                throw FindHubError.crypto(
                    "Random generation failed"
                )
            }

            fidBytes[0] =
                0x70 | (fidBytes[0] & 0x0f)

            let fid =
                Data(fidBytes)
                    .base64EncodedString()

            let payload: [String: Any] = [
                "appId": appID,
                "authVersion": "FIS_v2",
                "fid": fid,
                "sdkVersion": "w:0.6.6"
            ]

            var req = URLRequest(
                url: URL(
                    string:
                        "https://firebaseinstallations.googleapis.com/v1/projects/\(projectID)/installations"
                )!
            )
            req.httpMethod = "POST"
            req.httpBody =
                try JSONSerialization.data(
                    withJSONObject: payload
                )
            req.timeoutInterval = 30

            let heartbeat =
                Data(
                    "{\"heartbeats\":[],\"version\":2}".utf8
                )
                .base64EncodedString()

            req.setValue(
                heartbeat,
                forHTTPHeaderField:
                    "x-firebase-client"
            )
            req.setValue(
                apiKey,
                forHTTPHeaderField:
                    "x-goog-api-key"
            )
            req.setValue(
                package,
                forHTTPHeaderField:
                    "X-Android-Package"
            )
            req.setValue(
                certificateSHA1,
                forHTTPHeaderField:
                    "X-Android-Cert"
            )
            req.setValue(
                "application/json",
                forHTTPHeaderField:
                    "Content-Type"
            )

            do {
                let (data, response) =
                    try await URLSession.shared.data(
                        for: req
                    )

                let status =
                    (response as? HTTPURLResponse)?
                        .statusCode
                    ?? -1

                if status == 200,
                   let obj =
                    try JSONSerialization
                        .jsonObject(
                            with: data
                        )
                        as? [String: Any],
                   let auth =
                    obj["authToken"]
                        as? [String: Any],
                   let token =
                    auth["token"] as? String,
                   let refresh =
                    obj["refreshToken"]
                        as? String,
                   let returnedFID =
                    obj["fid"] as? String
                {
                    return (
                        token,
                        refresh,
                        returnedFID
                    )
                }

                lastError =
                    "HTTP \(status): "
                    + String(
                        decoding: data,
                        as: UTF8.self
                    )
            } catch {
                lastError =
                    error.localizedDescription
            }

            guard attempt < 8 else {
                break
            }

            try await Task.sleep(
                for: .seconds(1)
            )
        }

        throw FindHubError.network(
            "Firebase installation failed after retries: \(lastError)"
        )
    }

    private static func firebaseRegister(
        gcmToken: String,
        installationToken: String,
        publicKey: Data,
        authSecret: Data
    ) async throws -> String {
        let payload: [String: Any] = [
            "web": [
                "auth": authSecret.base64URL,
                "endpoint":
                    "https://fcm.googleapis.com/fcm/send/\(gcmToken)",
                "p256dh": publicKey.base64URL
            ]
        ]

        var lastError =
            "Unknown FCM registration error"

        for attempt in 1...8 {
            var req = URLRequest(
                url: URL(
                    string:
                        "https://fcmregistrations.googleapis.com/v1/projects/\(projectID)/registrations"
                )!
            )
            req.httpMethod = "POST"
            req.httpBody =
                try JSONSerialization.data(
                    withJSONObject: payload
                )
            req.timeoutInterval = 30
            req.setValue(
                apiKey,
                forHTTPHeaderField:
                    "x-goog-api-key"
            )
            req.setValue(
                installationToken,
                forHTTPHeaderField:
                    "x-goog-firebase-installations-auth"
            )
            req.setValue(
                package,
                forHTTPHeaderField:
                    "X-Android-Package"
            )
            req.setValue(
                certificateSHA1,
                forHTTPHeaderField:
                    "X-Android-Cert"
            )
            req.setValue(
                "application/json",
                forHTTPHeaderField:
                    "Content-Type"
            )

            do {
                let (data, response) =
                    try await URLSession.shared.data(
                        for: req
                    )

                let status =
                    (response as? HTTPURLResponse)?
                        .statusCode
                    ?? -1

                if status == 200,
                   let obj =
                    try JSONSerialization
                        .jsonObject(
                            with: data
                        )
                        as? [String: Any],
                   let token =
                    obj["token"] as? String,
                   !token.isEmpty
                {
                    return token
                }

                lastError =
                    "HTTP \(status): "
                    + String(
                        decoding: data,
                        as: UTF8.self
                    )
            } catch {
                lastError =
                    error.localizedDescription
            }

            guard attempt < 8 else {
                break
            }

            try await Task.sleep(
                for: .seconds(1)
            )
        }

        throw FindHubError.network(
            "FCM registration failed after retries: \(lastError)"
        )
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
