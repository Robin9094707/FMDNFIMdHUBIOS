import Foundation
@preconcurrency import Network

enum AndroidAuthService {
    static let clientSignature = "38918a453d07199354f8b19af05ec6562ced5788"

    static func token(
        secrets: ImportedSecrets,
        scope: String,
        playServices: Bool = false
    ) async throws -> String {
        let form: [String: String] = [
            "accountType": "HOSTED_OR_GOOGLE",
            "Email": secrets.username,
            "has_permission": "1",
            "EncryptedPasswd": secrets.aasToken,
            "service": "oauth2:https://www.googleapis.com/auth/\(scope)",
            "source": "android",
            "androidId": secrets.authAndroidID,
            "app": playServices
                ? "com.google.android.gms"
                : "com.google.android.apps.adm",
            "client_sig": clientSignature,
            "device_country": "us",
            "operatorCountry": "us",
            "lang": "en",
            "sdk_version": "17",
            "google_play_services_version": "240913000"
        ]

        let body = formEncoded(form)
        let raw = try await HTTP1TLSClient.post(
            host: "android.clients.google.com",
            path: "/auth",
            headers: [
                "User-Agent": "GoogleAuth/1.4",
                "Accept-Encoding": "identity",
                "Content-Type": "application/x-www-form-urlencoded"
            ],
            body: body
        )

        guard let text = String(
            data: raw,
            encoding: .utf8
        ) else {
            throw FindHubError.auth("Unreadable auth response")
        }

        var response: [String: String] = [:]

        for line in text.split(separator: "\n") {
            let parts = line
                .split(
                    separator: "=",
                    maxSplits: 1
                )
                .map(String.init)

            if parts.count == 2 {
                response[parts[0]] = parts[1]
            }
        }

        if let auth = response["Auth"],
           !auth.isEmpty {
            return auth
        }

        throw FindHubError.auth(
            response["Error"]
            ?? response["error"]
            ?? text
        )
    }

    static func exchangeEmbeddedSetupToken(
        _ webToken: String,
        androidID: String
    ) async throws -> (email: String, aasToken: String) {
        let form: [String: String] = [
            "accountType": "HOSTED_OR_GOOGLE",
            "Email": "",
            "has_permission": "1",
            "add_account": "1",
            "ACCESS_TOKEN": "1",
            "Token": webToken,
            "service": "ac2dm",
            "source": "android",
            "androidId": androidID,
            "device_country": "us",
            "operatorCountry": "us",
            "lang": "en",
            "sdk_version": "17",
            "google_play_services_version": "240913000",
            "client_sig": clientSignature,
            "callerSig": clientSignature,
            "droidguard_results": "dummy123"
        ]

        let raw = try await HTTP1TLSClient.post(
            host: "android.clients.google.com",
            path: "/auth",
            headers: [
                "User-Agent": "GoogleAuth/1.4",
                "Accept-Encoding": "identity",
                "Content-Type": "application/x-www-form-urlencoded"
            ],
            body: formEncoded(form)
        )

        let response = parseAuthResponse(raw)

        guard let aasToken = response["Token"],
              !aasToken.isEmpty else {
            throw FindHubError.auth(
                response["Error"]
                ?? response["error"]
                ?? String(decoding: raw, as: UTF8.self)
            )
        }

        guard let email = response["Email"],
              !email.isEmpty else {
            throw FindHubError.auth(
                "Google accepted the login but did not return the account email."
            )
        }

        return (email, aasToken)
    }

    private static func parseAuthResponse(
        _ data: Data
    ) -> [String: String] {
        let text = String(decoding: data, as: UTF8.self)
        var response: [String: String] = [:]

        for line in text.split(separator: "\n") {
            let parts = line
                .split(
                    separator: "=",
                    maxSplits: 1
                )
                .map(String.init)

            if parts.count == 2 {
                response[parts[0]] = parts[1]
            }
        }

        return response
    }

    private static func formEncoded(
        _ dictionary: [String: String]
    ) -> Data {
        let allowed = CharacterSet(
            charactersIn:
                "abcdefghijklmnopqrstuvwxyz"
                + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "0123456789-._~"
        )

        let value = dictionary
            .sorted { $0.key < $1.key }
            .map { key, value in
                let encodedKey =
                    key.addingPercentEncoding(
                        withAllowedCharacters: allowed
                    )
                    ?? key

                let encodedValue =
                    value.addingPercentEncoding(
                        withAllowedCharacters: allowed
                    )
                    ?? value

                return "\(encodedKey)=\(encodedValue)"
            }
            .joined(separator: "&")

        return Data(value.utf8)
    }
}

private final class HTTP1RequestOperation: @unchecked Sendable {
    private let host: String
    private let path: String
    private let headers: [String: String]
    private let body: Data
    private let continuation: CheckedContinuation<Data, Error>
    private let connection: NWConnection
    private let queue: DispatchQueue

    private var responseData = Data()
    private var finished = false

    init(
        host: String,
        path: String,
        headers: [String: String],
        body: Data,
        continuation: CheckedContinuation<Data, Error>
    ) {
        self.host = host
        self.path = path
        self.headers = headers
        self.body = body
        self.continuation = continuation

        let tls = NWProtocolTLS.Options()
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        self.connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: 443,
            using: NWParameters(tls: tls, tcp: tcp)
        )
        self.queue = DispatchQueue(
            label: "FindHub.HTTP1.\(UUID().uuidString)"
        )
    }

    func start() {
        connection.stateUpdateHandler = { [self] state in
            handle(state)
        }
        connection.start(queue: queue)
    }

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            sendRequest()

        case .failed(let error):
            finish(.failure(error))

        case .cancelled:
            if !finished {
                finish(
                    .failure(
                        FindHubError.network(
                            "Connection cancelled"
                        )
                    )
                )
            }

        default:
            break
        }
    }

    private func sendRequest() {
        var request =
            "POST \(path) HTTP/1.1\r\n"
            + "Host: \(host)\r\n"
            + "Connection: close\r\n"
            + "Content-Length: \(body.count)\r\n"

        for (key, value) in headers {
            request += "\(key): \(value)\r\n"
        }

        request += "\r\n"

        var packet = Data(request.utf8)
        packet.append(body)

        connection.send(
            content: packet,
            completion: .contentProcessed { [self] error in
                if let error {
                    finish(.failure(error))
                }
            }
        )

        receive()
    }

    private func receive() {
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: 64 * 1024
        ) { [self] content, _, isComplete, error in
            if let content {
                responseData.append(content)
            }

            if let error {
                finish(.failure(error))
                return
            }

            if isComplete {
                do {
                    finish(
                        .success(
                            try HTTP1TLSClient.parseHTTPResponse(
                                responseData
                            )
                        )
                    )
                } catch {
                    finish(.failure(error))
                }
                return
            }

            receive()
        }
    }

    private func finish(
        _ result: Result<Data, Error>
    ) {
        guard !finished else {
            return
        }

        finished = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        continuation.resume(with: result)
    }
}

private enum HTTP1TLSClient {
    static func post(
        host: String,
        path: String,
        headers: [String: String],
        body: Data
    ) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let operation = HTTP1RequestOperation(
                host: host,
                path: path,
                headers: headers,
                body: body,
                continuation: continuation
            )
            operation.start()
        }
    }

    fileprivate static func parseHTTPResponse(
        _ data: Data
    ) throws -> Data {
        guard let marker = data.range(
            of: Data("\r\n\r\n".utf8)
        ) else {
            throw FindHubError.network(
                "Malformed HTTP response"
            )
        }

        let head = data[..<marker.lowerBound]
        var body = Data(
            data[marker.upperBound...]
        )

        let headerText = String(
            decoding: head,
            as: UTF8.self
        )

        guard
            let statusLine =
                headerText
                    .components(
                        separatedBy: "\r\n"
                    )
                    .first,
            let status = Int(
                statusLine
                    .split(separator: " ")
                    .dropFirst()
                    .first
                    ?? "0"
            ),
            (200..<300).contains(status)
        else {
            throw FindHubError.network(
                "HTTP response: "
                + String(
                    headerText.prefix(160)
                )
            )
        }

        if headerText
            .lowercased()
            .contains(
                "transfer-encoding: chunked"
            ) {
            body = try decodeChunked(body)
        }

        return body
    }

    private static func decodeChunked(
        _ data: Data
    ) throws -> Data {
        var input = data
        var output = Data()

        while !input.isEmpty {
            guard let range = input.range(
                of: Data("\r\n".utf8)
            ) else {
                break
            }

            let line = String(
                decoding:
                    input[..<range.lowerBound],
                as: UTF8.self
            )

            guard let count = Int(
                line.trimmingCharacters(
                    in:
                        CharacterSet.whitespacesAndNewlines
                ),
                radix: 16
            ) else {
                throw FindHubError.network(
                    "Bad chunk size"
                )
            }

            input.removeSubrange(
                ..<range.upperBound
            )

            if count == 0 {
                break
            }

            guard input.count >= count + 2 else {
                throw FindHubError.network(
                    "Truncated chunk"
                )
            }

            output.append(
                input.prefix(count)
            )

            input.removeSubrange(
                ..<(count + 2)
            )
        }

        return output
    }
}

enum NovaService {
    static func listDevices(
        secrets: ImportedSecrets
    ) async throws -> [TrackerDevice] {
        let auth =
            try await AndroidAuthService
                .token(
                    secrets: secrets,
                    scope:
                        "android_device_manager"
                )

        var request = ProtoWriter()

        request.message(1) { payload in
            payload.varint(1, 2)
            payload.string(
                3,
                UUID()
                    .uuidString
                    .lowercased()
            )
        }

        let data =
            try await post(
                scope:
                    "nbe_list_devices",
                token: auth,
                payload: request.data
            )

        return try parseDevices(data)
    }

    static func executeLocate(
        secrets: ImportedSecrets,
        deviceID: String,
        registrationToken: String,
        requestUUID: String,
        clientUUID: String
    ) async throws {
        let auth =
            try await AndroidAuthService
                .token(
                    secrets: secrets,
                    scope:
                        "android_device_manager"
                )

        var writer = ProtoWriter()

        writer.message(1) { scope in
            scope.varint(2, 2)
            scope.message(3) { device in
                device.message(1) { id in
                    id.string(
                        1,
                        deviceID
                    )
                }
            }
        }

        writer.message(2) { action in
            action.message(30) { locate in
                locate.message(2) {
                    time in
                    time.varint(
                        1,
                        1_732_120_060
                    )
                }
                locate.varint(3, 2)
            }
        }

        writer.message(3) { metadata in
            metadata.varint(1, 2)
            metadata.string(
                2,
                requestUUID
            )
            metadata.string(
                3,
                clientUUID
            )
            metadata.message(4) {
                gcm in
                gcm.string(
                    1,
                    registrationToken
                )
            }
            metadata.bool(6, true)
        }

        _ =
            try await post(
                scope:
                    "nbe_execute_action",
                token: auth,
                payload: writer.data
            )
    }

    private static func post(
        scope: String,
        token: String,
        payload: Data
    ) async throws -> Data {
        var request = URLRequest(
            url: URL(
                string:
                    "https://android.googleapis.com/nova/\(scope)"
            )!
        )

        request.httpMethod = "POST"
        request.httpBody = payload
        request.timeoutInterval = 30
        request.setValue(
            "application/x-www-form-urlencoded; charset=UTF-8",
            forHTTPHeaderField:
                "Content-Type"
        )
        request.setValue(
            "Bearer \(token)",
            forHTTPHeaderField:
                "Authorization"
        )
        request.setValue(
            "en-US",
            forHTTPHeaderField:
                "Accept-Language"
        )
        request.setValue(
            "fmd/20006320; gzip",
            forHTTPHeaderField:
                "User-Agent"
        )

        let (data, response) =
            try await URLSession.shared
                .data(for: request)

        guard
            let http =
                response
                    as? HTTPURLResponse,
            http.statusCode == 200
        else {
            throw FindHubError.network(
                "Nova \(scope) returned "
                + "\((response as? HTTPURLResponse)?.statusCode ?? -1): "
                + String(
                    decoding: data,
                    as: UTF8.self
                )
            )
        }

        return data
    }

    private static func parseDevices(
        _ data: Data
    ) throws -> [TrackerDevice] {
        let root =
            try ProtoReader.read(data)

        var devices: [TrackerDevice] = []

        for metadataField in root.all(2) {
            let metadata =
                metadataField.message

            let name =
                metadata.first(5)?.string
                ?? "Find Hub Tracker"

            let image =
                metadata
                    .first(6)?
                    .message
                    .first(1)?
                    .string
                    .flatMap(URL.init(string:))

            let identifier =
                metadata
                    .first(1)?
                    .message
                ?? []

            let idType = Int(
                identifier
                    .first(2)?
                    .varint
                ?? 0
            )

            let idsContainer:
                [ProtoField]

            if idType == 1 {
                idsContainer =
                    identifier
                        .first(1)?
                        .message
                        .first(2)?
                        .message
                    ?? []
            } else {
                idsContainer =
                    identifier
                        .first(3)?
                        .message
                    ?? []
            }

            let ids =
                idsContainer
                    .all(1)
                    .compactMap {
                        $0.message
                            .first(1)?
                            .string
                    }

            let information =
                metadata
                    .first(4)?
                    .message
                ?? []

            let registration =
                information
                    .first(1)?
                    .message
                ?? []

            let kindRaw = Int(
                registration
                    .first(2)?
                    .message
                    .first(2)?
                    .varint
                ?? 0
            )

            let manufacturer =
                registration
                    .first(20)?
                    .string
                ?? ""

            let model =
                registration
                    .first(34)?
                    .string
                ?? ""

            let access =
                information
                    .all(3)
                    .map {
                        $0.message
                    }

            let owner =
                access
                    .first {
                        $0.first(4)?
                            .varint
                        == 1
                    }?
                    .first(3)?
                    .varint
                == 1

            for id in ids
            where !id.isEmpty {
                devices.append(
                    TrackerDevice(
                        id: id,
                        name: name,
                        manufacturer:
                            manufacturer,
                        model: model,
                        imageURL: image,
                        kind:
                            TrackerDevice
                                .Kind(
                                    rawValue:
                                        kindRaw
                                )
                            ?? .unknown,
                        isOwner: owner,
                        lastLocation: nil
                    )
                )
            }
        }

        return devices
    }
}
