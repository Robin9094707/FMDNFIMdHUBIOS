import Foundation
import Combine

@MainActor
final class AppSession: ObservableObject {
    @Published var secrets: ImportedSecrets?
    @Published var devices: [TrackerDevice] = []
    @Published var isBusy = false
    @Published var status = "Ready"
    @Published var errorMessage: String?
    @Published var debugEvents: [String] = []

    private var pushCredentials: PushCredentials?
    private var pushBootstrap: PushBootstrapIdentity?
    private var pendingGeneratedSecrets: ImportedSecrets?
    private var sequence: SequenceState
    private var customNames: [String: String] = [:]
    private var hiddenIDs: Set<String> = []
    private var locationCache: [String: TrackerLocation] = [:]

    init() {
        secrets = SecureStore.load(ImportedSecrets.self, key: "secrets")
        pushCredentials = SecureStore.load(PushCredentials.self, key: "push")
        pushBootstrap = SecureStore.load(PushBootstrapIdentity.self, key: "push_bootstrap")
        sequence = SecureStore.load(SequenceState.self, key: "sequence") ?? SequenceState()
        loadPreferences()
        debug("App session initialized")
        if secrets != nil {
            Task { await refreshDevices() }
        }
    }

    var visibleDevices: [TrackerDevice] {
        devices.filter { !hiddenIDs.contains($0.id) }
    }

    var googleSetupAndroidID: String? {
        pushCredentials?.androidID
            ?? pushBootstrap?.androidID
    }

    var pushChannelStatus: String {
        if pushCredentials != nil {
            return "Registered"
        }
        if pushBootstrap != nil {
            return "Identity ready"
        }
        return "Not prepared"
    }


    var hiddenDevices: [TrackerDevice] {
        devices.filter { hiddenIDs.contains($0.id) }
    }

    func prepareGeneratedSetup() async -> Bool {
        if pushCredentials != nil
            || pushBootstrap != nil
        {
            debug(
                "Reusing existing Google bootstrap identity"
            )
            status = "Continue with Google"
            return true
        }

        isBusy = true
        status =
            "Preparing secure Google device identity…"
        debug(
            "Creating GCM check-in identity before EmbeddedSetup"
        )
        defer {
            isBusy = false
        }

        do {
            let identity =
                try await PushRegistrationService
                    .bootstrapIdentity()

            pushBootstrap = identity

            try SecureStore.save(
                identity,
                key: "push_bootstrap"
            )

            debug(
                "Google bootstrap identity ready"
            )
            status = "Continue with Google"
            return true
        } catch {
            present(error)
            return false
        }
    }

    func completeEmbeddedSetup(
        oauthToken: String
    ) async -> Bool {
        isBusy = true
        status = "Connecting your Google account…"
        debug("EmbeddedSetup oauth_token received")
        defer { isBusy = false }

        do {
            let androidID: String

            if let existing =
                    pushCredentials?.androidID
                    ?? pushBootstrap?.androidID
            {
                androidID = existing
                debug("Reusing existing Google bootstrap identity")
            } else {
                status = "Creating secure Google device identity…"
                debug("Creating GCM check-in identity after Google sign-in")

                let identity =
                    try await PushRegistrationService
                        .bootstrapIdentity()

                pushBootstrap = identity
                androidID = identity.androidID

                try SecureStore.save(
                    identity,
                    key: "push_bootstrap"
                )

                debug("GCM bootstrap identity created")
            }

            status = "Connecting your Google account…"
            debug("Exchanging EmbeddedSetup token with Google")

            let result =
                try await AndroidAuthService
                    .exchangeEmbeddedSetupToken(
                        oauthToken,
                        androidID: androidID
                    )

            pendingGeneratedSecrets =
                ImportedSecrets(
                    username: result.email,
                    aasToken: result.aasToken,
                    authAndroidID: androidID,
                    sharedKeyHex: nil,
                    ownerKeyHex: nil
                )

            status =
                "Google connected. Unlock Find Hub encryption."
            debug("Google token exchange succeeded; ready for finder_hw unlock")
            return true
        } catch {
            present(error)
            return false
        }
    }

    func completeSecurityUnlock(
        vaultKeys: String
    ) async -> Bool {
        guard var generated =
                pendingGeneratedSecrets
        else {
            present(
                FindHubError.notReady(
                    "Google sign in must be completed first."
                )
            )
            return false
        }

        isBusy = true
        status = "Saving Find Hub encryption keys…"
        debug("Vault callback received; parsing finder_hw key")
        defer { isBusy = false }

        do {
            let vault =
                try SecurityDomainUnlock
                    .parseFinderHWKey(
                        vaultKeys
                    )

            generated.sharedKeyHex =
                vault.key.hex
            debug("finder_hw shared key parsed successfully")

            // Store the shared key first. Owner-key retrieval uses it
            // and can be retried later if Google temporarily rejects Spot.
            try SecureStore.save(
                generated,
                key: "secrets"
            )

            do {
                let owner =
                    try await SpotService
                        .ownerKey(
                            secrets:
                                generated
                        )
                generated.ownerKeyHex =
                    owner.0.hex
                debug("Owner key retrieved successfully")
            } catch {
                debug("Owner key retrieval deferred: \(error.localizedDescription)")
                // A valid shared finder_hw key is sufficient to retry
                // owner-key retrieval during the first Locate request.
            }

            secrets = generated
            pendingGeneratedSecrets = nil

            try SecureStore.save(
                generated,
                key: "secrets"
            )

            try writeGeneratedSecretsFile(
                generated
            )

            status =
                "Find Hub account ready"
            debug("Generated secrets saved locally")

            await refreshDevices()

            Task {
                do {
                    _ = try await
                        self.ensurePushCredentials()

                    if self.status
                        .hasPrefix("Error")
                    {
                        return
                    }

                    self.status =
                        "Find Hub ready"
                } catch {
                    self.debug(
                        "Background push registration deferred: \(error.localizedDescription)"
                    )

                    if self.status
                        != "Error"
                    {
                        self.status =
                            "Trackers ready • push setup will retry when locating"
                    }
                }
            }

            return true
        } catch {
            present(error)
            return false
        }
    }

    func importSecrets(data: Data) {
        do {
            let value = try SecretsImporter.decode(data)
            secrets = value
            try SecureStore.save(value, key: "secrets")
            status = "Account imported"
            Task { await refreshDevices() }
        } catch {
            present(error)
        }
    }

    func importSequence(data: Data) {
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw FindHubError.invalidSecrets("Invalid sequence.json")
            }

            if let uuid = (object["clientUUID"] ?? object["client_uuid"] ?? object["fmdClientUuid"]) as? String,
               !uuid.isEmpty {
                sequence.clientUUID = uuid
            }
            if let counter = (object["requestCounter"] ?? object["request_counter"]) as? NSNumber {
                sequence.requestCounter = counter.uint64Value
            }

            try SecureStore.save(sequence, key: "sequence")
            status = "Sequence imported"
        } catch {
            present(error)
        }
    }

    func exportSecretsURL() -> URL? {
        guard let secrets else { return nil }
        do {
            let data = try SecretsImporter.export(secrets, push: pushCredentials)
            return try exportFile(name: "secrets.json", data: data)
        } catch {
            present(error)
            return nil
        }
    }

    func exportSequenceURL() -> URL? {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: [
                    "clientUUID": sequence.clientUUID,
                    "requestCounter": sequence.requestCounter
                ],
                options: [.prettyPrinted, .sortedKeys]
            )
            return try exportFile(name: "sequence.json", data: data)
        } catch {
            present(error)
            return nil
        }
    }

    func refreshDevices() async {
        guard let secrets else { return }
        isBusy = true
        status = "Loading trackers…"
        defer { isBusy = false }

        do {
            var loaded = try await NovaService.listDevices(secrets: secrets)
            for index in loaded.indices {
                if let custom = customNames[loaded[index].id] {
                    loaded[index].name = custom
                }
                loaded[index].lastLocation = locationCache[loaded[index].id]
            }
            devices = loaded
            status = "\(loaded.count) trackers loaded"
        } catch {
            present(error)
        }
    }

    func testPushConnection() async {
        isBusy = true
        status = "Testing secure push channel…"
        debug("Manual push-channel test started")
        defer { isBusy = false }

        do {
            let credentials =
                try await ensurePushCredentials()

            status =
                "Connecting to Google push…"

            let client =
                MCSClient(
                    credentials:
                        credentials
                )

            try await client.connect()
            client.close()

            status =
                "Push channel ready"
            debug(
                "Push-channel test succeeded"
            )
        } catch {
            present(error)
        }
    }

    private func ensurePushCredentials()
        async throws -> PushCredentials
    {
        if let pushCredentials {
            return pushCredentials
        }

        status =
            "Registering secure push channel…"

        let identity: PushBootstrapIdentity

        if let existing = pushBootstrap {
            identity = existing
        } else {
            let created =
                try await PushRegistrationService
                    .bootstrapIdentity()

            pushBootstrap = created

            try SecureStore.save(
                created,
                key: "push_bootstrap"
            )

            identity = created
        }

        debug(
            "Starting full GCM/FCM registration"
        )

        let created =
            try await PushRegistrationService
                .register(
                    identity: identity
                )

        pushCredentials = created

        try SecureStore.save(
            created,
            key: "push"
        )

        if let current = secrets {
            try? writeGeneratedSecretsFile(
                current
            )
        }

        debug(
            "Full GCM/FCM registration succeeded"
        )

        return created
    }

    func locate(_ device: TrackerDevice) async {
        guard var secrets else { return }
        isBusy = true
        status = "Locating \(device.name)…"
        defer { isBusy = false }

        var mcs: MCSClient?

        do {
            let pushCredentials =
                try await ensurePushCredentials()

            status = "Connecting to Find Hub…"
            let client = MCSClient(credentials: pushCredentials)
            mcs = client
            try await client.connect()

            sequence.requestCounter &+= 1
            try SecureStore.save(sequence, key: "sequence")

            let requestUUID = UUID().uuidString.lowercased()

            async let incoming = client.waitForFindHubPayload(
                requestUUID: requestUUID,
                timeout: 35
            )

            try await NovaService.executeLocate(
                secrets: secrets,
                deviceID: device.id,
                registrationToken: pushCredentials.registrationToken,
                requestUUID: requestUUID,
                clientUUID: sequence.clientUUID
            )

            let update = try await incoming

            status = "Decrypting location…"

            let ownerKey: Data
            if let hex = secrets.ownerKeyHex, let cached = Data(hex: hex) {
                ownerKey = cached
            } else {
                let fetched = try await SpotService.ownerKey(secrets: secrets)
                ownerKey = fetched.0
                secrets.ownerKeyHex = ownerKey.hex
                self.secrets = secrets
                try SecureStore.save(secrets, key: "secrets")
            }

            let locations = try TrackerCrypto.decryptLocations(
                deviceUpdate: update,
                ownerKey: ownerKey
            )

            guard let newest = locations.first else {
                throw FindHubError.notReady(
                    "Google returned no location reports for this tracker."
                )
            }

            locationCache[device.id] = newest
            if let index = devices.firstIndex(where: { $0.id == device.id }) {
                devices[index].lastLocation = newest
            }

            savePreferences()
            status = "Updated \(newest.timestamp.formatted(date: .omitted, time: .shortened))"
        } catch {
            present(error)
        }

        mcs?.close()
    }

    func rename(_ device: TrackerDevice, to newName: String) {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            customNames.removeValue(forKey: device.id)
        } else {
            customNames[device.id] = trimmed
        }

        if let index = devices.firstIndex(where: { $0.id == device.id }),
           !trimmed.isEmpty {
            devices[index].name = trimmed
        }

        savePreferences()
    }

    func hide(_ device: TrackerDevice) {
        hiddenIDs.insert(device.id)
        savePreferences()
        objectWillChange.send()
    }

    func restore(_ device: TrackerDevice) {
        hiddenIDs.remove(device.id)
        savePreferences()
        objectWillChange.send()
    }

    func resetPushIdentity() {
        pushCredentials = nil
        pushBootstrap = nil
        pendingGeneratedSecrets = nil
        errorMessage = nil
        SecureStore.delete("push")
        SecureStore.delete("push_bootstrap")
        status = "Setup identity reset"
        debug("Push/bootstrap identity reset")
    }

    func signOut() {
        secrets = nil
        pushCredentials = nil
        pushBootstrap = nil
        devices = []
        SecureStore.delete("secrets")
        SecureStore.delete("push")
        SecureStore.delete("push_bootstrap")
        pendingGeneratedSecrets = nil
        removeGeneratedSecretsFile()
        status = "Signed out locally"
    }

    func debug(_ message: String) {
        let stamp = Date.now.formatted(
            date: .omitted,
            time: .standard
        )
        let entry = "[\(stamp)] \(message)"
        debugEvents.append(entry)
        if debugEvents.count > 150 {
            debugEvents.removeFirst(
                debugEvents.count - 150
            )
        }
    }

    func clearDebugLog() {
        debugEvents.removeAll()
        debug("Debug log cleared")
    }

    private func present(_ error: Error) {
        debug("Error: \(error.localizedDescription)")
        errorMessage = (error as? LocalizedError)?.errorDescription
            ?? error.localizedDescription
        status = "Error"
    }

    private func writeGeneratedSecretsFile(
        _ value: ImportedSecrets
    ) throws {
        let data =
            try SecretsImporter.export(
                value,
                push: pushCredentials
            )

        let directory =
            try generatedSecretsDirectory()

        let url =
            directory
                .appendingPathComponent(
                    "secrets.json"
                )

        try data.write(
            to: url,
            options: [
                .atomic,
                .completeFileProtection
            ]
        )
    }

    private func removeGeneratedSecretsFile() {
        guard
            let directory =
                try? generatedSecretsDirectory()
        else {
            return
        }

        try? FileManager.default.removeItem(
            at:
                directory.appendingPathComponent(
                    "secrets.json"
                )
        )
    }

    private func generatedSecretsDirectory() throws -> URL {
        let base =
            try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            )

        let directory =
            base.appendingPathComponent(
                "FindHub",
                isDirectory: true
            )

        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )

        return directory
    }

    private func exportFile(name: String, data: Data) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FindHubExports", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )

        let url = directory.appendingPathComponent(name)
        try data.write(to: url, options: .atomic)
        return url
    }

    private func loadPreferences() {
        let decoder = JSONDecoder()

        if let data = UserDefaults.standard.data(forKey: "customNames"),
           let value = try? decoder.decode([String: String].self, from: data) {
            customNames = value
        }

        if let data = UserDefaults.standard.data(forKey: "hiddenIDs"),
           let value = try? decoder.decode(Set<String>.self, from: data) {
            hiddenIDs = value
        }

        if let data = UserDefaults.standard.data(forKey: "locations"),
           let value = try? decoder.decode([String: TrackerLocation].self, from: data) {
            locationCache = value
        }
    }

    private func savePreferences() {
        let encoder = JSONEncoder()

        if let data = try? encoder.encode(customNames) {
            UserDefaults.standard.set(data, forKey: "customNames")
        }
        if let data = try? encoder.encode(hiddenIDs) {
            UserDefaults.standard.set(data, forKey: "hiddenIDs")
        }
        if let data = try? encoder.encode(locationCache) {
            UserDefaults.standard.set(data, forKey: "locations")
        }
    }
}
