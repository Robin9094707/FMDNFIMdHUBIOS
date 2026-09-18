import Foundation
import Combine

@MainActor
final class AppSession: ObservableObject {
    @Published var secrets: ImportedSecrets?
    @Published var devices: [TrackerDevice] = []
    @Published var isBusy = false
    @Published var status = "Ready"
    @Published var errorMessage: String?

    private var pushCredentials: PushCredentials?
    private var sequence: SequenceState
    private var customNames: [String: String] = [:]
    private var hiddenIDs: Set<String> = []
    private var locationCache: [String: TrackerLocation] = [:]

    init() {
        secrets = SecureStore.load(ImportedSecrets.self, key: "secrets")
        pushCredentials = SecureStore.load(PushCredentials.self, key: "push")
        sequence = SecureStore.load(SequenceState.self, key: "sequence") ?? SequenceState()
        loadPreferences()
        if secrets != nil {
            Task { await refreshDevices() }
        }
    }

    var visibleDevices: [TrackerDevice] {
        devices.filter { !hiddenIDs.contains($0.id) }
    }

    var hiddenDevices: [TrackerDevice] {
        devices.filter { hiddenIDs.contains($0.id) }
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

    func locate(_ device: TrackerDevice) async {
        guard var secrets else { return }
        isBusy = true
        status = "Locating \(device.name)…"
        defer { isBusy = false }

        var mcs: MCSClient?

        do {
            if pushCredentials == nil {
                status = "Registering secure push channel…"
                let created = try await PushRegistrationService.register()
                pushCredentials = created
                try SecureStore.save(created, key: "push")
            }

            guard let pushCredentials else {
                throw FindHubError.notReady("Push registration unavailable")
            }

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
        SecureStore.delete("push")
        status = "Push identity reset"
    }

    func signOut() {
        secrets = nil
        pushCredentials = nil
        devices = []
        SecureStore.delete("secrets")
        SecureStore.delete("push")
        status = "Signed out locally"
    }

    private func present(_ error: Error) {
        errorMessage = (error as? LocalizedError)?.errorDescription
            ?? error.localizedDescription
        status = "Error"
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
