import SwiftUI
import MapKit
import UniformTypeIdentifiers

struct TrackerDetailView: View {
    @EnvironmentObject private var session: AppSession
    @Environment(\.openURL) private var openURL

    let deviceID: String

    @State private var renameText = ""
    @State private var showRename = false
    @State private var showHide = false
    @State private var showPermanent = false

    private var device: TrackerDevice? {
        session.devices.first { $0.id == deviceID }
    }

    var body: some View {
        ScrollView {
            if let device {
                VStack(spacing: 18) {
                    locationCard(device)

                    GlassCard {
                        VStack(alignment: .leading, spacing: 10) {
                            Text(device.name)
                                .font(.title2.bold())

                            let details = [
                                device.manufacturer,
                                device.model
                            ]
                            .filter { !$0.isEmpty }
                            .joined(separator: " · ")

                            if !details.isEmpty {
                                Text(details)
                                    .foregroundStyle(.secondary)
                            }

                            if let location = device.lastLocation {
                                Divider()

                                Label(
                                    location.timestamp.formatted(
                                        date: .abbreviated,
                                        time: .standard
                                    ),
                                    systemImage: "clock.fill"
                                )

                                if location.accuracy > 0 {
                                    Label(
                                        "± \(Int(location.accuracy.rounded())) m",
                                        systemImage: "scope"
                                    )
                                }

                                Label(
                                    sourceName(location.source),
                                    systemImage: location.isOwnReport
                                        ? "iphone"
                                        : "dot.radiowaves.left.and.right"
                                )
                            }
                        }
                    }

                    Button {
                        Task {
                            await session.locate(device)
                        }
                    } label: {
                        Label(
                            session.isBusy ? "Locating…" : "Locate now",
                            systemImage: "location.fill"
                        )
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(session.isBusy)

                    Menu {
                        Button {
                            renameText = device.name
                            showRename = true
                        } label: {
                            Label(
                                "Rename locally",
                                systemImage: "pencil"
                            )
                        }

                        Button(role: .destructive) {
                            showHide = true
                        } label: {
                            Label(
                                "Remove from this app",
                                systemImage: "eye.slash"
                            )
                        }

                        Button(role: .destructive) {
                            showPermanent = true
                        } label: {
                            Label(
                                "Remove from Google Find Hub…",
                                systemImage: "trash"
                            )
                        }
                    } label: {
                        Label(
                            "Manage tracker",
                            systemImage: "ellipsis.circle"
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                .padding()
            }
        }
        .navigationTitle(device?.name ?? "Tracker")
        .navigationBarTitleDisplayMode(.inline)
        .alert(
            "Rename tracker",
            isPresented: $showRename
        ) {
            TextField("Name", text: $renameText)

            Button("Save") {
                if let device {
                    session.rename(device, to: renameText)
                }
            }

            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog(
            "Remove this tracker from the app?",
            isPresented: $showHide,
            titleVisibility: .visible
        ) {
            Button(
                "Remove locally",
                role: .destructive
            ) {
                if let device {
                    session.hide(device)
                }
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This only hides the tracker on this iPhone. "
                + "It remains in your Google account."
            )
        }
        .confirmationDialog(
            "Open Google Find Hub to permanently remove this tracker?",
            isPresented: $showPermanent,
            titleVisibility: .visible
        ) {
            Button(
                "Open Google Find Hub",
                role: .destructive
            ) {
                openURL(
                    URL(
                        string: "https://www.google.com/android/find/"
                    )!
                )
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "Permanent removal is handed off to Google's official UI."
            )
        }
    }

    @ViewBuilder
    private func locationCard(
        _ device: TrackerDevice
    ) -> some View {
        if let location = device.lastLocation,
           let coordinate = location.coordinate {
            Map(
                initialPosition: .region(
                    MKCoordinateRegion(
                        center: coordinate,
                        latitudinalMeters: max(
                            location.accuracy * 5,
                            700
                        ),
                        longitudinalMeters: max(
                            location.accuracy * 5,
                            700
                        )
                    )
                )
            ) {
                Marker(
                    device.name,
                    coordinate: coordinate
                )
            }
            .frame(height: 330)
            .clipShape(
                RoundedRectangle(
                    cornerRadius: 28,
                    style: .continuous
                )
            )
        } else {
            GlassCard {
                VStack(spacing: 12) {
                    Image(systemName: device.kind.symbol)
                        .font(.system(size: 58))
                        .frame(maxWidth: .infinity)

                    Text("No cached location yet")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                }
            }
        }
    }

    private func sourceName(
        _ source: TrackerLocation.Source
    ) -> String {
        switch source {
        case .semantic:
            return "Saved place"
        case .lastKnown:
            return "Last known"
        case .crowdsourced:
            return "Find Hub network"
        case .aggregated:
            return "Aggregated network report"
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject private var session: AppSession

    @State private var importSecrets = false
    @State private var importSequence = false
    @State private var showSignOut = false

    var body: some View {
        NavigationStack {
            List {
                Section("Account") {
                    LabeledContent(
                        "Google account",
                        value: session.secrets?.username ?? "—"
                    )

                    LabeledContent(
                        "Status",
                        value: session.status
                    )
                }

                Section("Files") {
                    Button {
                        importSecrets = true
                    } label: {
                        Label(
                            "Import secrets.json",
                            systemImage: "square.and.arrow.down"
                        )
                    }

                    Button {
                        importSequence = true
                    } label: {
                        Label(
                            "Import sequence.json",
                            systemImage:
                                "arrow.triangle.2.circlepath.doc.on.clipboard"
                        )
                    }

                    if let url = session.exportSecretsURL() {
                        ShareLink(item: url) {
                            Label(
                                "Export secrets.json",
                                systemImage: "square.and.arrow.up"
                            )
                        }
                    }

                    if let url = session.exportSequenceURL() {
                        ShareLink(item: url) {
                            Label(
                                "Export sequence.json",
                                systemImage:
                                    "square.and.arrow.up.on.square"
                            )
                        }
                    }
                }

                Section("Hidden trackers") {
                    if session.hiddenDevices.isEmpty {
                        Text("None")
                            .foregroundStyle(.secondary)
                    }

                    ForEach(session.hiddenDevices) { device in
                        Button {
                            session.restore(device)
                        } label: {
                            Label(
                                "Restore \(device.name)",
                                systemImage: "eye"
                            )
                        }
                    }
                }

                Section("Diagnostics") {
                    Button(
                        "Reset iPhone push identity"
                    ) {
                        session.resetPushIdentity()
                    }

                    Button("Refresh trackers") {
                        Task {
                            await session.refreshDevices()
                        }
                    }
                }

                Section {
                    Button(
                        "Sign out on this iPhone",
                        role: .destructive
                    ) {
                        showSignOut = true
                    }
                } footer: {
                    Text(
                        "Find Hub uses undocumented Google endpoints, "
                        + "so server-side changes can require an app update."
                    )
                }
            }
            .navigationTitle("Settings")
        }
        .fileImporter(
            isPresented: $importSecrets,
            allowedContentTypes: [.json]
        ) { result in
            importFile(
                result,
                sequence: false
            )
        }
        .fileImporter(
            isPresented: $importSequence,
            allowedContentTypes: [.json]
        ) { result in
            importFile(
                result,
                sequence: true
            )
        }
        .confirmationDialog(
            "Sign out locally?",
            isPresented: $showSignOut,
            titleVisibility: .visible
        ) {
            Button(
                "Sign out",
                role: .destructive
            ) {
                session.signOut()
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This deletes imported credentials and "
                + "the push identity from this iPhone only."
            )
        }
    }

    private func importFile(
        _ result: Result<URL, Error>,
        sequence: Bool
    ) {
        guard case .success(let url) = result else {
            return
        }

        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                url.stopAccessingSecurityScopedResource()
            }
        }

        guard let data = try? Data(contentsOf: url) else {
            return
        }

        if sequence {
            session.importSequence(data: data)
        } else {
            session.importSecrets(data: data)
        }
    }
}
