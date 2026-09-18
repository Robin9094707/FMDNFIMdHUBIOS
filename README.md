# Find Hub iOS

Native SwiftUI client for your own Google Find Hub / Find My Device trackers, based on the interoperability research in [leonboe1/GoogleFindMyTools](https://github.com/leonboe1/GoogleFindMyTools).

## What works

- Native SwiftUI tracker list, detail screens and MapKit location view
- Liquid-Glass-style UI with native `glassEffect()` when the build SDK supports it and a material fallback otherwise
- **In-app Google account setup** through Google's `EmbeddedSetup` page
- On-device exchange of Google's one-time `oauth_token` for the Android AAS/master token
- In-app Google security-domain unlock for `finder_hw`
- Android-device/PIN verification happens inside Google's page, not in custom app UI
- Automatic generation of the app's Find Hub secrets after successful sign-in/unlock
- Protected internal `secrets.json` plus iOS Keychain storage
- Import/export of `secrets.json` remains available as an advanced fallback
- Local `sequence.json` import/export for client UUID/request state
- Direct `nbe_list_devices` calls to Google Nova
- Fresh GCM/FCM registration on the iPhone for location replies
- Foreground MCS connection to Google push infrastructure
- `nbe_execute_action` Locate requests
- Spot owner-key retrieval
- WebPush `aesgcm` decoding
- Standard Find Hub location decryption (own reports plus SECP160R1/HKDF/AES-EAX crowdsourced reports)
- Local rename/hide with confirmation, restore hidden trackers, and handoff to Google's official Find Hub UI for permanent account removal
- GitHub Actions unsigned IPA build

## In-app authentication flow

1. Tap **Sign in with Google**.
2. The app prepares its own Android/GCM identity on the iPhone.
3. A WKWebView opens Google's `https://accounts.google.com/EmbeddedSetup` flow.
4. Sign in normally on Google's page, including password and 2-Step Verification if Google requests them.
5. After Google issues the short-lived `oauth_token`, the app exchanges it on-device for the AAS/master token.
6. The app opens Google's `https://accounts.google.com/encryption/unlock/android` flow for the `finder_hw` security domain.
7. Google may ask for the screen-lock PIN of an Android device already associated with the account.
8. Google returns the Find Hub vault shared key to the embedded Android-style bridge.
9. The app derives/retrieves the owner key, generates its local Find Hub secrets and loads the account's trackers.

The app does **not** read or store the Google password or Android-device PIN. Those values are entered into Google-hosted pages. The app does receive and store the resulting authentication tokens and E2EE key material required to access the signed-in user's Find Hub account.

The EmbeddedSetup and Find Hub interfaces are private/undocumented Google flows and can change without notice.

## Storage

The canonical secrets are stored in iOS Keychain. After successful first-time setup, the app also writes a protected internal `secrets.json` inside its Application Support container using iOS complete file protection. It can be exported manually from Settings.

## Existing secrets

If in-app authentication stops working because Google changes the private flow, **Advanced / existing setup** can still import a compatible `secrets.json` created by GoogleFindMyTools.

## Build

1. `brew install xcodegen`
2. `xcodegen generate`
3. Open `FMDNHub.xcodeproj`
4. Select your Apple Development team if you want to install directly from Xcode.

GitHub Actions builds `FindHub-unsigned.ipa`. An unsigned IPA must still be signed before installation on a normal iPhone.

## Compatibility

Google's private Find Hub endpoints can change without notice. The current implementation targets the standard SECP160R1 tracker format used by GoogleFindMyTools. P-256/32-byte advertisement variants require additional crypto support.

Persistent MCS reception is designed for foreground Locate requests. iOS can suspend arbitrary long-lived sockets when the app is backgrounded.

## Credits

GPL-3.0. Protocol behavior and protobuf layouts are based on GoogleFindMyTools by Leon Böttger. Android-style authentication behavior references gpsoauth and microG's EmbeddedSetup implementation. WebPush legacy `aesgcm` key derivation follows the public `http_ece` implementation. See `THIRD_PARTY_NOTICES.md`.
