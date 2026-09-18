# Find Hub iOS

Native SwiftUI client for your own Google Find Hub / Find My Device trackers, based on the interoperability research in [leonboe1/GoogleFindMyTools](https://github.com/leonboe1/GoogleFindMyTools).

## What works

- Native SwiftUI tracker list, detail screens and MapKit location view
- Liquid-Glass-style UI with native `glassEffect()` when the build SDK supports it and a material fallback otherwise
- Import/export of `secrets.json`
- Local `sequence.json` import/export for client UUID/request state
- Tokens and E2EE material stored in iOS Keychain
- Android Device Manager OAuth from an already-authorized AAS/master token
- Direct `nbe_list_devices` calls to Google Nova
- Fresh GCM/FCM registration on the iPhone for location replies
- Foreground MCS connection to Google push infrastructure
- `nbe_execute_action` Locate requests
- WebPush `aesgcm` decoding
- Standard Find Hub location decryption (own reports plus SECP160R1/HKDF/AES-EAX crowdsourced reports)
- Local rename/hide with confirmation, restore hidden trackers, and handoff to Google's official Find Hub UI for permanent account removal
- GitHub Actions unsigned IPA build

## Authentication

Google Find Hub does not expose a documented public third-party iOS authentication API. This build intentionally does **not** scrape Google passwords or browser session cookies. Import the `Auth/secrets.json` produced by GoogleFindMyTools after its normal authentication/key-unlock flow. At minimum the app needs:

- `username`
- `aas_token`
- the original Android ID inside `fcm_credentials.gcm.android_id`
- `shared_key` (or `owner_key`)

The app then performs the remaining token exchange and tracker requests locally on the iPhone. Your Google password is never requested by this app.

## Build

1. `brew install xcodegen`
2. `xcodegen generate`
3. Open `FMDNHub.xcodeproj`
4. Select your Apple Development team if you want to install directly from Xcode.

GitHub Actions builds `FindHub-unsigned.ipa`. An unsigned IPA must still be signed before installation on a normal iPhone.

## Compatibility

Google's private Find Hub endpoints can change without notice. The current implementation targets the standard SECP160R1 tracker format used by GoogleFindMyTools. P-256/32-byte advertisement variants require additional crypto support.

## Credits

GPL-3.0. Protocol behavior and protobuf layouts are based on GoogleFindMyTools by Leon Böttger. WebPush legacy `aesgcm` key derivation follows the public `http_ece` implementation. See `THIRD_PARTY_NOTICES.md`.
