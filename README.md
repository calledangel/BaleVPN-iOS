# BaleVPN for iOS

An unofficial iPhone client for [BaleVPN](https://github.com/kookoo1sabzy/BaleVPN) by Kookoo Sabzy. It exposes a SOCKS5 proxy on `127.0.0.1` for apps that support one. The client uses a paired QUIC identity and checks HTTPS through the proxy before showing the connection as ready on iOS 17 and later.

## Build on a Mac

You need Xcode with an iOS SDK that supports `BGContinuedProcessingTask`, Python 3.12 or later, Go 1.26, Rust and rustup.

```sh
python3 build_core.py
./build_flow_core.sh
open BaleVPN.xcodeproj
```

In Xcode, select your signing team and set a unique bundle identifier in `App/App.xcconfig`. Choose a physical iPhone and click **Run**. Enable Developer Mode on the phone if iOS asks. The app targets iOS 16 and later. The background measurement task requires iOS 26 and remains subject to iOS scheduling.

## Pair with your own relay

Generate a pair of profiles outside the checkout with `python3 make_quic_profiles.py /path/to/new/private-folder`. Import `iphone.json` in the iPhone app. A compatible BaleVPN relay built from the upstream source staged by `build_core.py --stage-only` must use the matching `server.json` through `BALEVPN_QUIC_TLS_PROFILE`. The upstream repository documents relay setup.

Sign in on the iPhone, enter your relay account's numeric ID, and start the proxy. Use the displayed loopback address and port in your SOCKS5 client. The traffic check tries a second HTTPS endpoint if the first fails. With automatic reconnection enabled, the app retries a temporary interruption up to two times.

Each pairing file contains a private key. Keep both files outside the repository and import only the iPhone profile on the phone. Mutual authentication protects the QUIC session between the paired devices. The messaging service can still observe call metadata.

## Connection status and troubleshooting

- **Waiting for the call or room** means the relay has not joined the session. Check the relay account and whether the relay process is running.
- **Checking traffic** means the loopback port is open and the app is testing an HTTPS request through it. On iOS 17 and later the connection is shown as ready once a probe succeeds.
- **Port changed** means the requested port was busy and the app picked another one. Update the port in the app that uses SOCKS5.
- **SSH host key mismatch** means the configured key differs from the server response. Check the key using your own server console before updating the profile.

The optional Cloudflare mode uses an imported VLESS WebSocket TLS profile. DNSTT uses an imported tunnel and SSH profile with DNS settings chosen on the device. To report a problem, share the iOS version, method and error stage. Keep connection links, account IDs and exported profiles out of public issues.

## مجوز و اعتبار

این نسخهٔ غیررسمی برای آیفون است و بر پایهٔ پروژهٔ [BaleVPN](https://github.com/kookoo1sabzy/BaleVPN) نوشتهٔ Kookoo Sabzy ساخته می‌شود. متن مجوز MIT و نام نویسنده در [LICENSE](LICENSE) آمده است.

این پروژه با پیام‌رسان بله وابستگی رسمی ندارد. برای ساخت، از تیم امضای خودت در Xcode استفاده کن. پروفایل‌های جفت‌سازی را خصوصی نگه دار. برای روش‌های Cloudflare و DNSTT، تنظیمات سرویس خودت را در اپ وارد کن.
