# Proton VPN Android – Port Forwarding patch

Adds NAT-PMP port forwarding on P2P servers, a **Settings → Features → Port forwarding** screen, and a
**traffic + port forwarding security check**.

Base: `ProtonVPN/android-app` commit `416d2ee` (17 Nov 2026). Paid Proton plan required (same as desktop).

## Apply and build

```sh
git clone https://github.com/ProtonVPN/android-app.git
cd android-app
# (already applied in this repo)
./gradlew testProductionVanillaOpenSourceDebugUnitTest --tests '*NatPmpTests*'
./gradlew assembleProductionVanillaOpenSourceDebug
# APK: app/build/outputs/apk/productionVanillaOpenSource/debug/
```

The build is signed with your own key, so uninstall the Play Store Proton VPN before installing it.

## How it works

1. With the setting on, a P2P server and strict NAT, the app sends the server the `port-forwarding`
   connection feature (the same key the Windows app uses).
2. It asks the in-tunnel gateway `10.2.0.1` for a TCP + UDP port over NAT-PMP, then renews it every 30 s
   (60 s lease).
3. The port is shown in Settings → Port forwarding with a Copy button. Enter it in your torrent app and
   turn off that app's UPnP/NAT-PMP.

## Hardening built in

| Risk | Mitigation |
|---|---|
| Port request leaking to the Wi-Fi/LAN, or a LAN device answering it | UDP socket bound to this app's own VPN network (VPN transport + owner UID + Proton tunnel address) and connected to 10.2.0.1. No fallback: if the tunnel isn't found, nothing is sent. |
| Spoofed or malformed NAT-PMP replies | Source IP/port must equal 10.2.0.1:5351; exact length, version, opcode and result checks; internal == external port; port ≥ 1024; lifetime 1–7200 s. TCP and UDP must get the same port. |
| Stale port after disconnect or server switch | The mapping is tied to one connection ID; any change cancels it and clears the port from the UI. |
| Hole left open after turning it off | The mapping is deleted actively (lifetime 0), and the server feature flag is set back to false. |
| Moderate NAT widening exposure | Port forwarding only takes effect with strict NAT; turning it on switches NAT back to strict. |
| Requests from non-P2P servers / free plan | `port-forwarding` is sent only for P2P servers on paid plans; it's false everywhere else. |
| Retry storms / hangs | Bounded retries (max ~7.75 s per request), exponential backoff up to 60 s. |
| Port or IP leaking to other apps or logs | No broadcasts, no exported components; clipboard marked sensitive (Android 13+); public IP never logged. |

## Security check (Settings → Port forwarding → Check traffic and port forwarding)

**Traffic:** VPN connected · tunnel is the default network · IPv4 routed into the tunnel · IPv6 leak
protection · DNS inside the tunnel · Private DNS note · exit IP confirmed by the server · Proton API sees
the exit IP · kill switch (Always-on + Block connections without VPN) · split tunneling · LAN direct
connections.

**Port forwarding:** P2P server · strict NAT · NAT-PMP routed only through the tunnel · port active · lease
fresh · gateway public IP matches the exit IP · spoofed replies seen · an app is listening on the port ·
exposure reminder · battery optimization (background renewal).

Fix buttons are shown where possible: open VPN settings, open battery settings, switch to strict NAT,
reconnect. Only Proton servers are contacted; no third-party IP or port checkers are used.

## Limits

- Only the NAT-PMP protocol code was compiled and unit tested here (22/22 pass). The full app wasn't built,
  because Google's Android SDK and Maven were blocked in this environment. Run the Gradle commands above and
  fix any compile errors they report.
- Android can't firewall inbound traffic per app without root. Any app listening on the forwarded port is
  reachable through it, so use the port only for your torrent app.
- The port changes when you reconnect (a Proton server-side behavior).
