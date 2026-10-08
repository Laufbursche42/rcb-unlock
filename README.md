# Laufbursche RCB unlock

A static web page that talks to RCB e-scooters over Web Bluetooth. Connect, read the data points the scooter reports and - straight from the browser - write Tuya control settings such as the headlight, LED, cruise, zero-start, unit, auto-unlock, move-alarm, find and boost. Nothing to install: no app store, no signing, no developer account. It runs in **Bluefy** on iOS and in **Chrome** or **Edge** on Android or desktop.

> **This is a feasibility study - the transport is proven, the writes depend on values that live outside the app.** RCB ships a white-label Tuya "Smart Life" container (`com.rcb.ytd`), so every scooter speaks the same shared Tuya BLE DP (data-point) protocol; there is no per-model opcode table to recover. The GATT transport is code-proven from the Tuya SDK (service `0xFD50` with write `0x2B11` / notify `0x2B10`, plus the alt profile `0x1910` with `00000001`/`00000002`-...-`07D0`), and the DP engine itself (varint GATT split, AES-128/ECB, CRC-16/MODBUS, MD5 key derivation) is the standard, documented Tuya protocol - the page self-tests it against known vectors on load. What is **not** in the app package, and therefore device- or cloud-side and never invented here: the numeric `dpId`s (Tuya cloud SchemaBean), the per-device `localKey` (your Tuya account), and the exact encrypted frame bytes (native `libBleLib.so`). You supply the session key (`secretKey5 = MD5(localKey || srand)`) and a `{code:dpId}` schema; every write is gated behind both and the risky ones are confirm-boxed. Error-free operation is not promised and there is no warranty of any kind. Whatever you do with it, you do at your own risk - read the [Legal](#legal) section before you connect a scooter.

**Open the web app: [laufbursche42.github.io/rcb-unlock](https://laufbursche42.github.io/rcb-unlock/)**

Or run it yourself, no build step and no dependencies: clone the repo and serve the folder over a local HTTP server. Opening `index.html` directly as a `file://` URL will not work, the page fetches its own documents and browsers block that over `file://`.

```
git clone https://github.com/Laufbursche42/rcb-unlock.git
cd rcb-unlock
python -m http.server 8000
```

Any static server works. With Node installed, this does the same job:

```
npx serve .
```

Then open the printed address in a browser that supports Web Bluetooth.

**Guide: [Deutsch](GUIDE.de.md) | [English](GUIDE.en.md)** covers everything step by step, from connecting to the first DP write.

## What it does

- **Keys and session** - derive the Tuya session key `secretKey5 = MD5(localKey || srand)` locally from a localKey (Tuya account) and an srand (pairing reply). Optional: analyze a btsnoop capture fully locally to surface srand and dpId candidates.
- **Device schema** - paste a `{code:dpId}` map so the page knows which numeric dpId each Tuya code writes.
- **Live values** - a tile grid of the control codes the scooter reports back over the DP channel.
- **Settings** - the nine proven Tuya control codes as write rows, each gated behind schema + session.
- **Expert** - build and send a raw DP frame from dpId, type, value and protocol version (preview or live).
- **Shortcut** - a home-screen link that opens the page and tries to connect.

## Protocol (proven vs device-side)

- **Proven (app_side):** GATT transport - primary Tuya service `0xFD50` (write `0x2B11`, notify `0x2B10`, CCCD `0x2902`) and the alt SIG profile `0x1910` (write `00000001`-, notify `00000002`-...-`07D0`). Control surface - the Tuya DP codes `auto_unlock`, `headlight_switch`, `unit_set`, `move_alarm`, `cruise_switch`, `zero_start`, `switch_led`, `search`, `boost` (from `od_dsl_dpc.json`).
- **Standard Tuya (documented, self-tested):** the DP frame engine - `00`-indexed varint GATT reassembly, a `seq|cmd|flag|data|crc16` inner frame, AES-128/ECB over the whole inner frame, `secretKey5 = MD5(localKey || srand)`.
- **Device/cloud-side (UNKNOWN, user-supplied, never invented):** numeric dpIds + value ranges (Tuya cloud SchemaBean), the per-device localKey (Tuya account), the srand offset in the pairing reply, and the exact encrypted per-model byte layout (native `libBleLib.so` / `libthing_security`). An on-device HCI sniff or the per-product cloud panel is needed to pin these.

## Honesty

Device-untested by design - you test on your own scooter, which is exactly the point of a public tool. An echo in the log means the scooter **accepted** the frame; only a value changing in the live tiles proves it actually took effect. Where a value cannot be proven from the app, the page gates it and says so rather than guessing.

## Legal

License: PolyForm Noncommercial, see [License](LICENSE.md). Privacy: nothing leaves your device, see [Privacy](PRIVACY.md). Trademarks: RCB and Tuya are trademarks of their respective owners, this project is independent, see [Trademarks](TRADEMARKS.md).

Source: https://github.com/Laufbursche42/rcb-unlock
