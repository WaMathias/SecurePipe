# Configuration & Deployment

This document explains how the gateway and the ESP32 are configured, and how
you switch between the two usual setups:

- **Direct**: an ESP32 with a sensor sends directly to the Rust gateway,
  which runs on your own computer.
- **Via Raspberry Pi**: the same ESP32 instead sends to a
  Raspberry Pi, on which the (identical) Rust gateway runs - e.g. because the
  Pi runs permanently and your computer doesn't.

For both setups, **a single device** (an ESP32 + a sensor) is enough -
`device_id` only exists so that the protocol can distinguish between multiple
devices if needed, not because multiple devices are required.

## Rust Gateway

All three of the following variables are optional - without them the gateway
behaves as before (bind to `0.0.0.0`, no device restriction).

| Variable | Default | Meaning |
|---|---|---|
| `SECUREPIPE_TCP_BIND` | `0.0.0.0:7777` | Address on which the gateway listens for ESP32 connections |
| `SECUREPIPE_HTTP_BIND` | `0.0.0.0:8080` | Address for the web dashboard |
| `SECUREPIPE_ALLOWED_DEVICES` | *(not set = all allowed)* | Comma-separated list of allowed `device_id`s, hex (`0x...`) or decimal |

Examples:

```bash
# Standard operation (as before), locally on your own computer
cargo run --bin gateway

# On the Raspberry Pi, listening only on the LAN interface
SECUREPIPE_TCP_BIND=0.0.0.0:7777 \
SECUREPIPE_HTTP_BIND=0.0.0.0:8080 \
cargo run --bin gateway

# Accept only exactly one known device
SECUREPIPE_ALLOWED_DEVICES=0x00000001 cargo run --bin gateway

# Multiple devices
SECUREPIPE_ALLOWED_DEVICES=0x00000001,0x00000002,42 cargo run --bin gateway
```

The binary itself is identical, whether it runs on your computer or a
Raspberry Pi (Rust compiles for ARM just as well as for x86) - the
only difference is where the ESP32 sends its frames (see below).

## ESP32 firmware: captive portal instead of reflashing

WiFi credentials, gateway host/port and device ID are no longer `#define`s
in the code, but are entered once via a small web interface and then stored
in the flash memory (NVS) of the ESP32.

### First setup

1. Power the ESP32 (the firmware must have been flashed once, see
   below for the required libraries).
2. The ESP32 opens its own WiFi access point called
   **`SecurePipe-Setup`**. Connect to it with a phone or laptop.
3. A configuration page should open automatically (captive
   portal). If not: open `192.168.4.1` in the browser.
4. There: select your own WiFi + enter the password, plus the three
   additional fields:
   - **Gateway Host / IP** - the IP of your computer or Raspberry Pi
   - **Gateway Port** - default `7777`
   - **Device ID** - 8 hex digits, e.g. `00000001`
5. Save. The ESP32 connects, remembers everything and starts sending
   to the entered target from now on.

### Switching from "your own computer" to "Raspberry Pi"

No reflashing needed:

1. **Hold the BOOT button** (GPIO0) **for 3 seconds** when/after
   powering on - this deletes the saved configuration and reopens
   the setup portal.
2. Reconnect as above, this time entering the IP of the Raspberry Pi.

### Afterwards

On every subsequent reboot, the ESP32 automatically connects with the
saved values - no portal, no manual step anymore, exactly like
before with the hardcoded `#define`s, only changeable without reflashing.

### Required Arduino libraries

In addition to the previous setup (mbedTLS is included in the
ESP32 Arduino core):

- **WiFiManager** by tzapu - install via the Arduino Library Manager
  (search for "WiFiManager", author "tzapu"), or
  https://github.com/tzapu/WiFiManager
- **Preferences** - included in the ESP32 Arduino core, no installation
  needed.

### What does NOT change on the wiring/sensor side

The Arduino sensor node (`arduino/sensor_node/sensor_node.ino`) and the
UART connection between Arduino and ESP32 are unaffected by all of this - the
changes only concern how the ESP32 gets its WiFi and its
send target configured.