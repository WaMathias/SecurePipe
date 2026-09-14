# SecurePipe

Encrypted IoT sensor protocol with real-time dashboard. An
ESP32-C6 reads a **TCRT5000 IR proximity sensor** (object detection),
encrypts the reading with **AES-256-GCM** and sends it securely over
TCP to a **Rust gateway**, which displays the data on a live dashboard.

---

## Architecture

```
+--------------+   GPIO    +----------+  TCP + AES-256-GCM  +--------------+  HTTP/SSE  +----------+
|  TCRT5000     |--------->|  ESP32-C6 |---------------------->| Rust Gateway |---------->|Dashboard |
| (IR-Reflexion)|  DO=GPIO22          |                       |              |           | (Web UI) |
+--------------+           +----------+                       +--------------+           +----------+
```

**Components:**
- **TCRT5000** - IR reflection/proximity sensor (object in front of the sensor detected/not detected)
- **ESP32-C6** - Reads the sensor, encrypts the data, sends it over TCP
- **Rust Gateway** - Receives TCP, decrypts, detects replay attacks, serves the dashboard
- **Dashboard** - Live display of sensor data and security events
- **Arduino** _(optional, UART mode)_ - Alternatively reads the sensor over UART and feeds the ESP32

---

## Prerequisites

### Rust Gateway
- [Rust Toolchain](https://rustup.rs/) (stable)
- No external system dependencies

### ESP32 + Sensor (hardware mode)
- Arduino CLI or Arduino IDE
- ESP32-C6 board (works with other ESP32 variants as well)
- TCRT5000 IR reflection/proximity sensor (MH-Sensor-Series board)
- USB data cable (CH343/UART port of the ESP32-C6)
- _(Optional)_ Arduino Uno for the UART mode

> **Note about the ESP32-C6 port:** The board has two USB-C connectors.
> For flashing and the serial monitor, use the **UART/CH343 port**
> (not the native USB-JTAG/`ESP32C6` port).

### Required Arduino Libraries

**ESP32:**
- [WiFiManager by tzapu](https://github.com/tzapu/WiFiManager) - Captive portal for runtime configuration
- mbedTLS - already included in the ESP32 framework
- Preferences - already included in the ESP32 framework

**Arduino (UART mode only):**
- Adafruit SSD1306
- Adafruit GFX Library

---

## Starting the gateway

### Start simply

```bash
cargo run --bin gateway
```

Starts on the default ports:
- **TCP:** `0.0.0.0:7777` (receives ESP32 connections)
- **HTTP:** `0.0.0.0:8080` (dashboard + API)

Open the dashboard: `http://localhost:8080`

### With custom configuration

```bash
SECUREPIPE_TCP_BIND=0.0.0.0:9000 \
SECUREPIPE_HTTP_BIND=0.0.0.0:3000 \
SECUREPIPE_ALLOWED_DEVICES=0x00000001,0x00000002 \
cargo run --bin gateway
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECUREPIPE_TCP_BIND` | `0.0.0.0:7777` | Address/port for ESP32 TCP connections |
| `SECUREPIPE_HTTP_BIND` | `0.0.0.0:8080` | Address/port for the HTTP dashboard |
| `SECUREPIPE_ALLOWED_DEVICES` | _(all)_ | Comma-separated device IDs (hex with `0x` or decimal). If unset: all devices accepted |
| `RUST_LOG` | `info` | Log level (`debug` for verbose output) |

---

## Simulator (test without hardware)

The simulator imitates an ESP32 sender. Two terminals needed:

**Terminal 1** - start the gateway:
```bash
cargo run --bin gateway
```

**Terminal 2** - start the simulator (only after the gateway is running):
```bash
cargo run --bin simulator
```

### Simulate a replay attack

```bash
cargo run --bin simulator replay
```

Sends 5 legitimate frames, then a replay frame (#1). The gateway should
report this in the dashboard as a security event.

---

## Hardware setup

### Mode 1: UART (Arduino + ESP32)

The Arduino reads the sensor and sends raw data over UART to the ESP32,
which encrypts it and forwards it.

```
+-----------+         +----------+
|  HC-SR04  |         |  Arduino |
|           |         |          |
|  VCC -----+---- 5V -+ VCC      |
|  GND -----+--- GND -+ GND      |
|  TRIG ----+-- Pin 6 + TRIG     |
|  ECHO ----+-- Pin 7 + ECHO     |
+-----------+         |          |
                      |  Pin 3 --+-- TX --+
                      |  GND ----+-- GND -+
                      +----------+         |
                                    +------+--------+
                                    |     ESP32      |
                                    |                |
                                    |  GPIO16 (RX2) <+-- Pin 3 (Arduino TX)
                                    |  GND          <+-- GND (Arduino GND)
                                    |                |
                                    |  Gateway <<<   |
                                    +----------------+
```

**Pin assignment:**

| Signal | Arduino | ESP32 |
|---|---|---|
| UART TX -> RX | Pin 3 (SoftwareSerial TX) | GPIO 16 (RX2) |
| GND | GND | GND |

**Flashing order:**
1. Flash `arduino/sensor_node/sensor_node.ino` onto the Arduino
2. Flash `arduino/esp32_sender/esp32_sender.ino` onto the ESP32
3. Configure the ESP32 (see [ESP32 configuration](#esp32-configuration))
4. Power on the ESP32 -> it connects automatically to the gateway

### Mode 2: Direct (ESP32 only, no Arduino)

The ESP32-C6 reads the TCRT5000 sensor directly via its digital output
(DO). **No Arduino needed.**

```
+--------------+         +----------------+
|  TCRT5000     |         |   ESP32-C6    |
|              |         |               |
|  VCC ----+------ 3.3V -+ 3V3          |
|  GND ----+------ GND --+ GND          |
|  DO  ----+------ GPIO22 + GPIO22 (DO) |
|  AO (unused)            |               |
+--------------+         +----------------+
```

**Connection (this school project):**

| Signal | TCRT5000 | ESP32-C6 GPIO |
|---|---|---|
| VCC | VCC | 3V3 |
| GND | GND | GND |
| DO (digital) | DO | GPIO 22 |

The **AO** analog input can optionally be connected to an ADC pin
to measure the intensity analog-wise (this project uses the digital
output DO).

**How to set it up:**
1. Configure the ESP32 in the captive portal
2. Set **Sensor Mode** to `direct`
3. Connect the TCRT5000 via DO to GPIO 22 (VCC/GND to 3V3/GND)
4. Restart the ESP32

**Caution:** The `direct` mode was configured for the TCRT5000 (reads
the digital output DO). The TRIG/ECHO fields requested in the portal
are meant for the HC-SR04 ultrasonic sensor and are not used in the
TCRT5000 setup.

---

## ESP32 configuration

### Initial setup

1. Power on the ESP32 (or do a factory reset - see below)
2. Open the WiFi AP **"SecurePipe-Setup"**
3. Connect -> the config page opens automatically
   _(or manually: open `192.168.4.1` in the browser)_
4. Fill in the following fields:

| Field | Description | Example |
|---|---|---|
| WiFi | WiFi credentials | MyWiFi / Password123 |
| Gateway Host | IP of the Rust gateway | `192.168.178.136` |
| Gateway Port | TCP port of the gateway | `7777` |
| Device ID | Unique device ID (8 hex digits) | `00000001` |
| Sensor Mode | `uart` or `direct` | `direct` |
| TRIG Pin | only for HC-SR04 (ignored with TCRT5000) | `5` |
| ECHO Pin | only for HC-SR04 (ignored with TCRT5000) | `18` |

**For the TCRT5000 proximity sensor** it suffices to set the sensor mode to
`direct`; the DO pin is fixed on GPIO 22 in the wiring (defined as
`DIRECT_DO_PIN` in the sketch).

5. Click **Save** -> the ESP32 reboots and connects automatically

### Changing the config (factory reset)

**Hold the BOOT button** (GPIO0) on the ESP32 **for 3 seconds**
while powering on. The ESP32 deletes the saved config and reopens
the captive portal.

**When needed:**
- The gateway IP has changed
- New WiFi
- Switching between uart/direct mode
- Changing the device ID

### Saved values

The configuration (including the sequence number) is stored in NVS/flash
and survives reboots. Persisting the sequence number prevents
frames from being wrongly rejected as replays after a WiFi reconnect.

---

## Dashboard

Available after starting the gateway at `http://localhost:8080` (or the configured port).

**Displays:**
- **Sensor data** - live values with device, sequence number, timestamp. For the
  TCRT5000 proximity sensor, **"OBJECT DETECTED"** or **"no object"** is shown
- **Security events** - replay detection, auth errors, unknown devices
- **Connection status** - LIVE indicator for the SSE connection

---

## Encryption made visible (demonstration)

A small Python script shows the difference between
unencrypted and encrypted frames in the real SecurePipe format:

```bash
python3 docs/demo_encryption.py
```

**Output (shortened):**

| Aspect | Bytes | Readable? |
|---|---|---|
| Plaintext payload (without AES) | `06 00 00 00 01 00 ...` | yes, immediately "object detected, value 1" |
| Encrypted payload (AES-256-GCM) | `BF D1 3D 66 FC B5 EA C4 ...` | no, random noise |

The script uses exactly the same test key and the same frame format
as the ESP32 and the Rust gateway (`docs/demo_encryption.py`).

---

## Tests

```bash
cargo test
```

**86 Tests** covering:
- AES-256-GCM encryption/decryption (roundtrip, wrong key, tampering)
- Frame parsing (magic bytes, version, size, CRC)
- Replay protection (sequence number, timestamp, nonce cache, forward clock)
- Device whitelist (env variables, hex/decimal)
- Integration tests (complete pipeline: build -> encrypt -> parse -> verify -> decrypt)

---

## Security

Quick overview - details in [`docs/SECURITY.md`](docs/SECURITY.md).

**Existing protection mechanisms:**
- AES-256-GCM (authenticated encryption) with header as AAD
- Three-way replay protection: sequence number, timestamp, nonce cache
- Auth tag verification before any further processing
- Memory-DoS protection (payload length is checked BEFORE allocation)
- Device whitelist (defense-in-depth)
- Sequence number persistence in NVS (reconnect-safe)

**Known open items (Phase 2):**
- Shared static AES key (per-device keys via ECDH planned)
- No HTTP auth on the dashboard/API
- No TCP read timeout
- No frame resync after bit errors

---

## Configuration documentation

Details on all settings: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)