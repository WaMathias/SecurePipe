# SecurePipe

Verschluesseltes IoT-Sensorprotokoll mit Echtzeit-Dashboard. Ein
ESP32-C6 liest einen **TCRT5000-IR-Naeherungssensor** (Objekterkennung),
verschluesselt den Messwert mit **AES-256-GCM** und sendet ihn sicher per
TCP an ein **Rust-Gateway**, das die Daten auf einem Live-Dashboard anzeigt.

---

## Architektur

```
+--------------+   GPIO    +----------+  TCP + AES-256-GCM  +--------------+  HTTP/SSE  +----------+
|  TCRT5000     |--------->|  ESP32-C6 |---------------------->| Rust Gateway |---------->|Dashboard |
| (IR-Reflexion)|  DO=GPIO22          |                       |              |           | (Web UI) |
+--------------+           +----------+                       +--------------+           +----------+
```

**Komponenten:**
- **TCRT5000** - IR-Reflexions-/Naeherungssensor (Objekt vor dem Sensor erkannt/nicht erkannt)
- **ESP32-C6** - Liest den Sensor, verschluesselt die Daten, sendet per TCP
- **Rust Gateway** - Empfaengt TCP, entschluesselt, erkennt Replay-Attacken, stellt das Dashboard bereit
- **Dashboard** - Live-Anzeige der Sensordaten und Sicherheitsereignisse
- **Arduino** _(optional, UART-Modus)_ - Alternativ als Sensor-Leser ueber UART an den ESP32

---

## Voraussetzungen

### Rust Gateway
- [Rust Toolchain](https://rustup.rs/) (stable)
- Keine externen System-Abhaengigkeiten

### ESP32 + Sensor (Hardware-Modus)
- Arduino CLI oder Arduino IDE
- ESP32-C6 Board (funktioniert ebenso mit anderen ESP32-Varianten)
- TCRT5000 IR-Reflexions-/Naeherungssensor (MH-Sensor-Series-Board)
- USB-Datenkabel (CH343/UART-Port des ESP32-C6)
- _(Optional)_ Arduino Uno fuer den UART-Modus

> **Hinweis zum ESP32-C6-Port:** Das Board besitzt zwei USB-C-Anschluesse.
> Fuer Flashen und Seriell-Monitor wird der **UART/CH343-Port** verwendet
> (nicht der native USB-JTAG/`ESP32C6`-Port).

### Benoetigte Arduino-Libraries

**ESP32:**
- [WiFiManager by tzapu](https://github.com/tzapu/WiFiManager) - Captive Portal fuer Runtime-Konfiguration
- mbedTLS - bereits im ESP32-Framework enthalten
- Preferences - bereits im ESP32-Framework enthalten

**Arduino (nur im UART-Modus):**
- Adafruit SSD1306
- Adafruit GFX Library

---

## Gateway starten

### Einfach starten

```bash
cargo run --bin gateway
```

Startet auf den Standard-Ports:
- **TCP:** `0.0.0.0:7777` (empfaengt ESP32-Verbindungen)
- **HTTP:** `0.0.0.0:8080` (Dashboard + API)

Dashboard oeffnen: `http://localhost:8080`

### Mit eigener Konfiguration

```bash
SECUREPIPE_TCP_BIND=0.0.0.0:9000 \
SECUREPIPE_HTTP_BIND=0.0.0.0:3000 \
SECUREPIPE_ALLOWED_DEVICES=0x00000001,0x00000002 \
cargo run --bin gateway
```

### Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `SECUREPIPE_TCP_BIND` | `0.0.0.0:7777` | Adresse/Port fuer ESP32-TCP-Verbindungen |
| `SECUREPIPE_HTTP_BIND` | `0.0.0.0:8080` | Adresse/Port fuer HTTP-Dashboard |
| `SECUREPIPE_ALLOWED_DEVICES` | _(alle)_ | Komma-getrennte Device-IDs (hex mit `0x` oder dezimal). Ohne Setzen: alle Geraete akzeptiert |
| `RUST_LOG` | `info` | Log-Level (`debug` fuer ausfuehrliche Ausgabe) |

---

## Simulator (ohne Hardware testen)

Der Simulator imitiert einen ESP32-Sender. Zwei Terminals benoetigt:

**Terminal 1** - Gateway starten:
```bash
cargo run --bin gateway
```

**Terminal 2** - Simulator starten (erst wenn Gateway laeuft):
```bash
cargo run --bin simulator
```

### Replay-Angriff simulieren

```bash
cargo run --bin simulator replay
```

Sendet 5 legitime Frames, dann einen Replay-Frame (#1). Der Gateway sollte
diesen im Dashboard als Sicherheitsereignis melden.

---

## Hardware-Setup

### Modus 1: UART (Arduino + ESP32)

Der Arduino liest den Sensor und sendet Rohdaten per UART an den ESP32,
der sie verschluesselt und weiterleitet.

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

**Pin-Belegung:**

| Signal | Arduino | ESP32 |
|---|---|---|
| UART TX -> RX | Pin 3 (SoftwareSerial TX) | GPIO 16 (RX2) |
| GND | GND | GND |

**Flash-Reihenfolge:**
1. `arduino/sensor_node/sensor_node.ino` auf Arduino flashen
2. `arduino/esp32_sender/esp32_sender.ino` auf ESP32 flashen
3. ESP32 konfigurieren (siehe [ESP32 Konfiguration](#esp32-konfiguration))
4. ESP32 einschalten -> verbindet sich automatisch mit Gateway

### Modus 2: Direct (nur ESP32, kein Arduino)

Der ESP32-C6 liest den TCRT5000-Sensor direkt ueber seinen digitalen Ausgang
(DO). **Kein Arduino noetig.**

```
+--------------+         +----------------+
|  TCRT5000     |         |   ESP32-C6    |
|              |         |               |
|  VCC ----+------ 3.3V -+ 3V3          |
|  GND ----+------ GND --+ GND          |
|  DO  ----+------ GPIO22 + GPIO22 (DO) |
|  AO (unbenutzt)         |               |
+--------------+         +----------------+
```

**Anschluss (dieses Schulprojekt):**

| Signal | TCRT5000 | ESP32-C6 GPIO |
|---|---|---|
| VCC | VCC | 3V3 |
| GND | GND | GND |
| DO (digital) | DO | GPIO 22 |

Der Analogeingang **AO** kann optional an einen ADC-Pin angeschlossen werden,
um die Intensitaet analog zu messen (in diesem Projekt wird der digitale
Ausgang DO verwendet).

**So richtest du es ein:**
1. ESP32 im Captive Portal konfigurieren
2. **Sensor Mode** auf `direct` setzen
3. TCRT5000 per DO an GPIO 22 anschliessen (VCC/GND an 3V3/GND)
4. ESP32 neustarten

**Achtung:** Der `direct`-Modus wurde fuer den TCRT5000 konfiguriert (liest
den digitalen Ausgang DO). Die im Portal abgefragten TRIG/ECHO-Felder sind
fuer den HC-SR04-Ultraschallsensor gedacht und werden im TCRT5000-Setup
nicht verwendet.

---

## ESP32 Konfiguration

### Ersteinrichtung

1. ESP32 einschalten (oder Factory Reset - siehe unten)
2. WiFi-AP **"SecurePipe-Setup"** oeffnen
3. Verbinden -> Config-Page oeffnet sich automatisch
   _(oder manuell: `192.168.4.1` im Browser aufrufen)_
4. Folgende Felder ausfuellen:

| Feld | Beschreibung | Beispiel |
|---|---|---|
| WiFi | WLAN-Zugangsdaten | MeinWLAN / Passwort123 |
| Gateway Host | IP des Rust-Gateways | `192.168.178.136` |
| Gateway Port | TCP-Port des Gateways | `7777` |
| Device ID | Eindeutige Geraete-ID (8 Hex-Ziffern) | `00000001` |
| Sensor Mode | `uart` oder `direct` | `direct` |
| TRIG Pin | nur fuer HC-SR04 (wird beim TCRT5000 ignoriert) | `5` |
| ECHO Pin | nur fuer HC-SR04 (wird beim TCRT5000 ignoriert) | `18` |

**Fuer den TCRT5000-Naeherungssensor** genuegt es, den Sensor-Mode auf
`direct` zu setzen; der DO-Pin ist fest auf GPIO 22 verdrahtet (im Sketch
als `DIRECT_DO_PIN` definiert).

5. **Save** klicken -> ESP32 startet neu und verbindet sich automatisch

### Config aendern (Factory Reset)

Den **BOOT-Knopf** (GPIO0) am ESP32 **3 Sekunden lang gedrueckt halten**
beim Einschalten. Der ESP32 loescht die gespeicherte Config und oeffnet
das Captive Portal erneut.

**Wann noetig:**
- Gateway-IP hat sich geaendert
- Neues WLAN
- Wechsel zwischen uart/direct Modus
- Device-ID aendern

### Gespeicherte Werte

Die Konfiguration (inkl. Sequence-Number) wird im NVS/Flash gespeichert
und ueberlebt Neustarts. Das Sequence-Number-Persistieren verhindert,
dass Frames nach einem WiFi-Reconnect faelschlich als Replay abgelehnt
werden.

---

## Dashboard

Nach dem Start des Gateways unter `http://localhost:8080` (oder konfigurierter Port) verfuegbar.

**Zeigt an:**
- **Sensordaten** - Live-Werte mit Geraet, Sequenznummer, Zeitstempel. Fuer den
  TCRT5000-Naeherungssensor erscheint **"OBJEKT ERKANNT"** bzw. **"kein Objekt"**
- **Sicherheitsereignisse** - Replay-Erkennung, Auth-Fehler, unbekannte Geraete
- **Verbindungsstatus** - LIVE-Indikator fuer SSE-Verbindung

---

## Verschlüsselung sichtbar gemacht (Demo)

Ein kleines Python-Skript zeigt anschaulich den Unterschied zwischen
unverschluesselten und verschluesselten Frames im echten SecurePipe-Format:

```bash
python3 docs/demo_encryption.py
```

**Ausgabe (gekuerzt):**

| Blickpunkt | Bytes | Lesbar? |
|---|---|---|
| Klartext-Payload (ohne AES) | `06 00 00 00 01 00 ...` | ja, sofort "Objekt erkannt, Wert 1" |
| Verschluesselter Payload (AES-256-GCM) | `BF D1 3D 66 FC B5 EA C4 ...` | nein, Zufallsrauschen |

Das Skript nutzt exakt denselben Test-Schluessel und dasselbe Frame-Format
wie ESP32 und Rust-Gateway (`docs/demo_encryption.py`).

---

## Tests

```bash
cargo test
```

**86 Tests** covering:
- AES-256-GCM Verschluesselung/Entschluesselung (Rundlauf, falscher Key, Manipulation)
- Frame-Parsing (Magic Bytes, Version, Groesse, CRC)
- Replay-Schutz (Sequenznummer, Timestamp, Nonce-Cache, Forward-Clock)
- Geraete-Whitelist (Env-Variablen, hex/dezimal)
- Integrationstests (kompletter Pipeline: bauen -> verschluesseln -> parsen -> verifizieren -> entschluesseln)

---

## Sicherheit

Kurzuebersicht - Details in [`docs/SECURITY.md`](docs/SECURITY.md).

**Vorhandene Schutzmechanismen:**
- AES-256-GCM (authenticated encryption) mit Header als AAD
- Drei-Wege-Replay-Schutz: Sequenznummer, Timestamp, Nonce-Cache
- Auth-Tag-Pruefung vor jeder weiteren Verarbeitung
- Speicher-DoS-Schutz (Payload-Laenge wird VOR Allokation geprueft)
- Geräte-Whitelist (Defense-in-Depth)
- Sequence-Number-Persistierung in NVS (Reconnect-sicher)

**Bekannte offene Punkte (Phase 2):**
- Gemeinsamer statischer AES-Schluessel (per-device-keys via ECDH geplant)
- Keine HTTP-Auth auf Dashboard/API
- Kein TCP-Read-Timeout
- Kein Frame-Resync nach Bitfehlern

---

## Konfigurations-Dokumentation

Details zu allen Einstellungen: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)


## KI-Info
Code wurde teilweise mit Unterstützung erstellt und zuletzt mit KI angepasst und verbessert.
