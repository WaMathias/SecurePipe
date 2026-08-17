# Konfiguration & Deployment

Dieses Dokument erklärt, wie Gateway und ESP32 konfiguriert werden, und wie
du zwischen den zwei üblichen Aufbauten wechselst:

- **Direkt**: ein ESP32 mit einem Sensor sendet direkt an den Rust-Gateway,
  der auf deinem eigenen Rechner läuft.
- **Über Raspberry Pi**: derselbe ESP32 sendet stattdessen an einen
  Raspberry Pi, auf dem der (identische) Rust-Gateway läuft - z. B. weil der
  Pi dauerhaft läuft und dein Rechner nicht.

Für beide Aufbauten reicht **ein einziges Gerät** (ein ESP32 + ein Sensor) -
`device_id` existiert nur, damit das Protokoll bei Bedarf mehrere Geräte
unterscheiden kann, nicht weil mehrere Geräte nötig wären.

## Rust-Gateway

Alle drei folgenden Variablen sind optional - ohne sie verhält sich der
Gateway wie bisher (Bind auf `0.0.0.0`, keine Geräte-Einschränkung).

| Variable | Default | Bedeutung |
|---|---|---|
| `SECUREPIPE_TCP_BIND` | `0.0.0.0:7777` | Adresse, auf der der Gateway auf ESP32-Verbindungen lauscht |
| `SECUREPIPE_HTTP_BIND` | `0.0.0.0:8080` | Adresse für das Web-Dashboard |
| `SECUREPIPE_ALLOWED_DEVICES` | *(nicht gesetzt = alle erlaubt)* | Kommagetrennte Liste erlaubter `device_id`s, hex (`0x...`) oder dezimal |

Beispiele:

```bash
# Standardbetrieb (wie bisher), lokal auf dem eigenen Rechner
cargo run --bin gateway

# Auf dem Raspberry Pi, nur auf der LAN-Schnittstelle lauschen
SECUREPIPE_TCP_BIND=0.0.0.0:7777 \
SECUREPIPE_HTTP_BIND=0.0.0.0:8080 \
cargo run --bin gateway

# Nur genau ein bekanntes Gerät akzeptieren
SECUREPIPE_ALLOWED_DEVICES=0x00000001 cargo run --bin gateway

# Mehrere Geräte
SECUREPIPE_ALLOWED_DEVICES=0x00000001,0x00000002,42 cargo run --bin gateway
```

Das Binary selbst ist identisch, egal ob es auf deinem Rechner oder einem
Raspberry Pi läuft (Rust kompiliert für ARM genauso wie für x86) - der
einzige Unterschied ist, wohin das ESP32 seine Frames schickt (siehe unten).

## ESP32-Firmware: Captive-Portal statt Neuflashen

WLAN-Zugangsdaten, Gateway-Host/-Port und Device-ID stehen nicht mehr als
`#define` im Code, sondern werden einmalig über eine kleine Weboberfläche
eingegeben und danach im Flash-Speicher (NVS) des ESP32 gespeichert.

### Erstes Setup

1. ESP32 mit Strom versorgen (Firmware muss einmal geflasht sein, siehe
   unten für benötigte Libraries).
2. Der ESP32 öffnet einen eigenen WLAN-Access-Point namens
   **`SecurePipe-Setup`**. Mit Handy oder Laptop damit verbinden.
3. Es sollte sich automatisch eine Konfigurationsseite öffnen (Captive
   Portal). Falls nicht: `192.168.4.1` im Browser öffnen.
4. Dort: eigenes WLAN auswählen + Passwort eingeben, dazu die drei
   zusätzlichen Felder:
   - **Gateway Host / IP** - die IP deines Rechners oder Raspberry Pis
   - **Gateway Port** - Standard `7777`
   - **Device ID** - 8 Hex-Ziffern, z. B. `00000001`
5. Speichern. Der ESP32 verbindet sich, merkt sich alles und sendet ab
   jetzt an das eingetragene Ziel.

### Von "eigener Rechner" auf "Raspberry Pi" wechseln

Kein Neuflashen nötig:

1. BOOT-Taste (GPIO0) beim/nach dem Einschalten **3 Sekunden gedrückt
   halten** - das löscht die gespeicherte Konfiguration und öffnet wieder
   das Setup-Portal.
2. Wie oben neu verbinden, diesmal die IP des Raspberry Pi eintragen.

### Danach

Bei jedem weiteren Neustart verbindet sich der ESP32 automatisch mit den
gespeicherten Werten - kein Portal, kein manueller Schritt mehr, genau wie
vorher mit den hartkodierten `#define`s, nur eben änderbar ohne Neuflashen.

### Benötigte Arduino-Libraries

Zusätzlich zum bisherigen Setup (mbedTLS ist im ESP32-Arduino-Core
enthalten):

- **WiFiManager** von tzapu - über den Arduino Library Manager installieren
  (Suche nach "WiFiManager", Autor "tzapu"), oder
  https://github.com/tzapu/WiFiManager
- **Preferences** - im ESP32-Arduino-Core enthalten, keine Installation
  nötig.

### Was sich am Wiring/Sensor-Teil NICHT ändert

Die Arduino-Sensor-Node (`arduino/sensor_node/sensor_node.ino`) und die
UART-Verbindung zwischen Arduino und ESP32 sind von alldem unberührt - die
Änderungen betreffen ausschließlich, wie das ESP32 sein WLAN und sein
Sendeziel konfiguriert bekommt.
