# Changelog

Alle Änderungen aus diesem Review-Durchgang. Details und Hintergründe stehen
in [`docs/SECURITY.md`](docs/SECURITY.md) und [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Sicherheit

- **Speicher-DoS behoben**: Die deklarierte Payload-Länge im Frame-Header
  wird jetzt gegen ein Maximum (`MAX_PAYLOAD_SIZE = 512` Byte) geprüft,
  *bevor* dafür ein Buffer alloziert wird. Vorher konnte ein Angreifer über
  ein manipuliertes Längenfeld beliebig große Speicherallokationen
  erzwingen. (`src/protocol/frame.rs`, `src/transport/tcp.rs`)
- **Replay-Schutz überlebt jetzt Reconnects**: Der `ReplayGuard` liegt nicht
  mehr pro TCP-Verbindung, sondern einmal geteilt (hinter einem `Mutex`) im
  `GatewayState`, keyed pro `device_id`. Vorher wurde die Sequenznummer-
  Historie bei jedem Reconnect (z. B. nach WiFi-Aussetzer) gelöscht, was
  kurz danach ein Replay-Fenster wieder geöffnet hätte.
  (`src/transport/tcp.rs`, `src/main.rs`)
- **Geräte-Whitelist ergänzt**: Neues Modul `src/protocol/registry.rs`.
  Über `SECUREPIPE_ALLOWED_DEVICES` lässt sich festlegen, welche
  `device_id`s die Gateway überhaupt akzeptiert. Ohne gesetzte Variable
  bleibt das Verhalten wie bisher (alle Geräte werden akzeptiert), damit
  ein einzelnes frisch geflashtes ESP32 ohne weitere Konfiguration
  funktioniert.

## Bugfix (beim Testen gefunden, unabhängig von den obigen Punkten)

- **`decrypt_payload` gab zu viele Bytes zurück**: Der entschlüsselte Buffer
  wurde nicht auf die tatsächliche Klartextlänge gekürzt, sondern enthielt
  noch die (jetzt bedeutungslosen) Auth-Tag-Bytes am Ende. Ist in der Praxis
  nie aufgefallen, weil `SensorPayload::parse` ohnehin nur die ersten 8 Byte
  liest - ein bestehender Unit-Test (`encrypt_then_decrypt_roundtrip`) hat es
  aber aufgedeckt. Gefixt in `src/crypto/aes_gcm.rs`.

## Konfiguration statt Hardcoding

- **Rust-Gateway**: `SECUREPIPE_TCP_BIND` und `SECUREPIPE_HTTP_BIND` als
  Umgebungsvariablen statt hartkodierter Konstanten in `main.rs`. Derselbe
  Binary läuft damit unverändert auf dem eigenen Rechner oder z. B. einem
  Raspberry Pi.
- **ESP32-Firmware**: WLAN-Zugangsdaten, Gateway-Host/-Port und Device-ID
  werden nicht mehr einkompiliert, sondern über ein WiFiManager-Captive-
  Portal zur Laufzeit eingegeben und in Flash (NVS) gespeichert. Ein
  Wechsel des Zielsystems (eigener Rechner ↔ Raspberry Pi) erfordert damit
  kein Neuflashen mehr. Siehe `arduino/esp32_sender/esp32_sender.ino` und
  `docs/CONFIGURATION.md`.

## Tests

- Neuer Unit-Test für die Payload-Größenprüfung
  (`parse_rejects_oversized_payload_len`).
- Neue Testsuite für die Geräte-Whitelist (`src/protocol/registry.rs`,
  6 Tests).
- Alle bisherigen 34 Unit- und 12 Integrationstests laufen weiterhin grün
  (46 Tests insgesamt, `cargo test`).
- Manuell gegen einen laufenden Gateway-Prozess verifiziert: Whitelist
  blockiert unbekannte Geräte korrekt, Env-Var-Konfiguration wirkt ohne
  Neukompilieren, Replay-Erkennung funktioniert im Normalbetrieb weiterhin.

## Unverändert (bewusst nicht Teil dieses Durchgangs)

- Der statische, für alle Geräte gemeinsame AES-Schlüssel ist weiterhin
  aktiv (`SessionKey::dev_test_key()`). Per-Device-Keys via ECDH bleiben
  ein offener Punkt für eine spätere Phase - siehe
  `docs/SECURITY.md#offene-punkte`.
- HTTP-API-Authentifizierung und CORS-Einschränkung wurden in diesem
  Durchgang nicht umgesetzt (waren nicht Teil der ausgewählten Features).
