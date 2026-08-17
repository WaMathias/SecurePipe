# Security-Modell von SecurePipe

Dieses Dokument beschreibt, was SecurePipe gegen wen schützt, was in diesem
Review-Durchgang gefixt wurde, und was bewusst noch offen ist.

## Bedrohungsmodell in Kürze

Ein Angreifer sitzt irgendwo zwischen ESP32 und Gateway (gleiches WLAN,
kompromittierter Router, o. ä.) und kann Pakete mitlesen, fälschen,
wiederholt einspielen oder beliebig viele eigene TCP-Verbindungen öffnen.
Er kennt **nicht** den AES-Schlüssel (der wird nur zwischen Firmware und
Gateway geteilt, nie über die Leitung übertragen).

## Bereits vorhandene Schutzmechanismen (unverändert gut)

- **AES-256-GCM (authenticated encryption)**: Payload *und* Header sind
  über AAD geschützt - eine Manipulation an irgendeiner Stelle des Frames
  lässt die Auth-Tag-Prüfung fehlschlagen.
- **Drei-Wege-Replay-Schutz**: aufsteigende Sequenznummer pro Gerät,
  Zeitstempel-Fenster (`MAX_FRAME_AGE_SECS = 30s`), Nonce-Cache.
- **Auth-Tag-Prüfung vor jeder weiteren Verarbeitung**: Es wird nie auf
  unauthentifizierten Daten gearbeitet, bevor der Tag geprüft wurde.

## In diesem Durchgang gefixt

### 1. Speicher-Erschöpfungs-Angriff (Memory-Exhaustion DoS)

**Vorher**: Die Payload-Länge im Frame-Header ist ein vom Angreifer
kontrolliertes, zu diesem Zeitpunkt noch unauthentifiziertes `u32`-Feld.
Der Gateway hat direkt `vec![0u8; payload_len + AUTH_TAG_SIZE]` alloziert -
mit einer präparierten Längenangabe nahe `u32::MAX` wäre das ein Buffer im
Gigabyte-Bereich gewesen, pro einzelnem Frame, ganz ohne gültige
Verschlüsselung.

**Fix**: `MAX_PAYLOAD_SIZE = 512` Byte (großzügiger Puffer über den
tatsächlich benötigten 8 Byte) wird geprüft, *bevor* irgendein Buffer für
die Payload alloziert wird - sowohl direkt beim Lesen vom Socket
(`transport/tcp.rs`) als auch defensiv nochmal in `SecurePipeFrame::parse`
für jeden anderen Aufrufer.

### 2. Replay-Schutz, der Reconnects überlebt

**Vorher**: `ReplayGuard::new()` wurde pro TCP-Verbindung neu erzeugt. Da
ESP32-Geräte über WLAN öfter mal kurz die Verbindung verlieren, hätte jeder
Reconnect die Sequenznummer-Historie und den Nonce-Cache gelöscht - ein
Angreifer, der eine alte, mitgeschnittene Nachricht direkt nach einem
(echten oder erzwungenen) Reconnect einspielt, wäre durchgekommen.

**Fix**: Der `ReplayGuard` liegt jetzt einmal, geteilt über alle
Verbindungen, hinter einem `Mutex` im `GatewayState` - weiterhin intern
`HashMap<device_id, DeviceState>`, also pro Gerät unabhängig, aber über die
gesamte Prozess-Laufzeit hinweg bestehend statt pro Connection.

### 3. Geräte-Whitelist

**Neu**: `SECUREPIPE_ALLOWED_DEVICES` (Env-Var, siehe
[`CONFIGURATION.md`](CONFIGURATION.md)) schränkt ein, welche `device_id`s
überhaupt akzeptiert werden. Geprüft *nach* der Auth-Tag-Verifikation
(nie auf unauthentifizierten Daten reagieren) aber *vor* dem Replay-Check
(ein unbekanntes Gerät bekommt gar nicht erst einen Eintrag im
Replay-Zustand).

Wichtig zu verstehen: Das ist **Defense-in-Depth, keine
Zugriffskontrolle im eigentlichen Sinne**. Da nach wie vor alle Geräte
denselben statischen Schlüssel teilen (siehe unten), kann jeder, der diesen
Schlüssel kennt, auch weiterhin gültig aussehende Frames für eine beliebige
`device_id` erzeugen. Die Whitelist schützt vor falschen/unbekannten
Device-IDs (Tippfehler, nicht provisionierte Testgeräte, Streuverkehr),
nicht vor einem Angreifer, der den Schlüssel bereits hat.

## Unabhängiger Bugfix: `decrypt_payload`

Beim Testen ist aufgefallen, dass `decrypt_payload` (`crypto/aes_gcm.rs`)
den entschlüsselten Buffer nicht auf die tatsächliche Klartextlänge
gekürzt hat - `ring::open_in_place` gibt eine Slice-Referenz mit der
korrekten (kürzeren) Länge zurück, verändert aber nicht die Länge des
übergebenen `Vec` selbst. Der Code hat trotzdem den vollen (längeren)
`Vec` zurückgegeben, der am Ende noch die jetzt bedeutungslosen
Auth-Tag-Bytes enthielt. In der Praxis nie aufgefallen, weil
`SensorPayload::parse` ohnehin nur die ersten 8 Byte liest - aber ein
bestehender Unit-Test (`encrypt_then_decrypt_roundtrip`) hat es beim
Kompilieren mit einer aktuelleren `ring`-Version aufgedeckt. Jetzt behoben.

## Offene Punkte

Bewusst **nicht** Teil dieses Durchgangs, aber weiterhin dokumentierte
bekannte Lücken:

- **Gemeinsamer statischer AES-Schlüssel für alle Geräte**
  (`SessionKey::dev_test_key()`). Das größte verbleibende Sicherheitsrisiko:
  wer den Schlüssel kennt, kann jede beliebige `device_id` fälschen. Geplant
  für eine spätere Phase: ECDH-Schlüsselaustausch beim Verbindungsaufbau,
  ein individueller Schlüssel pro Gerät.
- **Keine Authentifizierung auf der HTTP-Dashboard-API**, dazu
  `CorsLayer::permissive()` - jede Website könnte die Live-Sensordaten und
  Security-Events auslesen. Für ein lokales Demo-Setup unkritisch, für
  einen Betrieb außerhalb des eigenen Netzes nicht.
- **Kein Read-Timeout auf TCP-Verbindungen** - ein Client, der nach dem
  Header nie weiterschickt, blockiert seine Connection-Task unbegrenzt.
- **Kein Resync nach ungültigen Magic-Bytes** - bei echtem Bitfehler auf
  der Leitung kann die Verbindung dauerhaft aus dem Takt geraten, statt
  gezielt nach dem nächsten Frame-Anfang zu suchen.
