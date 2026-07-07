# SecurePipe — Testsuite

Diese Testsuite läuft vollständig auf dem Entwicklungsrechner, ganz ohne
Arduino, ESP32 oder Raspberry Pi. Sie prüft die gesamte Protokolllogik
isoliert: Frame-Parsing, AES-GCM-Verschlüsselung, und Replay-Schutz.

## Ausführen

```bash
# Alle Tests (Unit- + Integrationstests)
cargo test

# Nur die Unit-Tests in den einzelnen Modulen
cargo test --lib

# Nur die Integrationstests (vollständiger Frame-Lebenszyklus)
cargo test --test integration

# Mit Ausgabe, auch bei erfolgreichen Tests
cargo test -- --nocapture

# Einen einzelnen Test gezielt ausführen
cargo test replay_attack_is_detected_and_rejected
```

## Was getestet wird

### Unit-Tests (`src/protocol/frame.rs`, `src/protocol/replay.rs`, `src/crypto/aes_gcm.rs`)

Jedes Modul prüft sich selbst isoliert — der CRC-16-Algorithmus gegen einen
bekannten Testvektor, der Frame-Parser gegen kaputte Magic-Bytes und
abgeschnittene Frames, der ReplayGuard gegen wiederholte Sequenznummern und
Nonces, AES-GCM gegen falsche Schlüssel und manipulierte Chiffrate.

### Integrationstests (`tests/integration.rs`)

Hier läuft der **vollständige Pfad** genau so, wie ihn der Rust-Gateway in
Produktion durchläuft: Frame parsen → Auth-Tag verifizieren → Replay prüfen
→ entschlüsseln → Payload parsen. Das ist der eigentliche Beweis, dass das
Protokoll als Ganzes funktioniert — nicht nur seine Einzelteile.

Der wichtigste Test ist `replay_attack_is_detected_and_rejected` — er baut
fünf legitime Frames, lässt sie normal durchlaufen, und spielt dann Frame #1
erneut ein. Das ist exakt das Szenario, das du auch live in der Demo mit
dem Simulator zeigst (`cargo run --bin simulator replay`) — nur hier
automatisiert und reproduzierbar.

## Warum das für die Präsentation wichtig ist

Eine Testsuite, die Angriffe als Testfälle modelliert, ist ein starkes
Argument in der Bewertung: Du zeigst nicht nur, dass das System unter
Normalbedingungen funktioniert, sondern dass du dir die Bedrohungsmodelle
bewusst gemacht und gezielt dagegen getestet hast. Das ist der Unterschied
zwischen „es funktioniert" und „ich kann beweisen, warum es sicher ist".

## Erwartete Laufzeit

Alle Tests zusammen laufen in unter einer Sekunde — es wird keine Hardware,
kein Netzwerk und keine Datenbank angesprochen. Das ist beabsichtigt: Die
Protokoll-Kernlogik ist vollständig von Transport und Persistenz entkoppelt
(siehe die Architektur-Diskussion zu Transport-Agnostizität).
