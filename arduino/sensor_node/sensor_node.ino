// ============================================================
// SecurePipe - Arduino Sensor Node
// ============================================================
// Reads distance from HC-SR04 ultrasonic sensor (digital pins),
// displays values on SSD1306 OLED via I2C,
// and sends raw sensor frames to the ESP32 via UART.
//
// Wiring:
//   HC-SR04 VCC  -> Arduino 5V
//   HC-SR04 GND  -> Arduino GND
//   HC-SR04 TRIG -> Arduino Pin 6
//   HC-SR04 ECHO -> Arduino Pin 7
//   OLED SDA     -> Arduino A4  (I2C)
//   OLED SCL     -> Arduino A5  (I2C)
//   ESP32 RX     -> Arduino Pin 3  (SoftwareSerial TX)
//   ESP32 GND    -> Arduino GND
//
// Libraries needed (install via Arduino Library Manager):
//   - Adafruit SSD1306
//   - Adafruit GFX Library

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <SoftwareSerial.h>

// ── Pin definitions ──────────────────────────────────────────
#define TRIG_PIN      6
#define ECHO_PIN      7
#define UART_TX_PIN   3
#define UART_RX_PIN   4    // unused but required by SoftwareSerial

// ── OLED (128x64, I2C) ──────────────────────────────────────
#define OLED_WIDTH    128
#define OLED_HEIGHT   64
#define OLED_RESET    -1
#define OLED_ADDRESS  0x3C

// ── HC-SR04 limits ───────────────────────────────────────────
#define DIST_MIN_CM   2     // sensor reliable range: 2–400 cm
#define DIST_MAX_CM   400

// ── SecurePipe raw UART frame ────────────────────────────────
// 10 bytes, matches ESP32 parser exactly:
//   Byte 0    Start         0xAA
//   Byte 1    Sensor type   0x04 = distance
//   Byte 2-5  Value (int32) value * 100, big-endian (cm * 100)
//   Byte 6    Unit          0x04 = cm
//   Byte 7-8  CRC-16        over bytes 0..6
//   Byte 9    End           0x55
#define FRAME_START       0xAA
#define FRAME_END         0x55
#define FRAME_SIZE        10
#define SENSOR_DISTANCE   0x04
#define UNIT_CM           0x04

// ── Timing ───────────────────────────────────────────────────
#define READ_INTERVAL_MS  500   // measure every 500ms

// ── Objects ──────────────────────────────────────────────────
Adafruit_SSD1306 display(OLED_WIDTH, OLED_HEIGHT, &Wire, OLED_RESET);
SoftwareSerial   espSerial(UART_RX_PIN, UART_TX_PIN);

// ── State ────────────────────────────────────────────────────
uint32_t lastReadTime = 0;
uint32_t frameCount   = 0;
bool     displayReady = false;

// ─────────────────────────────────────────────────────────────

void setup() {
  Serial.begin(115200);
  espSerial.begin(9600);

  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  digitalWrite(TRIG_PIN, LOW);

  if (display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    displayReady = true;
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.println("SecurePipe v1");
    display.println("HC-SR04 Node");
    display.println("------------");
    display.println("Initialisiere...");
    display.display();
  } else {
    Serial.println("OLED init failed - continuing without display");
  }

  delay(1000);
  Serial.println("SecurePipe Arduino HC-SR04 Node ready");
}

// ─────────────────────────────────────────────────────────────

void loop() {
  uint32_t now = millis();
  if (now - lastReadTime >= READ_INTERVAL_MS) {
    lastReadTime = now;
    readAndSend();
  }
}

// ─────────────────────────────────────────────────────────────

void readAndSend() {
  float distCm = measureDistance();

  if (distCm < 0) {
    Serial.println("ERROR: HC-SR04 out of range or no echo");
    showError("Kein Echo!");
    return;
  }

  frameCount++;

  // Fixed-point: store as cm * 100 to keep one decimal place
  // e.g. 23.4 cm -> 2340
  int32_t distRaw = (int32_t)(distCm * 100.0f);

  Serial.print("Frame #");
  Serial.print(frameCount);
  Serial.print(" | Distanz: ");
  Serial.print(distCm, 1);
  Serial.println(" cm");

  showDistance(distCm, frameCount);
  sendFrame(SENSOR_DISTANCE, distRaw, UNIT_CM);
}

// ─────────────────────────────────────────────────────────────
// HC-SR04 measurement
// Returns distance in cm, or -1.0 on error
// ─────────────────────────────────────────────────────────────

float measureDistance() {
  // Ensure TRIG is low before pulse
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);

  // Send 10µs trigger pulse
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  // Measure echo pulse duration (timeout: 30ms = ~5m range)
  long duration = pulseIn(ECHO_PIN, HIGH, 30000UL);

  if (duration == 0) return -1.0f;

  // Convert to cm: sound travels at ~343 m/s
  // distance = (duration_us / 2) / 29.1 ≈ duration / 58
  float distCm = duration / 58.0f;

  if (distCm < DIST_MIN_CM || distCm > DIST_MAX_CM) return -1.0f;

  return distCm;
}

// ─────────────────────────────────────────────────────────────
// Build and send raw UART frame to ESP32
// ─────────────────────────────────────────────────────────────

void sendFrame(uint8_t sensorType, int32_t valueRaw, uint8_t unit) {
  uint8_t frame[FRAME_SIZE];

  frame[0] = FRAME_START;
  frame[1] = sensorType;
  frame[2] = (valueRaw >> 24) & 0xFF;
  frame[3] = (valueRaw >> 16) & 0xFF;
  frame[4] = (valueRaw >>  8) & 0xFF;
  frame[5] = (valueRaw      ) & 0xFF;
  frame[6] = unit;

  uint16_t crc = crc16(frame, 7);
  frame[7] = (crc >> 8) & 0xFF;
  frame[8] = (crc     ) & 0xFF;
  frame[9] = FRAME_END;

  espSerial.write(frame, FRAME_SIZE);
}

// ─────────────────────────────────────────────────────────────
// CRC-16/CCITT — must match ESP32 and Rust exactly
// ─────────────────────────────────────────────────────────────

uint16_t crc16(uint8_t* data, uint8_t length) {
  uint16_t crc = 0xFFFF;
  for (uint8_t i = 0; i < length; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (uint8_t j = 0; j < 8; j++) {
      crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
    }
  }
  return crc;
}

// ─────────────────────────────────────────────────────────────
// OLED helpers
// ─────────────────────────────────────────────────────────────

void showDistance(float distCm, uint32_t frameNr) {
  if (!displayReady) return;

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);

  // Header
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.print("SecurePipe  #");
  display.println(frameNr);
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);

  // Distance — large
  display.setTextSize(2);
  display.setCursor(0, 16);
  display.print(distCm, 1);
  display.println(" cm");

  // Visual bar (maps 0–200cm to 0–128px)
  int barWidth = constrain((int)(distCm / 200.0f * 118.0f), 0, 118);
  display.drawRect(5, 42, 118, 10, SSD1306_WHITE);
  display.fillRect(5, 42, barWidth, 10, SSD1306_WHITE);

  // Footer
  display.setTextSize(1);
  display.setCursor(0, 56);
  display.print("-> ESP32 via UART");

  display.display();
}

void showError(const char* msg) {
  if (!displayReady) return;
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("! FEHLER !");
  display.println(msg);
  display.display();
}
