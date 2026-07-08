// ============================================================
// SecurePipe - ESP32 Sender Node
// ============================================================
// Receives raw sensor frames from Arduino via UART,
// builds and encrypts SecurePipe frames (AES-256-GCM),
// and sends them to the Rust gateway via TCP.
//
// Wiring:
//   Arduino Pin 3 (TX) -> ESP32 GPIO 16 (RX2)
//   Arduino GND        -> ESP32 GND
//
// Libraries needed (install via Arduino Library Manager):
//   - mbedTLS: built into ESP32 Arduino framework, no install needed
//
// Board: ESP32 Dev Module (or any ESP32 variant)

#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

// ── WiFi credentials ─────────────────────────────────────────
// Change these to your network
#define WIFI_SSID     "YourNetworkName"
#define WIFI_PASSWORD "YourPassword"

// ── Gateway address ──────────────────────────────────────────
// During development: your computer's local IP
// Later: Raspberry Pi IP
#define GATEWAY_HOST  "192.168.1.100"
#define GATEWAY_PORT  7777

// ── UART from Arduino ────────────────────────────────────────
#define UART_RX_PIN   16    // ESP32 RX2 <- Arduino TX
#define UART_BAUD     9600

// ── Device identity ──────────────────────────────────────────
#define DEVICE_ID     0x00000001UL

// ── SecurePipe protocol constants ───────────────────────────
// Must match Rust gateway exactly
#define SP_MAGIC_0    0x53   // 'S'
#define SP_MAGIC_1    0x50   // 'P'
#define SP_VERSION    0x01

#define NONCE_SIZE    12
#define AUTH_TAG_SIZE 16
#define HEADER_SIZE   35
#define PAYLOAD_SIZE  8

// Arduino raw frame (from UART)
#define RAW_FRAME_START  0xAA
#define RAW_FRAME_END    0x55
#define RAW_FRAME_SIZE   10

// Sensor types and units
#define SENSOR_TEMPERATURE  0x01
#define SENSOR_HUMIDITY     0x02
#define UNIT_CELSIUS        0x01
#define UNIT_PERCENT        0x02

// ── MVP: hardcoded test key (32 bytes = AES-256) ─────────────
// MUST match SessionKey::dev_test_key() in Rust exactly
static const uint8_t SESSION_KEY[32] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

// ── State ─────────────────────────────────────────────────────
WiFiClient       tcpClient;
HardwareSerial   arduinoSerial(2);   // UART2

uint32_t         sequenceNr   = 0;
bool             connected    = false;

// mbedTLS RNG context (used for nonce generation)
mbedtls_entropy_context  entropy;
mbedtls_ctr_drbg_context ctrDrbg;

// ─────────────────────────────────────────────────────────────

void setup() {
  Serial.begin(115200);
  arduinoSerial.begin(UART_BAUD, SERIAL_8N1, UART_RX_PIN, -1);

  Serial.println("SecurePipe ESP32 Sender Node");
  Serial.println("Initializing RNG...");

  // Initialize mbedTLS random number generator
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctrDrbg);
  const char* pers = "securepipe_esp32";
  mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
                         (const unsigned char*)pers, strlen(pers));

  connectWiFi();
  connectGateway();
}

void loop() {
  // Reconnect if connection dropped
  if (!tcpClient.connected()) {
    Serial.println("Gateway connection lost - reconnecting...");
    connected = false;
    delay(2000);
    connectGateway();
    return;
  }

  // Check for incoming raw frame from Arduino
  if (arduinoSerial.available() >= RAW_FRAME_SIZE) {
    uint8_t rawFrame[RAW_FRAME_SIZE];
    arduinoSerial.readBytes(rawFrame, RAW_FRAME_SIZE);

    if (validateRawFrame(rawFrame)) {
      processAndSend(rawFrame);
    } else {
      Serial.println("ERROR: Invalid raw frame from Arduino - discarding");
    }
  }
}

// ─────────────────────────────────────────────────────────────
// WiFi connection
// ─────────────────────────────────────────────────────────────

void connectWiFi() {
  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  uint8_t attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\nERROR: WiFi connection failed - restarting");
    ESP.restart();
  }

  Serial.println();
  Serial.print("WiFi connected. IP: ");
  Serial.println(WiFi.localIP());

  // Sync time via NTP - required for valid SecurePipe timestamps
  // The Rust gateway checks timestamps against real Unix time.
  // Without NTP, millis()/1000 would be rejected as "too old".
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("Waiting for NTP sync");
  time_t now = 0;
  uint8_t attempts = 0;
  while (now < 1000000000UL && attempts < 20) {
    delay(500);
    Serial.print(".");
    time(&now);
    attempts++;
  }
  if (now > 1000000000UL) {
    Serial.println(" OK");
  } else {
    Serial.println(" FAILED - timestamps will be wrong");
  }
}

// ─────────────────────────────────────────────────────────────
// TCP connection to Rust gateway
// ─────────────────────────────────────────────────────────────

void connectGateway() {
  Serial.print("Connecting to gateway ");
  Serial.print(GATEWAY_HOST);
  Serial.print(":");
  Serial.println(GATEWAY_PORT);

  uint8_t attempts = 0;
  while (!tcpClient.connect(GATEWAY_HOST, GATEWAY_PORT) && attempts < 10) {
    Serial.print(".");
    delay(1000);
    attempts++;
  }

  if (!tcpClient.connected()) {
    Serial.println("\nERROR: Could not connect to gateway - will retry in loop");
    return;
  }

  Serial.println("Connected to gateway");
  connected = true;
  // Reset sequence number on new connection
  // Each new TCP session = fresh sequence counter
  sequenceNr = 0;
}

// ─────────────────────────────────────────────────────────────
// Validate the raw 10-byte frame from Arduino
// ─────────────────────────────────────────────────────────────

bool validateRawFrame(uint8_t* frame) {
  // Check start and end bytes
  if (frame[0] != RAW_FRAME_START || frame[9] != RAW_FRAME_END) {
    return false;
  }

  // Verify CRC-16 over bytes 0..6
  uint16_t receivedCrc = ((uint16_t)frame[7] << 8) | frame[8];
  uint16_t computedCrc = crc16(frame, 7);

  return receivedCrc == computedCrc;
}

// ─────────────────────────────────────────────────────────────
// Process a validated raw frame: build + encrypt + send
// ─────────────────────────────────────────────────────────────

void processAndSend(uint8_t* rawFrame) {
  uint8_t sensorType = rawFrame[1];
  int32_t valueRaw   = ((int32_t)rawFrame[2] << 24)
                     | ((int32_t)rawFrame[3] << 16)
                     | ((int32_t)rawFrame[4] <<  8)
                     | ((int32_t)rawFrame[5]);
  uint8_t unit       = rawFrame[6];

  sequenceNr++;

  Serial.print("Sending frame #");
  Serial.print(sequenceNr);
  Serial.print(" | type=0x");
  Serial.print(sensorType, HEX);
  Serial.print(" | value=");
  Serial.println(valueRaw);

  // Build unencrypted payload (8 bytes)
  uint8_t payload[PAYLOAD_SIZE];
  buildPayload(payload, sensorType, valueRaw, unit);

  // Generate random nonce (12 bytes)
  uint8_t nonce[NONCE_SIZE];
  generateNonce(nonce);

  // Unix timestamp from NTP-synced clock
  uint64_t timestamp = (uint64_t)time(nullptr);

  // Build header (used as AAD for AES-GCM)
  uint8_t header[HEADER_SIZE];
  buildHeader(header, timestamp, nonce, PAYLOAD_SIZE);

  // Encrypt payload with AES-256-GCM
  uint8_t encryptedPayload[PAYLOAD_SIZE];
  uint8_t authTag[AUTH_TAG_SIZE];

  bool ok = encryptPayload(
    payload, PAYLOAD_SIZE,
    header, HEADER_SIZE,
    nonce,
    encryptedPayload,
    authTag
  );

  if (!ok) {
    Serial.println("ERROR: Encryption failed");
    return;
  }

  // Assemble and send full SecurePipe frame
  sendSecurePipeFrame(header, encryptedPayload, authTag);
}

// ─────────────────────────────────────────────────────────────
// Build the 8-byte unencrypted sensor payload
// ─────────────────────────────────────────────────────────────

void buildPayload(uint8_t* out, uint8_t sensorType, int32_t valueRaw, uint8_t unit) {
  out[0] = sensorType;
  out[1] = (valueRaw >> 24) & 0xFF;
  out[2] = (valueRaw >> 16) & 0xFF;
  out[3] = (valueRaw >>  8) & 0xFF;
  out[4] = (valueRaw      ) & 0xFF;
  out[5] = unit;

  // CRC-16 over first 6 bytes
  uint16_t crc = crc16(out, 6);
  out[6] = (crc >> 8) & 0xFF;
  out[7] = (crc     ) & 0xFF;
}

// ─────────────────────────────────────────────────────────────
// Build the 35-byte SecurePipe header (used as AAD)
// ─────────────────────────────────────────────────────────────

void buildHeader(uint8_t* out, uint64_t timestamp, uint8_t* nonce, uint32_t payloadLen) {
  out[0] = SP_MAGIC_0;
  out[1] = SP_MAGIC_1;
  out[2] = SP_VERSION;

  // Device ID (big-endian)
  out[3] = (DEVICE_ID >> 24) & 0xFF;
  out[4] = (DEVICE_ID >> 16) & 0xFF;
  out[5] = (DEVICE_ID >>  8) & 0xFF;
  out[6] = (DEVICE_ID      ) & 0xFF;

  // Sequence number (big-endian)
  out[7]  = (sequenceNr >> 24) & 0xFF;
  out[8]  = (sequenceNr >> 16) & 0xFF;
  out[9]  = (sequenceNr >>  8) & 0xFF;
  out[10] = (sequenceNr      ) & 0xFF;

  // Timestamp (big-endian, 8 bytes)
  out[11] = (timestamp >> 56) & 0xFF;
  out[12] = (timestamp >> 48) & 0xFF;
  out[13] = (timestamp >> 40) & 0xFF;
  out[14] = (timestamp >> 32) & 0xFF;
  out[15] = (timestamp >> 24) & 0xFF;
  out[16] = (timestamp >> 16) & 0xFF;
  out[17] = (timestamp >>  8) & 0xFF;
  out[18] = (timestamp      ) & 0xFF;

  // Payload length (big-endian, 4 bytes)
  out[19] = (payloadLen >> 24) & 0xFF;
  out[20] = (payloadLen >> 16) & 0xFF;
  out[21] = (payloadLen >>  8) & 0xFF;
  out[22] = (payloadLen      ) & 0xFF;

  // Nonce (12 bytes)
  memcpy(&out[23], nonce, NONCE_SIZE);
}

// ─────────────────────────────────────────────────────────────
// AES-256-GCM encryption via mbedTLS
// ─────────────────────────────────────────────────────────────

bool encryptPayload(
  uint8_t* plaintext,   uint16_t plaintextLen,
  uint8_t* aad,         uint16_t aadLen,
  uint8_t* nonce,
  uint8_t* ciphertext,
  uint8_t* tag
) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                SESSION_KEY, 256);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  ret = mbedtls_gcm_crypt_and_tag(
    &gcm,
    MBEDTLS_GCM_ENCRYPT,
    plaintextLen,         // input length
    nonce, NONCE_SIZE,    // nonce
    aad, aadLen,          // additional authenticated data
    plaintext,            // input
    ciphertext,           // output
    AUTH_TAG_SIZE,        // tag length
    tag                   // output tag
  );

  mbedtls_gcm_free(&gcm);
  return ret == 0;
}

// ─────────────────────────────────────────────────────────────
// Assemble and send the full SecurePipe frame over TCP
// ─────────────────────────────────────────────────────────────

void sendSecurePipeFrame(uint8_t* header, uint8_t* encPayload, uint8_t* authTag) {
  // Total: 35 (header) + 8 (payload) + 16 (tag) = 59 bytes
  uint8_t frame[HEADER_SIZE + PAYLOAD_SIZE + AUTH_TAG_SIZE];

  memcpy(frame,                              header,     HEADER_SIZE);
  memcpy(frame + HEADER_SIZE,                encPayload, PAYLOAD_SIZE);
  memcpy(frame + HEADER_SIZE + PAYLOAD_SIZE, authTag,    AUTH_TAG_SIZE);

  size_t written = tcpClient.write(frame, sizeof(frame));

  if (written != sizeof(frame)) {
    Serial.println("ERROR: TCP write incomplete");
  } else {
    Serial.print("Sent ");
    Serial.print(sizeof(frame));
    Serial.println(" bytes to gateway");
  }
}

// ─────────────────────────────────────────────────────────────
// Generate a random 12-byte nonce using mbedTLS DRBG
// ─────────────────────────────────────────────────────────────

void generateNonce(uint8_t* out) {
  mbedtls_ctr_drbg_random(&ctrDrbg, out, NONCE_SIZE);
}

// ─────────────────────────────────────────────────────────────
// CRC-16/CCITT - must match Arduino and Rust implementations
// ─────────────────────────────────────────────────────────────

uint16_t crc16(uint8_t* data, uint16_t length) {
  uint16_t crc = 0xFFFF;
  for (uint16_t i = 0; i < length; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (uint8_t j = 0; j < 8; j++) {
      if (crc & 0x8000) {
        crc = (crc << 1) ^ 0x1021;
      } else {
        crc <<= 1;
      }
    }
  }
  return crc;
}
