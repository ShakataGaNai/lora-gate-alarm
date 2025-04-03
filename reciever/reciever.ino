#include "LoRaWan_APP.h"
#include "Arduino.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

// --- WiFi & Home Assistant configuration ---
const char* ssid      = "WIFISSID";
const char* password  = "PASSWORD_HERE";
const char* ha_host   = "YOUR_HOME_ASSISTANT_HOST"; // e.g., "192.168.1.100"
const int   ha_port   = 8123;
const char* ha_token  = "YOUR_HOME_ASSISTANT_LONG_LIVED_ACCESS_TOKEN";
const char* ha_entity = "sensor.gate_status";

// --- LoRa parameters (matching your working receiver code) ---
#define RF_FREQUENCY            915000000   // Hz
#define LORA_BANDWIDTH          0           // 0: 125 kHz
#define LORA_SPREADING_FACTOR   7           // SF7..SF12
#define LORA_CODINGRATE         1           // 1: 4/5, 2: 4/6, etc.
#define LORA_PREAMBLE_LENGTH    8           // Same for Tx and Rx
#define LORA_SYMBOL_TIMEOUT     0           // Symbols
#define LORA_FIX_LENGTH_PAYLOAD_ON false
#define LORA_IQ_INVERSION_ON    false

#define BUFFER_SIZE             256   // increased buffer size for encrypted packets

// --- Global variables ---
bool lora_idle = true;
static RadioEvents_t RadioEvents;
char rxpacket[BUFFER_SIZE];

// Pre-shared AES key (must match sender)
const unsigned char aes_key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

void OnRxDone(uint8_t *payload, uint16_t size, int16_t rssi, int8_t snr);
String decryptData(const String &ciphertext_base64);
void postToHomeAssistant(const char* event, float battery, int raw, double txNumber, int16_t rssi, int8_t snr);

void setup() {
  Serial.begin(115200);
  while (!Serial);

  // Call Mcu.begin() first (as in your working code)
  Serial.println("Initializing Heltec board...");
  Mcu.begin(HELTEC_BOARD, SLOW_CLK_TPYE);

  // Then connect to WiFi
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);
  while(WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected.");

  // Initialize LoRa radio using Heltec API (exactly as in your working receiver firmware)
  RadioEvents.RxDone = OnRxDone;
  Radio.Init(&RadioEvents);
  Radio.SetChannel(RF_FREQUENCY);
  Radio.SetRxConfig(MODEM_LORA, LORA_BANDWIDTH, LORA_SPREADING_FACTOR,
                    LORA_CODINGRATE, 0, LORA_PREAMBLE_LENGTH,
                    LORA_SYMBOL_TIMEOUT, LORA_FIX_LENGTH_PAYLOAD_ON,
                    0, true, 0, 0, LORA_IQ_INVERSION_ON, true);
  Serial.println("LoRa radio initialized and set to RX mode.");
  
  // Start in RX mode
  lora_idle = false;
  Serial.println("Entering RX mode...");
  Radio.Rx(0);
}

void loop() {
  // Debug: print loop heartbeat every 5 seconds
  static unsigned long lastLoop = 0;
  if(millis() - lastLoop > 5000) {
    Serial.println("Loop running...");
    lastLoop = millis();
  }
  
  Radio.IrqProcess();
  
  // If we're idle, ensure RX mode is active
  if(lora_idle) {
    lora_idle = false;
    Serial.println("Re-entering RX mode...");
    Radio.Rx(0);
  }
}

void OnRxDone(uint8_t *payload, uint16_t size, int16_t rssi, int8_t snr) {
  uint16_t copySize = (size < BUFFER_SIZE - 1) ? size : (BUFFER_SIZE - 1);
  memcpy(rxpacket, payload, copySize);
  rxpacket[copySize] = '\0';
  Radio.Sleep();
  
  Serial.printf("\nReceived raw packet: \"%s\"\n", rxpacket);
  Serial.printf("Packet size: %d, RSSI: %d dBm, SNR: %d dB\n", size, rssi, snr);
  
  // Decrypt received payload (encrypted, base64-encoded)
  String encryptedMessage = String(rxpacket);
  String decryptedPayload = decryptData(encryptedMessage);
  Serial.printf("Decrypted payload: %s\n", decryptedPayload.c_str());
  
  // Parse JSON using ArduinoJson
  StaticJsonDocument<256> doc;
  DeserializationError error = deserializeJson(doc, decryptedPayload);
  if (error) {
    Serial.print("JSON parse error: ");
    Serial.println(error.c_str());
    lora_idle = true;
    Serial.println("Re-entering RX mode...");
    Radio.Rx(0);
    return;
  }
  
  // Extract transmitted fields
  const char* event = doc["event"];
  float battery = doc["battery"];
  int raw = doc["raw"];
  double txNumber = doc["txNumber"];
  Serial.printf("Parsed fields:\n  event: %s\n  battery: %.2f V\n  raw: %d\n  txNumber: %.2f\n",
                event, battery, raw, txNumber);
  
  // Post all fields plus RF parameters to Home Assistant
  postToHomeAssistant(event, battery, raw, txNumber, rssi, snr);
  
  if (strcmp(event, "gate_opened") == 0) {
    Serial.println("Gate opened event received.");
  }
  
  lora_idle = true;
  Serial.println("Re-entering RX mode...");
  Radio.Rx(0);
}

String decryptData(const String &ciphertext_base64) {
  size_t decodedLen = 0;
  size_t decodedBufferSize = (ciphertext_base64.length() * 3) / 4;
  unsigned char *decodedBuffer = new unsigned char[decodedBufferSize];
  int ret = mbedtls_base64_decode(decodedBuffer, decodedBufferSize, &decodedLen,
                                  (const unsigned char*)ciphertext_base64.c_str(), ciphertext_base64.length());
  if (ret != 0) {
    Serial.printf("Base64 decode failed: %d\n", ret);
    delete[] decodedBuffer;
    return "";
  }
  
  unsigned char *decryptedBuffer = new unsigned char[decodedLen];
  unsigned char iv[16] = {0};
  
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  ret = mbedtls_aes_setkey_dec(&aes, aes_key, 128);
  if (ret != 0) {
    Serial.printf("AES setkey_dec failed: %d\n", ret);
    mbedtls_aes_free(&aes);
    delete[] decodedBuffer;
    delete[] decryptedBuffer;
    return "";
  }
  ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decodedLen, iv, decodedBuffer, decryptedBuffer);
  mbedtls_aes_free(&aes);
  if (ret != 0) {
    Serial.printf("AES decryption failed: %d\n", ret);
    delete[] decodedBuffer;
    delete[] decryptedBuffer;
    return "";
  }
  
  int padding = decryptedBuffer[decodedLen - 1];
  int plaintextLen = decodedLen - padding;
  String plaintext = "";
  for (int i = 0; i < plaintextLen; i++) {
    plaintext += (char)decryptedBuffer[i];
  }
  
  delete[] decodedBuffer;
  delete[] decryptedBuffer;
  return plaintext;
}

void postToHomeAssistant(const char* event, float battery, int raw, double txNumber, int16_t rssi, int8_t snr) {
  StaticJsonDocument<256> haDoc;
  
  if (strcmp(event, "gate_opened") == 0) {
    haDoc["state"] = "open";
  } else if (strcmp(event, "battery_status") == 0) {
    haDoc["state"] = "normal";
  } else {
    haDoc["state"] = "unknown";
  }
  
  JsonObject attributes = haDoc.createNestedObject("attributes");
  attributes["event"] = event;
  attributes["battery"] = battery;
  attributes["raw"] = raw;
  attributes["txNumber"] = txNumber;
  attributes["rssi"] = rssi;
  attributes["snr"] = snr;
  
  String haPayload;
  serializeJson(haDoc, haPayload);
  Serial.printf("Posting to Home Assistant: %s\n", haPayload.c_str());
  
  HTTPClient http;
  String url = String("http://") + ha_host + ":" + String(ha_port) + "/api/states/" + ha_entity;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", String("Bearer ") + ha_token);
  
  int httpResponseCode = http.POST(haPayload);
  if (httpResponseCode > 0) {
    Serial.printf("Home Assistant response code: %d\n", httpResponseCode);
  } else {
    Serial.printf("HTTP POST error: %s\n", http.errorToString(httpResponseCode).c_str());
  }
  http.end();
}
