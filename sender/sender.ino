#include "LoRaWan_APP.h"
#include <Arduino.h>
#include <ArduinoJson.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include <esp_sleep.h>
#include <WiFi.h>
#include <esp_bt.h>

// LoRa parameters
#define RF_FREQUENCY            915000000
#define TX_OUTPUT_POWER         5    // dBm
#define LORA_BANDWIDTH          0    // 0:125 kHz
#define LORA_SPREADING_FACTOR   7
#define LORA_CODINGRATE         1
#define LORA_PREAMBLE_LENGTH    8
#define LORA_SYMBOL_TIMEOUT     0
#define LORA_FIX_LENGTH_PAYLOAD_ON false
#define LORA_IQ_INVERSION_ON    false

#define BUFFER_SIZE             256

// Pin definitions
#define BATTERY_READ_PIN        37
#define REED_PIN                33  // Reed switch for gate open detection

// ADC configuration constants for battery reading
float XS = 0.0025;       // Scale factor from ADC reading to voltage
uint16_t MUL = 1000;     // Multiplier to convert to mV

// Debug flag: if true, wait 15 seconds between transmissions;
// if false, use deep sleep for 6 hours with wakeup on timer or reed switch.
bool debug = true;

bool lora_idle = true;
static RadioEvents_t RadioEvents;
double txNumber = 0;

// Pre-shared AES key (16 bytes)
const unsigned char aes_key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

void OnTxDone(void);
void OnTxTimeout(void);
String encryptData(const String &plaintext);

void setup() {
  Serial.begin(115200);
  while(!Serial);

  // Disable WiFi and Bluetooth for battery efficiency
  WiFi.mode(WIFI_OFF);
  btStop();

  // Configure ADC for battery reading on BATTERY_READ_PIN
  analogSetAttenuation(ADC_11db);
  analogSetPinAttenuation(BATTERY_READ_PIN, ADC_11db);

  // Configure the reed switch pin for external wakeup
  pinMode(REED_PIN, INPUT_PULLUP);

  // Check wakeup cause
  esp_sleep_wakeup_cause_t wakeupReason = esp_sleep_get_wakeup_cause();
  Serial.printf("Wakeup cause: %d\n", wakeupReason);

  // Initialize Heltec board
  Mcu.begin(HELTEC_BOARD, SLOW_CLK_TPYE);
  txNumber = 0;

  // Setup LoRa
  RadioEvents.TxDone = OnTxDone;
  RadioEvents.TxTimeout = OnTxTimeout;
  Radio.Init(&RadioEvents);
  Radio.SetChannel(RF_FREQUENCY);
  Radio.SetTxConfig(MODEM_LORA, TX_OUTPUT_POWER, 0, LORA_BANDWIDTH,
                    LORA_SPREADING_FACTOR, LORA_CODINGRATE,
                    LORA_PREAMBLE_LENGTH, LORA_FIX_LENGTH_PAYLOAD_ON,
                    true, 0, 0, LORA_IQ_INVERSION_ON, 3000);

  Serial.println("Sender setup complete.");
}

void loop() {
  if(lora_idle) {
    lora_idle = false;
    
    // Read battery voltage from ADC on BATTERY_READ_PIN
    int rawBattery = analogRead(BATTERY_READ_PIN);
    uint16_t battery_mV = rawBattery * XS * MUL;
    float battery_V = battery_mV / 1000.0;

    Serial.printf("Raw battery reading from GPIO %d: %d\n", BATTERY_READ_PIN, rawBattery);
    Serial.printf("Calculated battery voltage: %.2f V (%d mV)\n", battery_V, battery_mV);
    Serial.printf("Tx sequence number: %.2f\n", txNumber);

    // Determine event type based on wakeup cause
    esp_sleep_wakeup_cause_t wakeupReason = esp_sleep_get_wakeup_cause();
    const char* eventType = "battery_status";
    if(wakeupReason == ESP_SLEEP_WAKEUP_EXT0) {
      eventType = "gate_opened";
    }
    Serial.printf("Event type determined: %s\n", eventType);

    // Build JSON payload using ArduinoJson
    StaticJsonDocument<128> doc;
    doc["event"] = eventType;
    doc["battery"] = battery_V;
    doc["raw"] = rawBattery;
    doc["txNumber"] = txNumber;
    String jsonPayload;
    serializeJson(doc, jsonPayload);
    Serial.printf("JSON Payload: %s\n", jsonPayload.c_str());

    // Encrypt the JSON payload
    String encryptedPayload = encryptData(jsonPayload);
    Serial.printf("Encrypted Payload: %s\n", encryptedPayload.c_str());

    // Send the encrypted payload 3 times for redundancy
    for (int i = 0; i < 3; i++) {
      Serial.printf("Sending packet (%d/3): %s\n", i+1, encryptedPayload.c_str());
      Radio.Send((uint8_t*)encryptedPayload.c_str(), encryptedPayload.length());
      while(!lora_idle) {
        Radio.IrqProcess();
      }
      delay(1000);
    }
    txNumber += 0.01;

    if(debug) {
      Serial.println("Debug mode: waiting 15 seconds before next transmission.");
      delay(15000);
      lora_idle = true;
    } else {
      // Enable wakeup sources: reed switch and timer
      esp_sleep_enable_ext0_wakeup((gpio_num_t)REED_PIN, 1);
      esp_sleep_enable_timer_wakeup(21600000000ULL);  // 6 hours in microseconds
      Serial.println("Entering deep sleep for 6 hours. Wakeup on timer or reed switch.");
      esp_deep_sleep_start();
    }
  }
  Radio.IrqProcess();
}

void OnTxDone(void) {
  Serial.println("TX done.");
  lora_idle = true;
}

void OnTxTimeout(void) {
  Serial.println("TX Timeout. Putting radio to sleep.");
  Radio.Sleep();
  lora_idle = true;
}

String encryptData(const String &plaintext) {
  int len = plaintext.length();
  int block_size = 16;
  int padded_len = ((len / block_size) + 1) * block_size;
  
  unsigned char *inputBuffer = new unsigned char[padded_len];
  memcpy(inputBuffer, plaintext.c_str(), len);
  int padding = padded_len - len;
  for (int i = len; i < padded_len; i++) {
    inputBuffer[i] = padding;
  }
  
  unsigned char *encryptedBuffer = new unsigned char[padded_len];
  unsigned char iv[16] = {0};
  
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int ret = mbedtls_aes_setkey_enc(&aes, aes_key, 128);
  if(ret != 0) {
    mbedtls_aes_free(&aes);
    delete[] inputBuffer;
    delete[] encryptedBuffer;
    return "";
  }
  ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, inputBuffer, encryptedBuffer);
  mbedtls_aes_free(&aes);
  if(ret != 0) {
    delete[] inputBuffer;
    delete[] encryptedBuffer;
    return "";
  }
  
  size_t encodedLen = 0;
  size_t base64BufferSize = 4 * ((padded_len + 2) / 3) + 1;
  unsigned char *base64Buffer = new unsigned char[base64BufferSize];
  ret = mbedtls_base64_encode(base64Buffer, base64BufferSize, &encodedLen, encryptedBuffer, padded_len);
  String encoded = "";
  if(ret == 0) {
    encoded = String((char*)base64Buffer);
  }
  
  delete[] inputBuffer;
  delete[] encryptedBuffer;
  delete[] base64Buffer;
  return encoded;
}
