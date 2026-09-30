// ChainSeal sensor node: ESP32 + ATECC608 + DHT22. Private key is generated inside the chip and never exported.
// Libraries: ArduinoECCX08, DHT sensor library, ArduinoJson, WiFi (ESP32 core)
#include <ArduinoECCX08.h>
#include <DHT.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

#define DHTPIN 4
#define TAMPER_PIN 14              // switch closes when enclosure is opened
#define KEY_SLOT 0
DHT dht(DHTPIN, DHT22);
const char* SSID = "YOUR_WIFI"; const char* PASS = "YOUR_PASS";
const char* SERVER = "http://YOUR_SERVER:3000";
const char* DEVICE_ID = "CS-NODE-01";

void setup() {
  Serial.begin(115200); dht.begin(); pinMode(TAMPER_PIN, INPUT_PULLUP);
  if (!ECCX08.begin()) { Serial.println("ATECC608 not found"); while (1); }
  if (!ECCX08.locked()) { ECCX08.writeConfiguration(ECCX08.defaultTLSConfig()); ECCX08.lock(); }
  byte pub[64];
  ECCX08.generatePrivateKey(KEY_SLOT, pub);        // key is born in the chip; only the public half leaves
  Serial.print("PUBLIC KEY (register this): "); for (int i = 0; i < 64; i++) Serial.printf("%02x", pub[i]); Serial.println();
  WiFi.begin(SSID, PASS); while (WiFi.status() != WL_CONNECTED) delay(300);
}

String sign(const String& msg) {
  byte hash[32], sig[64];
  mbedtls_sha256((const unsigned char*)msg.c_str(), msg.length(), hash, 0);
  ECCX08.ecSign(KEY_SLOT, hash, sig);              // raw r||s, same as ieee-p1363 on the server
  unsigned char b64[100]; size_t n;
  mbedtls_base64_encode(b64, sizeof(b64), &n, sig, 64);
  return String((char*)b64).substring(0, n);
}

void loop() {
  float t = dht.readTemperature(), h = dht.readHumidity();
  if (isnan(t) || t < -40 || t > 80) { delay(2000); return; }          // sensor sanity check
  unsigned long long ts = 1700000000000ULL + millis();                   // replace with NTP time
  String nonce = String((uint32_t)esp_random(), HEX) + String((uint32_t)esp_random(), HEX);
  String canon = String(DEVICE_ID) + "|" + String((double)ts, 0) + "|" + nonce + "|" + String(t, 1) + "|" + String((int)h) + "|0|18.5204|73.8567";
  String body = "{\"reading\":{\"deviceId\":\"" + String(DEVICE_ID) + "\",\"ts\":" + String((double)ts, 0) + ",\"nonce\":\"" + nonce +
                "\",\"temp\":" + String(t, 1) + ",\"hum\":" + String((int)h) + ",\"shock\":0,\"lat\":18.5204,\"lng\":73.8567},\"signature\":\"" + sign(canon) + "\"}";
  HTTPClient http; http.begin(String(SERVER) + "/api/readings"); http.addHeader("Content-Type", "application/json");
  int code = http.POST(body); Serial.printf("POST %d\n", code); http.end();
  delay(10000);                                                          // batch: server seals many readings under one root
}
