#include <WiFi.h>
#include <WebServer.h>
#include <Adafruit_Fingerprint.h>
#include <SPI.h>
#include <SD.h>
#include <Preferences.h>
#include <sodium.h>

// ========== Wi‑Fi Configuration ==========
const char* ssid     = "Aasrith";
const char* password = "12345678";

// ========== Fingerprint Sensor Setup ==========
HardwareSerial mySerial(2);
Adafruit_Fingerprint finger(&mySerial);

// ========== Web Server ==========
WebServer server(80);

// ========== Voting State ==========
String lastScanResult    = "<div class='scanning'><img src='https://i.gifer.com/YCZH.gif' width='120'/><br>"
                           "Scanning fingerprint...<br>फ़िंगरप्रिंट स्कैन किया जा रहा है...</div>";
String statusType        = "scanning";
unsigned long resultDisplayTime = 0;
bool resultShowing       = false;

String userNames[128];
bool   hasVoted[128]     = { false };
int    lastDetectedID    = -1;
unsigned long lastScanTime     = 0;

// ========== SD Card Pins ==========
#define SD_CS   33
#define SD_MOSI 27
#define SD_MISO 25
#define SD_SCK  26

bool sdCardPresent  = false;
bool sdCardWasPresent = true;
bool popupAlert     = false;

// ========== Libsodium + Key Storage ==========
Preferences prefs;
static unsigned char device_public_key[crypto_box_PUBLICKEYBYTES];
static unsigned char device_private_key[crypto_box_SECRETKEYBYTES];
const char* integrityFile = "/keycheck.bin";

// Derive a 32‑byte AEAD key from our private key
void deriveEncKey(unsigned char *encKey) {
  const char *ctx = "FP_ENC_KEY";
  crypto_generichash(encKey, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                     device_private_key, crypto_box_SECRETKEYBYTES,
                     (const unsigned char*)ctx, strlen(ctx));
}

// Create or verify the integrity file at boot
bool performIntegrityCheck() {
  SPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if (!SD.begin(SD_CS)) {
    Serial.println("🚨 SD init failed on integrity check!");
    return false;
  }

  // First‑boot? Create the file
  if (!SD.exists(integrityFile)) {
    File f = SD.open(integrityFile, FILE_WRITE);
    if (!f) return false;
    const unsigned char test[] = "DEVICECHECK";
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    unsigned char encKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    deriveEncKey(encKey);

    size_t ctLen = sizeof(test) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char *ct = (unsigned char*) malloc(ctLen);
    unsigned long long outLen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      ct, &outLen,
      test, sizeof(test),
      NULL, 0, NULL,
      nonce, encKey
    );
    f.write(nonce, sizeof(nonce));
    f.write(ct, outLen);
    f.close();
    free(ct);
    Serial.println("🔐 Created integrity file.");
    return true;
  }

  // Subsequent boots: verify
  File f = SD.open(integrityFile, FILE_READ);
  if (!f) return false;
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  f.read(nonce, sizeof(nonce));
  size_t csize = f.size() - sizeof(nonce);
  unsigned char *ct = (unsigned char*) malloc(csize);
  f.read(ct, csize);
  f.close();

  unsigned char dec[64];
  unsigned long long decLen;
  unsigned char encKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  deriveEncKey(encKey);

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        dec, &decLen,
        NULL,
        ct, csize,
        NULL, 0,
        nonce, encKey
      ) != 0) {
    free(ct);
    return false;
  }
  free(ct);
  // Compare to expected
  if (decLen != strlen("DEVICECHECK") ||
      memcmp(dec, "DEVICECHECK", decLen) != 0) {
    return false;
  }
  Serial.println("✅ Integrity check passed.");
  return true;
}

// Encrypt a raw fingerprint template and store on SD
bool encryptAndStoreTemplate(const uint8_t *tpl, size_t len, uint16_t id) {
  unsigned char encKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  deriveEncKey(encKey);

  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  size_t ctLen = len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  unsigned char *ct = (unsigned char*) malloc(ctLen);
  unsigned long long outLen;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct, &outLen,
        tpl, len,
        NULL, 0, NULL,
        nonce, encKey
      ) != 0) {
    free(ct);
    return false;
  }

  char fn[16];
  snprintf(fn, sizeof(fn), "/finger_%03d.bin", id);
  File f = SD.open(fn, FILE_WRITE);
  if (!f) {
    free(ct);
    return false;
  }
  f.write(nonce, sizeof(nonce));
  f.write(ct, outLen);
  f.close();
  free(ct);
  Serial.printf("🔒 Template %d encrypted→%s\n", id, fn);
  return true;
}

// Decrypt & load a template into the sensor (assumes send_fpdata exists)
void loadEncryptedTemplates() {
  File root = SD.open("/");
  if (!root) return;
  File file = root.openNextFile();
  while (file) {
    String n = file.name();
    if (n.startsWith("/finger_") && n.endsWith(".bin")) {
      int id = atoi(n.substring(8, n.length()-4).c_str());
      size_t sz = file.size();
      if (sz > crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        file.read(nonce, sizeof(nonce));
        size_t csize = sz - sizeof(nonce);
        unsigned char *ct = (unsigned char*) malloc(csize);
        file.read(ct, csize);
        unsigned char encKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        deriveEncKey(encKey);
        unsigned char plain[600];
        unsigned long long plainLen;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
              plain, &plainLen,
              NULL,
              ct, csize,
              NULL, 0,
              nonce, encKey
            ) == 0) {
          // send decrypted template into sensor buffer 1
          finger.uploadModel(1, plain, plainLen);      // <— you need a helper that sends raw bytes to the sensor
          finger.storeModel(id);                       // store from buffer 1→slot=id
          Serial.printf("✔ Loaded ID %d (size %llu)\n", id, plainLen);
        } else {
          Serial.printf("⚠ Failed decrypt %s\n", n.c_str());
        }
        free(ct);
      }
    }
    file = root.openNextFile();
  }
  root.close();
}

// ========== HTML Template & Handlers ==========
String generateHtml(String message, String styleClass, bool alertFlag) {
  String html = R"rawliteral(
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Nirvachana – Fingerprint Voting</title><meta http-equiv='refresh' content='2'><script>%ALERTSCRIPT%</script>
<style>body{margin:0;font-family:'Segoe UI',sans-serif;background:linear-gradient(to right,#FF9933,white,#138808);display:flex;justify-content:center;align-items:center;height:100vh;}
.wrapper{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:30px;width:100%;}
.logo{width:150px;height:150px;border-radius:50%;object-fit:contain;background:#fff;padding:15px;box-shadow:0 6px 24px rgba(0,0,0,0.15);}
.card{background:rgba(255,255,255,0.95);padding:40px 60px;border-radius:15px;box-shadow:0 8px 32px rgba(0,0,0,0.2);text-align:center;width:90%;max-width:700px;}
.fingerprint-container{width:200px;height:250px;position:relative;border-radius:15px;background:#fff;overflow:hidden;margin:0 auto;}
.fingerprint-container img{width:100%;height:100%;object-fit:cover;border-radius:15px;}
.scan-line{position:absolute;width:100%;height:8px;background:linear-gradient(to right,transparent,rgba(76,175,80,1),transparent);animation:scanning 2.5s ease-in-out infinite;}
@keyframes scanning{0%{top:0}50%{top:calc(100% - 8px)}100%{top:0}}
.status{margin-top:20px;font-size:18px;color:#333;background:#f1f1f1;padding:12px;border-radius:10px;}
.success{color:#2ecc71;font-weight:bold;} .error{color:#e74c3c;font-weight:bold;} .warning{color:#f39c12;font-weight:bold;}
</style></head><body><div class="wrapper">
<img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/thumb/7/72/Election_Commission_of_India_Logo.svg/1024px-Election_Commission_of_India_Logo.svg.png"/>
<div class="card"><h1>Nirvachana</h1><h1>निर्वचन</h1>
<div class="fingerprint-container"><img src="https://images.rawpixel.com/image_800/cHJpdmF0ZS9sci9pbWFnZXMvd2Vic2l0ZS8yMDIyLTA0L2pvYjY3My0wNjktdi5qcGc.jpg"/><div class="scan-line"></div></div>
<div class="status %STYLE%">%MESSAGE%</div></div></div></body></html>
  )rawliteral";
  String as = alertFlag ? "alert('⚠ SD Card removed!');" : "";
  html.replace("%ALERTSCRIPT%", as);
  html.replace("%MESSAGE%", message);
  html.replace("%STYLE%", styleClass);
  return html;
}

void handleRoot() {
  server.send(200, "text/html", generateHtml(lastScanResult, statusType, popupAlert));
  popupAlert = false;
}

// ========== Setup & Loop ==========
void connectToWiFi() {
  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    Serial.print(".");
    delay(500);
  }
  Serial.println(WiFi.status() == WL_CONNECTED ? "\n✅ WiFi Connected." : "\n🚨 WiFi Failed.");
}

void initFingerprintSensor() {
  mySerial.begin(57600, SERIAL_8N1, 16, 17);
  delay(100);
  finger.begin(57600);
  if (finger.verifyPassword()) {
    Serial.println("✅ Fingerprint sensor connected.");
  } else {
    Serial.println("🚨 Fingerprint sensor not detected.");
    while (true) delay(1);
  }
}

void checkSDCard() {
  SPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  bool now = SD.begin(SD_CS);
  if (sdCardWasPresent && !now) {
    lastScanResult = "⚠ SD Card Removed. Cannot continue.";
    statusType     = "warning";
    popupAlert     = true;
    Serial.println("⚠ SD removed.");
  }
  sdCardPresent    = now;
  sdCardWasPresent = now;
}

void registerVote(int id, int confidence) {
  String name = userNames[id].length() ? userNames[id] : "Unknown";
  if (!hasVoted[id]) {
    hasVoted[id] = true;
    lastScanResult = "✅ Vote Cast!<br>ID: " + String(id) +
                     "<br>Name: " + name +
                     "<br>Confidence: " + String(confidence);
    statusType = "success";
  } else {
    lastScanResult = "🚨 Already voted!<br>ID: " + String(id) + "<br>Name: " + name;
    statusType = "error";
  }
  Serial.println(lastScanResult);
  resultDisplayTime = millis();
  resultShowing     = true;
}

void checkFingerprint() {
  if (!sdCardPresent) return;
  if (resultShowing && millis() - resultDisplayTime < 5000) return;

  if (finger.getImage() == FINGERPRINT_OK) {
    if (finger.image2Tz() == FINGERPRINT_OK) {
      if (finger.fingerSearch() == FINGERPRINT_OK) {
        if (lastDetectedID == finger.fingerID &&
            millis() - lastScanTime < 3000) {
          lastScanResult = "🚨 Duplicate scan!";
          statusType = "error";
        } else {
          lastDetectedID = finger.fingerID;
          lastScanTime   = millis();
          registerVote(finger.fingerID, finger.confidence);
        }
      } else {
        lastScanResult = "🚨 No match found.";
        statusType = "error";
      }
    } else {
      lastScanResult = "🚨 Image conversion failed.";
      statusType = "error";
    }
    resultDisplayTime = millis();
    resultShowing = true;
  } else {
    lastScanResult = "<div class='scanning'><img src='https://i.gifer.com/YCZH.gif' width='120'/>"
                     "<br>Scanning fingerprint...</div>";
    statusType = "scanning";
  }
}

void setup() {
  Serial.begin(115200);
  delay(100);

  // ————— Libsodium & Key Setup —————
  if (sodium_init() < 0) {
    Serial.println("🚨 libsodium init failed!");
    while (true) delay(1);
  }
  prefs.begin("crypto", false);
  size_t pkL = prefs.getBytesLength("pubkey");
  size_t skL = prefs.getBytesLength("privkey");
  if (pkL == crypto_box_PUBLICKEYBYTES &&
      skL == crypto_box_SECRETKEYBYTES) {
    prefs.getBytes("pubkey", device_public_key, pkL);
    prefs.getBytes("privkey", device_private_key, skL);
    Serial.println("🔑 Loaded existing keypair.");
  } else {
    crypto_box_keypair(device_public_key, device_private_key);
    prefs.putBytes("pubkey", device_public_key, crypto_box_PUBLICKEYBYTES);
    prefs.putBytes("privkey", device_private_key, crypto_box_SECRETKEYBYTES);
    Serial.println("🔑 Generated & stored new keypair.");
  }
  prefs.end();

  // ————— Integrity Check —————
  if (!performIntegrityCheck()) {
    Serial.println("🚨 Integrity FAILED. Halting.");
    while (true) delay(1);
  }

  // ————— Networking & Server —————
  connectToWiFi();
  server.on("/", handleRoot);
  server.begin();
  Serial.println("🌐 Server started at " + WiFi.localIP().toString());

  // ————— Sensor & Templates —————
  initFingerprintSensor();
  loadEncryptedTemplates();  // decrypt & push to sensor flash

  // ————— User Names Setup —————
  userNames[1] = "Aasrith/असरिथ";
  userNames[2] = "Raghavendra/राघवेंद्र";
  userNames[3] = "Akshaya/अक्षय";
  userNames[4] = "Bhuvan";
  userNames[5] = "Eve";
}

void loop() {
  server.handleClient();

  if (resultShowing && millis() - resultDisplayTime >= 5000) {
    resultShowing = false;
    lastScanResult = "<div class='scanning'><img src='https://i.gifer.com/YCZH.gif' width='120'/>"
                     "<br>Scanning fingerprint...</div>";
    statusType = "scanning";
  }

  checkSDCard();
  checkFingerprint();
}
