#include <WiFi.h>
#include <WebServer.h>
#include <Adafruit_Fingerprint.h>

// ========== Wi‑Fi Configuration ==========
const char* ssid     = "Aasrith";
const char* password = "12345678";

// ========== Fingerprint Sensor Setup ==========
HardwareSerial mySerial(2);
Adafruit_Fingerprint finger(&mySerial);

// ========== Web Server ==========
WebServer server(80);

// ========== Voting State ==========
String lastScanResult     = "<div class='scanning'><img src='https://i.gifer.com/YCZH.gif' width='120'/><br>"
                            "Scanning fingerprint...<br>फ़िंगरप्रिंट स्कैन किया जा रहा है...</div>";
String statusType         = "scanning";
unsigned long resultDisplayTime = 0;
bool resultShowing        = false;

String userNames[128];
bool   hasVoted[128]      = { false };
int    lastDetectedID     = -1;
unsigned long lastScanTime      = 0;

// ========== HTML Template ==========
String generateHtml(const String &message, const String &styleClass) {
  String html = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Nirvachana - Fingerprint Voting</title>
  <meta http-equiv='refresh' content='2'>
  <style>
    body { margin:0; font-family:'Segoe UI',sans-serif;
           background:linear-gradient(to right,#FF9933,white,#138808);
           display:flex; justify-content:center; align-items:center; height:100vh; }
    .wrapper { display:flex; flex-direction:column; align-items:center;
               justify-content:center; gap:30px; width:100%; }
    .logo { width:150px; height:150px; border-radius:50%; object-fit:contain;
             background:#fff; padding:15px; box-shadow:0 6px 24px rgba(0,0,0,0.15); }
    .card { background:rgba(255,255,255,0.95); padding:40px 60px;
             border-radius:15px; box-shadow:0 8px 32px rgba(0,0,0,0.2);
             text-align:center; width:90%; max-width:700px; }
    .fingerprint-container { width:200px; height:250px; position:relative;
                             border-radius:15px; background:#fff; overflow:hidden; margin:0 auto; }
    .fingerprint-container img { width:100%; height:100%; object-fit:cover; border-radius:15px; }
    .scan-line { position:absolute; width:100%; height:8px;
                 background:linear-gradient(to right,transparent,rgba(76,175,80,1),transparent);
                 animation:scanning 2.5s ease-in-out infinite; }
    @keyframes scanning { 0%{top:0}50%{top:calc(100% - 8px)}100%{top:0} }
    .status { margin-top:20px; font-size:18px; color:#333;
              background:#f1f1f1; padding:12px; border-radius:10px; }
    .success{color:#2ecc71;font-weight:bold;} .error{color:#e74c3c;font-weight:bold;}
    .warning{color:#f39c12;font-weight:bold;}
  </style>
</head>
<body>
  <div class="wrapper">
    <img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/thumb/7/72/Election_Commission_of_India_Logo.svg/1024px-Election_Commission_of_India_Logo.svg.png"/>
    <div class="card">
      <h1>Nirvachana</h1><h1>निर्वचन</h1>
      <div class="fingerprint-container">
        <img src="https://images.rawpixel.com/image_800/cHJpdmF0ZS9sci9pbWFnZXMvd2Vic2l0ZS8yMDIyLTA0L2pvYjY3My0wNjktdi5qcGc.jpg"/>
        <div class="scan-line"></div>
      </div>
      <div class="status )rawliteral";
  html += styleClass;
  html += "\">";
  html += message;
  html += R"rawliteral(
      </div>
    </div>
  </div>
</body>
</html>
)rawliteral";
  return html;
}

void handleRoot() {
  server.send(200, "text/html", generateHtml(lastScanResult, statusType));
}

// ========== Setup Functions ==========
void connectToWiFi() {
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    Serial.print(".");
    delay(500);
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n✅ WiFi Connected.");
    Serial.print("📡 IP Address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\n🚨 WiFi Connection Failed.");
  }
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

void registerVote(int id, int confidence) {
  String name = userNames[id].length() ? userNames[id] : "Unknown";
  if (!hasVoted[id]) {
    hasVoted[id] = true;
    lastScanResult = "✅ Vote Cast!<br>ID: " + String(id) +
                     "<br>Name: " + name +
                     "<br>Confidence: " + String(confidence);
    statusType = "success";
  } else {
    lastScanResult = "🚨 Already voted!<br>ID: " + String(id) +
                     "<br>Name: " + name;
    statusType = "error";
  }
  Serial.println(lastScanResult);
  resultDisplayTime = millis();
  resultShowing     = true;
}

void checkFingerprint() {
  if (resultShowing && millis() - resultDisplayTime < 5000) return;

  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) return;
  if (p != FINGERPRINT_OK) return;

  if (finger.image2Tz(1) == FINGERPRINT_OK) {
    if (finger.fingerSearch() == FINGERPRINT_OK) {
      if (lastDetectedID == finger.fingerID &&
          millis() - lastScanTime < 3000) {
        lastScanResult = "🚨 Duplicate scan!";
        statusType     = "error";
      } else {
        lastDetectedID = finger.fingerID;
        lastScanTime   = millis();
        registerVote(finger.fingerID, finger.confidence);
      }
    } else {
      lastScanResult = "🚨 No match found.";
      statusType     = "error";
    }
  } else {
    lastScanResult = "🚨 Image conversion failed.";
    statusType     = "error";
  }

  resultDisplayTime = millis();
  resultShowing     = true;
}

void setup() {
  Serial.begin(115200);
  delay(100);

  connectToWiFi();

  server.on("/", handleRoot);
  server.begin();
  Serial.println("🌐 Web server started.");

  initFingerprintSensor();

  // Pre-fill user names
  userNames[1] = "Aasrith/असरिथ";
  userNames[2] = "Raghavendra/राघवेंद्र";
  userNames[3] = "Akshaya/अक्षय";
  userNames[4] = "Bhuvan";
  userNames[5] = "Eve";
}

void loop() {
  server.handleClient();

  if (resultShowing && millis() - resultDisplayTime >= 5000) {
    resultShowing    = false;
    lastScanResult   = "<div class='scanning'><img src='https://i.gifer.com/YCZH.gif' width='120'/><br>"
                       "Scanning fingerprint...<br>फ़िंगरप्रिंट स्कैन किया जा रहा है...</div>";
    statusType       = "scanning";
  }

  checkFingerprint();
}
