#include <PulseSensorPlayground.h> // Include the PulseSensorPlayground library for handling the pulse sensor
#include <WiFi.h> // Include the WiFi library for connecting to a Wi-Fi network
#include <HTTPClient.h> // Include the HTTPClient library for making HTTP requests
#include <mbedtls/md.h> // Include the mbedtls library for cryptographic functions

const int PulsePin = 34; // Define the GPIO pin where the pulse sensor is connected
const int Threshold = 550; // Define the threshold value for detecting a heartbeat

const char* ssid = "moto g32"; // Wi-Fi network SSID
const char* password = "sriganesh"; // Wi-Fi network password

const char* serverURL = "https://esp-server-ze37.onrender.com/data"; // The URL of the hospital server where data will be sent

const char* TRA_URL = "http://your_tra_url"; // URL of the Trusted Registration Authority
const char* ENTITY_ID = "pulse_sensor_1"; // Unique ID for the Pulse Sensor
String SESSION_KEY; // Session key for secure communication

PulseSensorPlayground pulseSensor; // Create an instance of the PulseSensorPlayground class

void setup() {
  Serial.begin(115200); // Initialize serial communication at 115200 baud rate

  Serial.println("Connecting to Wi-Fi..."); // Print message to serial monitor
  WiFi.begin(ssid, password); // Start connecting to the Wi-Fi network

  while (WiFi.status() != WL_CONNECTED) { // Wait until the ESP32 is connected to the Wi-Fi network
    delay(500); // Wait for 500 milliseconds
    Serial.print("."); // Print a dot to indicate connection progress
  }
  Serial.println("\nWi-Fi connected!"); // Print message when the connection is successful

  pulseSensor.analogInput(PulsePin); // Set the analog input pin for the pulse sensor
  pulseSensor.setThreshold(Threshold); // Set the threshold value for detecting a heartbeat

  if (!pulseSensor.begin()) { // Initialize the pulse sensor
    Serial.println("Pulse Sensor initialization failed!"); // Print error message if initialization fails
    while (1); // Stop execution if initialization fails
  }

  Serial.println("Pulse Sensor initialized."); // Print message when the pulse sensor is initialized
  registerWithTRA(); // Register the pulse sensor with the Trusted Registration Authority (TRA) to obtain a session key
}

void loop() {
  if (pulseSensor.sawStartOfBeat()) { // Check if a heartbeat is detected
    int bpm = pulseSensor.getBeatsPerMinute(); // Get the beats per minute (BPM) value

    Serial.print("Heartbeat detected! BPM: "); // Print message to serial monitor
    Serial.println(bpm); // Print the BPM value to serial monitor

    sendDataToServer(bpm); // Send the BPM value to the hospital server
  }

  delay(20); // Wait for 20 milliseconds before the next loop iteration
}

void registerWithTRA() {
  if (WiFi.status() == WL_CONNECTED) { // Check if the ESP32 is connected to the Wi-Fi network
    HTTPClient http; // Create an instance of the HTTPClient class
    http.begin(String(TRA_URL) + "/register"); // Specify the URL for the TRA registration endpoint
    http.addHeader("Content-Type", "application/json"); // Add a header specifying the content type as JSON

    String payload = "{"; // Create a JSON payload for the registration request
    payload += "\"entity_id\": \"" + String(ENTITY_ID) + "\", "; // Add the entity ID to the payload
    payload += "\"entity_type\": \"pulse_sensor\""; // Add the entity type to the payload
    payload += "}";

    int httpResponseCode = http.POST(payload); // Send the POST request to the TRA registration endpoint

    if (httpResponseCode == 201) { // Check if the registration was successful
      String response = http.getString(); // Get the response from the TRA
      DynamicJsonDocument doc(1024); // Create a JSON document to parse the response
      deserializeJson(doc, response); // Parse the JSON response
      SESSION_KEY = doc["session_key"].as<String>(); // Extract the session key from the response
      Serial.println("Successfully registered with TRA. SKEY: " + SESSION_KEY); // Print the session key to serial monitor
    } else {
      Serial.println("TRA registration failed: " + String(httpResponseCode)); // Print error message if registration fails
    }

    http.end(); // End the HTTP connection
  } else {
    Serial.println("Wi-Fi not connected!"); // Print error message if not connected to Wi-Fi
  }
}

String generateHMAC(String message) {
  byte hmacResult[32]; // Array to store the HMAC result
  mbedtls_md_context_t ctx; // Create a context for the HMAC operation
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256; // Specify the hash function type as SHA-256
  const size_t keyLength = SESSION_KEY.length(); // Get the length of the session key

  mbedtls_md_init(&ctx); // Initialize the HMAC context
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1); // Set up the HMAC context
  mbedtls_md_hmac_starts(&ctx, (unsigned char*)SESSION_KEY.c_str(), keyLength); // Start the HMAC operation with the session key
  mbedtls_md_hmac_update(&ctx, (unsigned char*)message.c_str(), message.length()); // Update the HMAC with the message
  mbedtls_md_hmac_finish(&ctx, hmacResult); // Finish the HMAC operation and store the result
  mbedtls_md_free(&ctx); // Free the HMAC context

  String hmacStr = ""; // Create a string to store the HMAC result as a hexadecimal string
  for (int i = 0; i < sizeof(hmacResult); i++) {
    char str[3]; // Buffer to store the hexadecimal representation of each byte
    sprintf(str, "%02x", (unsigned int)hmacResult[i]); // Convert the byte to a hexadecimal string
    hmacStr += str; // Append the hexadecimal string to the HMAC result string
  }
  return hmacStr; // Return the HMAC result string
}

void sendDataToServer(int bpm) {
  if (WiFi.status() == WL_CONNECTED) { // Check if the ESP32 is connected to the Wi-Fi network
    HTTPClient http; // Create an instance of the HTTPClient class
    http.begin(serverURL); // Specify the URL for the hospital server endpoint
    http.addHeader("Content-Type", "application/json"); // Add a header specifying the content type as JSON

    String nonce = String(random(0, 999999)); // Generate a random nonce
    String hmac = generateHMAC(nonce); // Generate the HMAC using the nonce

    http.addHeader("Entity-ID", ENTITY_ID); // Add the Entity-ID header
    http.addHeader("Nonce", nonce); // Add the Nonce header
    http.addHeader("HMAC", hmac); // Add the HMAC header

    String payload = "{"; // Create a JSON payload for the POST request
    payload += "\"id\": \"sensor1\", "; // Add the sensor ID to the payload
    payload += "\"bpm\": " + String(bpm); // Add the BPM value to the payload
    payload += "}";

    int httpResponseCode = http.POST(payload); // Send the POST request to the hospital server

    if (httpResponseCode > 0) { // Check if the POST request was successful
      String response = http.getString(); // Get the response from the server
      Serial.println("Server response: " + response); // Print the server response to serial monitor
    } else {
      Serial.println("Error in sending POST request: " + String(httpResponseCode)); // Print error message if POST request fails
    }

    http.end(); // End the HTTP connection
  } else {
    Serial.println("Wi-Fi not connected!"); // Print error message if not connected to Wi-Fi
  }
}