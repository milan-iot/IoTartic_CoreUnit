#include "WiFi_client.h"

#include <Arduino.h>
#include "RGB_LED.h"

#include <WiFi.h>
#include <WiFiMulti.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>

#define ATTEMPTS_NUM 20

WiFiUDP udp;
WiFiMulti wifiMulti;
WiFiClient tcp;
WiFiClient espClient;
PubSubClient client(espClient);
bool WIFI_debug_enable = false;

uint8_t *mqtt_rx_buffer;
int mqtt_rx_buffer_size;

void WiFI_debugEnable(bool enable)
{
  WIFI_debug_enable = enable;
}

bool WiFi_setup(const char* ssid, const char* pass)
{
  uint32_t num_of_attempts = 100;

  if (WIFI_debug_enable)
    Serial.print("Connecting to WiFi");

  //WiFi_disconnect();

  wifiMulti.addAP(ssid, pass);
  do
  {
    if (WIFI_debug_enable)
      Serial.print('.');
    //RGB_LED_setColor(CYAN);
    delay(100);
    //RGB_LED_setColor(BLACK);
    if (--num_of_attempts == 0)
      break;
  } while (!(wifiMulti.run() == WL_CONNECTED));
  
  if (WIFI_status() != WL_CONNECTED)
    return false;

  if (WIFI_debug_enable)
  {
    Serial.println(" OK!");
    Serial.print("IP address: "); 
    //RGB_LED_setColor(CYAN);
  }

  // Print ESP32 Local IP Address
  if (WIFI_debug_enable)
  {
    Serial.println(WiFi.localIP());
    delay(1000);
    //RGB_LED_setColor(BLACK);
  }
  
  return true;
}

void WiFi_reconnect()
{
  int attempts = ATTEMPTS_NUM;

  if (WIFI_debug_enable)
    Serial.print("Reconnecting to WiFi");
  do
  {
    Serial.print('.');
    RGB_LED_setColor(CYAN);
    delay(100);
    RGB_LED_setColor(BLACK);
    attempts--;
    if(attempts == 0)
    {
      break;
    }
  }
  // Scan -> Connect to best known WiFi
  while (!(wifiMulti.run() == WL_CONNECTED)); 
  // Reconnect to last used WiFi
  //while(!WiFi.reconnect());

  wl_status_t wifi_status = WiFi.status();
  if (WIFI_debug_enable)
  {
    if(wifi_status == WL_CONNECTED)
      Serial.println(" RECONNECTED!");
    else
      Serial.println(" RECONNECTING FAILED!");
  }
}

void WiFi_disconnect()
{
  WiFi.disconnect();
}

bool WiFi_UDPsend(const char* ip, uint16_t port, uint8_t udp_packet[], uint16_t size)
{
  if (!udp.beginPacket(ip, port))
    return false;
  for (int i = 0; i < size; i++)
    udp.write(udp_packet[i]);
  if (!udp.endPacket())
    return false;
  return true;
}

bool WiFi_UDPrecv(char rx_buffer[], uint16_t *size)
{
  uint32_t t0 = millis();

  while(!udp.available() && (millis() - t0 < 5000))
  //{
    udp.parsePacket();
  //  vTaskDelay(50 / portTICK_PERIOD_MS);
  //}
  
  if (*size > udp.available())
    *size = udp.available();
  
  udp.read(rx_buffer, *size);
  rx_buffer[*size] = '\0';

  if (WIFI_debug_enable)
  {
    Serial.print("RX -> ");
    Serial.println(rx_buffer);
  }

  //udp.flush();
  return true;
}

void callback(char *topic, byte *payload, unsigned int length)
{
  if (WIFI_debug_enable)
  {
    Serial.println(topic);
    Serial.println(length);
  }
  mqtt_rx_buffer = payload;
  mqtt_rx_buffer_size = length;
}

bool WiFi_MQTTconnect(char *broker, int port, char *client_id)
{
  client.setServer(broker, port);
  client.setCallback(callback);
  
  int num_of_attempts = 3;

  // if already connected return
  if (client.connected())
    return true;

  while (!client.connected())
  {
     if (client.connect(client_id))
     {
         if (WIFI_debug_enable)
            Serial.println("mqtt broker connected");
         return true;
     }
     else
     {
         if (WIFI_debug_enable)
         {
          Serial.print("failed with state ");
          Serial.print(client.state());
         }
         if (num_of_attempts == 0)
            break;
         delay(1000);
         num_of_attempts--;
     }
 }
 
 return false;
}

bool WiFi_MQTTsend(char *topic, uint8_t mqtt_packet[], uint16_t size)
{
  if (!client.beginPublish(topic, size, false))
    return false;
  client.write(mqtt_packet, size);
  if (!client.endPublish())
    return false;
  return true;
}

bool WiFi_MQTTsubscribe(char *topic)
{
  if (!client.subscribe(topic))
    return false;
  return true;
}

bool WiFi_MQTTrecv(uint8_t *rx_buffer, uint16_t *size)
{
  uint32_t number_of_attempts = 50; // 5 seconds wait
  mqtt_rx_buffer_size = 0;
  do
  {
    client.loop();
    delay(100);
    if (--number_of_attempts == 0)
      break;
  } while(mqtt_rx_buffer_size == 0);

  *size = mqtt_rx_buffer_size;
  memcpy(rx_buffer, mqtt_rx_buffer,mqtt_rx_buffer_size);
  return true;
}


bool WiFi_TCPconnect(const char *ip, uint16_t port)
{
  uint8_t num_of_attempts = 10;
  while (!tcp.connect(ip, port))
  {
      Serial.println("Connection failed.");
      Serial.println("Waiting 1 second before retrying...");
      delay(1000);
      if (--num_of_attempts == 0)
        return false;
  }
  return true;
}

bool WiFi_TCPsend(uint8_t tcp_packet[], uint16_t size)
{
  if (tcp.write(tcp_packet, size) != size)
    return false;
  return true;
}

bool WiFi_TCPrecv(char rx_buffer[], uint16_t *size)
{
  uint32_t t0 = millis();
  while(!tcp.available() && (millis() - t0 < 5000));
  
  Serial.println(tcp.available());

  if (*size > tcp.available())
    *size = tcp.available();
  tcp.readBytes(rx_buffer, *size);
  return true;
}

void WiFi_TCPdisconnect()
{
  tcp.stop();
}

int WIFI_status()
{
  return WiFi.status();
}

void WiFi_printStatus(wl_status_t wifi_status)
{
  switch(wifi_status)
  {
    case WL_IDLE_STATUS:
      Serial.println("WL_IDLE_STATUS");
      break;
    case WL_NO_SSID_AVAIL:
      Serial.println("WL_NO_SSID_AVAIL");
      break;
    case WL_SCAN_COMPLETED:
      Serial.println("WL_SCAN_COMPLETED");
      break;
    case WL_CONNECTED:
      Serial.println("WL_CONNECTED");
      break;
    case WL_CONNECT_FAILED:
      Serial.println("WL_CONNECT_FAILED");
      break;
    case WL_CONNECTION_LOST:
      Serial.println("WL_CONNECTION_LOSTTATUS");
      break;
    case WL_DISCONNECTED:
      Serial.println("WL_DISCONNECTED");
      break;
    case WL_NO_SHIELD:
      Serial.println("WL_NO_SHIELD");
      break;
    default:
      break;
  }
}
