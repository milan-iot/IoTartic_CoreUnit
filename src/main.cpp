#include <Arduino.h>

#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include <WiFi.h>
#include <ESP32Time.h>
#include <BG96.h>
#include <RS485.h>
#include <sensors.h>
#include <RGB_LED.h>
#include <BLE_server.h>
#include <file_utils.h>
#include <sdu.h>
#include <ldu.h>
#include <test_functions.h>
#include <json.h>
#include <RTOS_utils.h>

// packet
//uint8_t packet[6 + sizeof(sensor_data_hashed)];
uint8_t packet[128];
uint16_t packet_len;

uint8_t mac_wifi[6];
uint8_t mac_sensor[6];

//-----------
json_config config;
SDU_struct server_comm_params;
LDU_struct local_comm_params;
char topic_to_subscribe[64];
uint8_t gateaway_mac[6];

void GPS_test(void)
{
  //GPS test
  char position[64], str[64];
  RGB_LED_setColor(RED);
  BG96_turnGpsOn();
  BG96_getGpsFix();
  RGB_LED_setColor(GREEN);
  uint16_t counter = 0;
  
  while(1)
  {
    if (BG96_getGpsPosition(position))
    {
      sprintf(str, "#%d: %s\r\n", ++counter, position);
      Serial.print(str);
      return;
    }
    else
      BG96_getGpsFix();
    delay(3000);
  }
}

void GetMacAddress()
{
  //https://techtutorialsx.com/2018/03/09/esp32-arduino-getting-the-bluetooth-device-address/
  btStart();
  esp_bluedroid_init();
  esp_bluedroid_enable();

  Serial.print("BLE MAC Address:  ");
  const uint8_t* point = esp_bt_dev_get_address();
  for (int i = 0; i < 6; i++)
  {
    char str[3];
   
    sprintf(str, "%02X", (int)point[i]);
    Serial.print(str);
    if (i < 5)
      Serial.print(":");
  }
  Serial.println();
  
  String mac = WiFi.macAddress();

  Serial.print("WiFi MAC Address: ");
  Serial.println(mac);

  for (int i = 0; i < 6; i++)
  {
    uint8_t hi, lo;
    char c = mac.charAt(3 * i);
    hi = c > '9' ? c - 'A' + 10 : c - '0';
    c = mac.charAt(3 * i + 1);
    lo = c > '9' ? c - 'A' + 10 : c - '0';
    mac_wifi[i] = (hi << 4) | lo;
    packet[i] = mac_wifi[i];
  }
}

void setup()
{
  Serial.begin(115200);
  Serial.println("--- Main Unit ---");

  RGB_LED_init();
  RGB_LED_setSaturation(32);
  FS_setup();

  // read configuration
  char json[1024];
  FS_readFile(SPIFFS, "/config.json", json);
  
  DynamicJsonDocument doc(1024);
  deserializeJson(doc, json);
  getJsonConfig(&config, &doc);

  RS485_begin(115200);

  /*while(1)
  {

      while (digitalRead(0));
      RS485_setMode(RS485_TX);

      if (!RS485_send((uint8_t *)"READ", strlen("READ")))
        Serial.println("SEND ALL");
      //for (int i = 0; i < 4; i++)
       // RS485_STREAM.write('T');

      delay(100);

      RS485_setMode(RS485_RX);
      RS485_recv(packet, &packet_len);
  }*/


  // BLE setup
  if (config.local_tunnel == BLE)
  {
    LDU_setBLEParams(&local_comm_params, config.serv_uuid, config.char_uuid, config.ble_password);
    LDU_getServerMac(&local_comm_params, gateaway_mac);

    LDU_init(&local_comm_params);
  }
  else if (config.local_tunnel == RS485)
  {
    LDU_setBLEParams(&local_comm_params, config.serv_uuid, config.char_uuid, config.ble_password);
    LDU_setRS485Params(&local_comm_params, 115200);

    LDU_init(&local_comm_params);

    LDU_getServerMac(&local_comm_params, gateaway_mac);
  }
  
  //communication test
  // setup part for encrypted communication
  uint8_t ret;
  
  SDU_debugEnable(true);
  SDU_init(&server_comm_params, config.comm_mode, config.protocol, config.server_tunnel, (char *) config.ip, config.port, (uint8_t*) gateaway_mac);
  
  if (config.protocol == MQTT)
  {
     memcpy(topic_to_subscribe, (char *) config.subscribe_topic, strlen((char *) config.subscribe_topic));
     for(uint8_t i= 0; i < 6; i++)
     {
        char str[3];
        sprintf(topic_to_subscribe + strlen((char *) config.subscribe_topic) + 2*i, "%02x", (int)gateaway_mac[i]);
     }

    topic_to_subscribe[strlen((char *) config.subscribe_topic) + 12] = 0;
    SDU_setMQTTparams(&server_comm_params, (char *) config.client_id, (char *) config.publish_topic, (char *)topic_to_subscribe);
  }

  if (config.server_tunnel == BG96)
  {
    SDU_setBG96params(&server_comm_params, (char *) config.apn, (char *) config.apn_user, (char *) config.apn_password);
  }
  
  if (config.server_tunnel == WIFI)
  {
    SDU_setWIFIparams(&server_comm_params, (char *) config.wifi_ssid, (char *) config.wifi_pass);
  }

  if (config.comm_mode == ENCRYPTED_COMM)
  { 
    SDU_setEncryptionParams(&server_comm_params, (char *) config.server_salt, (char *)config.server_password);
  }

  SDU_setup(&server_comm_params);

  if(config.comm_mode == ENCRYPTED_COMM)
  {
    ret = SDU_updateIV(&server_comm_params);
    SDU_debugPrintError(ret);
    ret = SDU_handshake(&server_comm_params);
    SDU_debugPrintError(ret);
  }

  // set server task communication params
  serverCommunicationTaskParams_s serverCommunicationTaskParams;
  serverCommunicationTaskParams.sdu_s = &server_comm_params;
  serverCommunicationTaskParams.json_c = &config;

  // set sensor task communication params
  sensorCommunicationTaskParams_s sensorCommunicationTaskParams;
  sensorCommunicationTaskParams.ldu_s = &local_comm_params;
  sensorCommunicationTaskParams.json_c = &config;

  // init RTOS functions
  RTOS_init();

  // create task for core-server communication
  RTOS_createTask(CORE_SERVER, &serverCommunicationTaskParams, 20000, 1);

  // create task for core-sensor communication
  RTOS_createTask(CORE_SENSOR, &sensorCommunicationTaskParams, 6000, 2);

  // create task for core-actuator communication
  RTOS_createTask(CORE_ACTUATOR, NULL, 5000, 3);

  //GPS_test();
}

void loop()
{
  delay(100);
}
