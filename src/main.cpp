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
#include <json.h>
#include <RTOS_utils.h>

// packet
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

  BG96_debugEnable(false);

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

  serverPacket_s serverPacket;

  // init RTOS functions
  RTOS_init();
  //BG96_debugEnable(false);

  // create task for core-server communication
  RTOS_createTask(CORE_SERVER, &serverCommunicationTaskParams, 30000, 1);

  // create task for core-sensor communication
  RTOS_createTask(CORE_SENSOR, &sensorCommunicationTaskParams, 6000, 2);

  // create task for core-actuator communication
  RTOS_createTask(CORE_ACTUATOR, NULL, 5000, 3);

  Serial.println("Init done...");
}

void loop()
{
  vTaskDelay(1000 / portTICK_PERIOD_MS);
}
