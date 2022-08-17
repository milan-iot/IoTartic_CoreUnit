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
#include "SD_card.h"
#include "FS.h"
#include <FOTA.h>
#include <SD_MMC.h>
#include <SD.h>

// ---------------------------------------------------------------------------
// SD MMC
#define DEST_FS_USES_SD_MMC
#include <ESP32-targz.h>
// filesystem object will be available as "tarGzFS"
// ---------------------------------------------------------------------------

#include <bspatch.h>

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
uint8_t gateaway_mac[6] = {0x84, 0xcc, 0xa8, 0x7a, 0x39, 0x2e};

uint8_t fw_version[7] = {0x07, 0xe6, 0x07, 0x10, 0x0a, 0x29, 0x0c};

void setup()
{
  Serial.begin(115200);
  Serial.println("------");
  Serial.println("--- Main Unit ---");
  Serial.println("------");

  uint8_t ret; 
  
  /*
  SPIClass spi = SPIClass(HSPI)
  /*
  if (!SD.begin(15 , spi, 80000000))
  /*{
    Serial.println("Not mounted");
    while(1);
  }

  Serial.println("Mounted");
  while(1);
  */

  //SD_debugEnable(false);

  RGB_LED_init();
  RGB_LED_setSaturation(32);
  FS_setup();

  // read configuration
  char json[1024];
  FS_readFile(SPIFFS, "/config.json", json);
  
  DynamicJsonDocument doc(1024);
  deserializeJson(doc, json);
  getJsonConfig(&config, &doc);

  //RS485_begin(115200);


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

  Crypto_debugEnable(false);
  BG96_debugEnable(false);
  SDU_debugEnable(true);
  FOTA_debugEnable(true);
  //Crypto_debugEnable(false);
/*
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
  */

  //communication test
  // setup part for encrypted communication
  //uint8_t ret;

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

  //WiFi_setup("Test", "12344321");

  SDU_setup(&server_comm_params);
  
  if(config.comm_mode == ENCRYPTED_COMM)
  {
    ret = SDU_updateIV(&server_comm_params);
    SDU_debugPrintError(ret);
    ret = SDU_handshake(&server_comm_params);
    SDU_debugPrintError(ret);
  }
  


  SPIClass spi = SPIClass(HSPI);
  spi.begin(14 /* SCK */, 12 /* MISO */, 13 /* MOSI */, 15 /* SS */);

  if (!SD.begin(15 /* SS */, spi, 80000000))
  {
    Serial.println("Not mounted");
    while(1);
  }

  /*
  if (!SD_MMC.begin())
  {
    Serial.println("Not mounted");
    while(1);
  }*/
  
  // delete files
  SD_deleteFile(SD, "/firmware.bin");
  SD_deleteFile(SD, "/tmp/fw_patch.tar.gz");
  SD_deleteFile(SD, "/tmp/fw_patch.bin");


  uint32_t t_start = 0;
  uint32_t t_end = 0;

  // merenje 1
  t_start = millis();
  ret = FOTA_pullCode(&server_comm_params);
  SDU_debugPrintError(ret);
  t_end = millis();

  Serial.println("Pull code time: " + String(t_end - t_start));

  // merenje 2
  t_start = millis();
  TarGzUnpacker *TARGZUnpacker = new TarGzUnpacker();

  TARGZUnpacker->haltOnError( true ); // stop on fail (manual restart/reset required)
  TARGZUnpacker->setTarVerify( true ); // true = enables health checks but slows down the overall process
  TARGZUnpacker->setupFSCallbacks( targzTotalBytesFn, targzFreeBytesFn ); // prevent the partition from exploding, recommended
  TARGZUnpacker->setGzProgressCallback( BaseUnpacker::defaultProgressCallback ); // targzNullProgressCallback or defaultProgressCallback
  TARGZUnpacker->setLoggerCallback( BaseUnpacker::targzPrintLoggerCallback  );    // gz log verbosity
  TARGZUnpacker->setTarProgressCallback( BaseUnpacker::defaultProgressCallback ); // prints the untarring progress for each individual file
  TARGZUnpacker->setTarStatusProgressCallback( BaseUnpacker::defaultTarStatusProgressCallback ); // print the filenames as they're expanded
  TARGZUnpacker->setTarMessageCallback( BaseUnpacker::targzPrintLoggerCallback ); // tar log verbosity
  
  if( !TARGZUnpacker->tarGzExpander(SD, "/tmp/fw_patch.tar.gz", SD, "/tmp", nullptr) ) {
    Serial.printf("tarGzExpander+intermediate file failed with return code #%d\n", TARGZUnpacker->tarGzGetError());
  }

  bspatch_fw(1579968L, 1580080L);

  t_end = millis();
  Serial.println("Patch time: " + String(t_end - t_start));

  //Serial.println("before update");

  if (ret == FOTA_OK)
  {
    t_start = millis();
    FOTA_updateFromSD(SD);
    t_end = millis();
    Serial.println("Update time: " + String(t_end - t_start));

    ESP.restart();
  }
  
  while(1);



  /*
  // check for new firmware
  while(1)
  {
    ret = FOTA_pullCode(&server_comm_params);

    Serial.println(ret, HEX);

    if (ret == FOTA_OK)
      ESP.restart();
      //FOTA_updateFromSD(SD_MMC);

    delay(10000);
  }

  while(1);
  */

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
  //BG96_debugEnable(false);

  

  // create task for core-server communication
  RTOS_createTask(CORE_SERVER, &serverCommunicationTaskParams, (uint32_t)25000L, 1);

  // create task for core-sensor communication
  RTOS_createTask(CORE_SENSOR, &sensorCommunicationTaskParams, 6000, 2);

  // create task for core-actuator communication
  RTOS_createTask(CORE_ACTUATOR, NULL, 5000, 3);

  Serial.println("Init done...");
}

void loop()
{
  while(RTOS_takeSem() != RTOS_OK)
    vTaskDelay(50 / portTICK_PERIOD_MS);

  RTOS_deinit();

  if (!SD_MMC.begin())
  {
    Serial.println("Not mounted");
    while(1);
  }

  uint8_t ret = FOTA_OK;//FOTA_pullCode(&server_comm_params);
  Serial.println(ret, HEX);

  TarGzUnpacker *TARGZUnpacker = new TarGzUnpacker();

  TARGZUnpacker->haltOnError( true ); // stop on fail (manual restart/reset required)
  TARGZUnpacker->setTarVerify( true ); // true = enables health checks but slows down the overall process
  TARGZUnpacker->setupFSCallbacks( targzTotalBytesFn, targzFreeBytesFn ); // prevent the partition from exploding, recommended
  TARGZUnpacker->setGzProgressCallback( BaseUnpacker::defaultProgressCallback ); // targzNullProgressCallback or defaultProgressCallback
  TARGZUnpacker->setLoggerCallback( BaseUnpacker::targzPrintLoggerCallback  );    // gz log verbosity
  TARGZUnpacker->setTarProgressCallback( BaseUnpacker::defaultProgressCallback ); // prints the untarring progress for each individual file
  TARGZUnpacker->setTarStatusProgressCallback( BaseUnpacker::defaultTarStatusProgressCallback ); // print the filenames as they're expanded
  TARGZUnpacker->setTarMessageCallback( BaseUnpacker::targzPrintLoggerCallback ); // tar log verbosity

  // or without intermediate file
  if( !TARGZUnpacker->tarGzExpander(SD_MMC, "/tmp/fw_patch.tar.gz", SD_MMC, "/tmp", nullptr) ) {
    Serial.printf("tarGzExpander+intermediate file failed with return code #%d\n", TARGZUnpacker->tarGzGetError());
  }

  bspatch_fw(1579968L, 1580080L);

  if (ret == FOTA_OK)
  {
    FOTA_updateFromSD(SD_MMC);
    ESP.restart();
  }
}
