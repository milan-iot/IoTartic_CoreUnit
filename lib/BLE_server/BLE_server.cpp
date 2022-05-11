/*
    Based on Neil Kolban example for IDF: https://github.com/nkolban/esp32-snippets/blob/master/cpp_utils/tests/BLE%20Tests/SampleServer.cpp
    Ported to Arduino ESP32 by Evandro Copercini
    updates by chegewara
    https://github.com/nkolban/ESP32_BLE_Arduino
*/

#include <Arduino.h>
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <ArduinoJson.h>

#include "BLE_server.h"
#include <RGB_LED.h>
#include <file_utils.h>
#include <crypto_utils.h>

BLECharacteristic *pCharacteristic;
bool data_received_flag = false;
bool BLE_debug_enable = false;

// See the following for generating UUIDs:
// https://www.uuidgenerator.net/

class MyServerCallbacks: public BLEServerCallbacks 
{
    void onConnect(BLEServer* pServer) 
    {
      if (BLE_debug_enable)
        DEBUG_STREAM.println("BLE Connected");
      RGB_LED_setColor(BLUE);
      delay(1000);
      RGB_LED_setColor(BLACK);
    };

    void onDisconnect(BLEServer* pServer) 
    {
      if (BLE_debug_enable)
        DEBUG_STREAM.println("BLE Disconnected");
      
      BLEDevice::startAdvertising();
      RGB_LED_setColor(PURPLE);
      delay(200);
      RGB_LED_setColor(BLACK);
    }
};

class MyCallbacks: public BLECharacteristicCallbacks 
{
  void onRead(BLECharacteristic *pCharacteristic) 
  {
    if (BLE_debug_enable)
      DEBUG_STREAM.println("BLE Read");
    
    RGB_LED_setColor(GREEN);
    delay(200);
    RGB_LED_setColor(BLACK);
  }
  
  void onWrite(BLECharacteristic *pCharacteristic) 
  {
    if (BLE_debug_enable)
      DEBUG_STREAM.println("BLE Write");
    data_received_flag = true;
    RGB_LED_setColor(RED);
    delay(200);
    RGB_LED_setColor(BLACK);
  }
};

void BLE_debugEnable(bool enable)
{
  BLE_debug_enable = enable;
}

void BLE_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
{
    DEBUG_STREAM.print(String((char *)title) + ":");
    for(uint16_t i = 0; i < data_len; i++)
    {
      char str[3];
      sprintf(str, "%02x", (int)data[i]);
      DEBUG_STREAM.print(str);
    }
    DEBUG_STREAM.println();
}


bool BLE_serverSetup(char *serv_uuid, char *char_uuid)
{
  if (BLE_debug_enable)
  {
    BLE_debugPrint((int8_t *)"serv_uuid: ", (uint8_t *)serv_uuid, 40);
    BLE_debugPrint((int8_t *)"char_uuid: ", (uint8_t *)char_uuid, 40);
  }

  BLEDevice::init("IO3T-SU");

  // Create the BLE Server
  BLEServer *pServer = BLEDevice::createServer();

  pServer->setCallbacks(new MyServerCallbacks());

  BLEService *pService = pServer->createService(serv_uuid);

  pCharacteristic = pService->createCharacteristic(
                                        char_uuid,
                                        BLECharacteristic::PROPERTY_READ |
                                        BLECharacteristic::PROPERTY_WRITE
                                      );

  pCharacteristic->setCallbacks(new MyCallbacks());

  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(serv_uuid);
  pAdvertising->setScanResponse(true);
  BLEDevice::startAdvertising();

  if (BLE_debug_enable)
    DEBUG_STREAM.println("Characteristic defined.");
  
  return true;
}

bool BLE_available()
{
  return data_received_flag;
}

void BLE_send(uint8_t *data, uint16_t data_length)
{
  pCharacteristic->setValue(data, data_length);
}

bool BLE_recv(char *data, uint16_t *size, uint32_t timeout)
{
  uint32_t t0 = millis();
  while (!data_received_flag && (millis() - t0) < timeout)
  {
    //vTaskDelay(5 / portTICK_PERIOD_MS);  
  }
  vTaskDelay(100 / portTICK_PERIOD_MS);

  if(data_received_flag)
  {
    uint8_t *rxValue = pCharacteristic->getData();
    // mac len (6B) + size(1B) + payload(size B) + header(2B)
    *size = HEADER_LENGTH + MAC_LENGTH + PAYLOAD_LENGTH + rxValue[8] + HASH_LENGTH;

    char *ptr = data;
    for (uint16_t i = 0; i < *size; i++)
    {
      *ptr = rxValue[i];
      ptr++;
    }
    data = (char *)(&rxValue[0]);

    data_received_flag = false;
  }
  else
  {
    *size = 0;
    return false;
  }

  return true;
}

void BLE_getMACStandalone(uint8_t *data)
{
  btStart();
  esp_bluedroid_init();
  esp_bluedroid_enable();
  const uint8_t* gateaway_mac = esp_bt_dev_get_address();
  esp_bluedroid_disable();
  esp_bluedroid_deinit();
  btStop();

  memcpy(data, gateaway_mac, 6);
}