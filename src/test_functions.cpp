#include <Arduino.h>
#include "test_functions.h"

#include "test_functions.h"
#include "sdu.h"
/*
void test_communication(uint8_t test_type, uint8_t *gateaway_mac)
{
  SDU_struct comm_params;
  char *key = "secretKey";
  // UDP
  if (test_type == 0)
  {
    uint8_t ret;
    SDU_debugEnable(true);
    SDU_init(&comm_params, ENCRYPTED_COMM, UDP, SERVER_IP, 58089, "io3t", "SecretPassword", "ecdh", (uint8_t*) gateaway_mac, key);
    ret = SDU_updateIV(&comm_params);
    SDU_debugPrintError(ret);
    ret = SDU_handshake(&comm_params);
    SDU_debugPrintError(ret);

    uint8_t sensor_data[128];

    memset(sensor_data, 0x48, 64);

    ret = SDU_sendData(&comm_params, sensor_data, 64);
    SDU_debugPrintError(ret);

    while(1);
  }
  else if (test_type == 1)
  {
    // topic = iot3_sensors_test + mac
    uint8_t ret;
    char topic_to_subscribe[64];
    memcpy(topic_to_subscribe, "io3t_sensors_test/nodes/", strlen("io3t_sensors_test/nodes/"));
    for(uint8_t i= 0; i < 6; i++)
    {
        char str[3];
        sprintf(topic_to_subscribe + strlen("io3t_sensors_test/nodes/") + 2*i, "%02x", (int)gateaway_mac[i]);
    }

    topic_to_subscribe[strlen("io3t_sensors_test/nodes/") + 12] = 0;

    Serial.print("topic: ");

    for(uint8_t i= 0; i< sizeof(topic_to_subscribe); i++)
    {
        char str[3];
        sprintf(str, "%02x", (int)topic_to_subscribe[i]);
        Serial.print(str);
    }
    Serial.println();
    
    SDU_debugEnable(true);
    SDU_init(&comm_params, ENCRYPTED_COMM, MQTT, SERVER_IP, 1883, "io3t", "SecretPassword", "ecdh", (uint8_t*) gateaway_mac, key);
    SDU_setMQTTparams(&comm_params, "eb8bf6c0-3212-11ea-8221-599f77add413", "io3t_sensors_test/server", (char *)topic_to_subscribe);
    ret = SDU_updateIV(&comm_params);
    SDU_debugPrintError(ret);
    ret = SDU_handshake(&comm_params);
    SDU_debugPrintError(ret);
    uint8_t sensor_data[128];

    memset(sensor_data, 0x48, 64);
    ret = SDU_sendData(&comm_params, sensor_data, 64);
    SDU_debugPrintError(ret);

    while(1);
  }
  else if (test_type == 2)
  {
    // TEST UDP VIA WIFI
    uint8_t ret;

    WiFI_debugEnable(true);
    SDU_debugEnable(true);
    SDU_init(&comm_params, ENCRYPTED_COMM, WIFI_UDP, SERVER_IP, 58089, "io3t", "SecretPassword", "ecdh", (uint8_t*) gateaway_mac, key);
    SDU_setWIFIparams(&comm_params, "Test", "12344321");
    
    ret = SDU_updateIV(&comm_params);
    SDU_debugPrintError(ret);
    ret = SDU_handshake(&comm_params);
    SDU_debugPrintError(ret);

    uint8_t sensor_data[128];

    memset(sensor_data, 0x48, 64);

    ret = SDU_sendData(&comm_params, sensor_data, 64);
    SDU_debugPrintError(ret);

    while(1);
  }
  else if (test_type == 3)
  {
    // TEST MQTT VIA WIFI
    uint8_t ret;
    char topic_to_subscribe[64];
    memcpy(topic_to_subscribe, "io3t_sensors_test/nodes/", strlen("io3t_sensors_test/nodes/"));
    for(uint8_t i= 0; i < 6; i++)
    {
        char str[3];
        sprintf(topic_to_subscribe + strlen("io3t_sensors_test/nodes/") + 2*i, "%02x", (int)gateaway_mac[i]);
    }
    topic_to_subscribe[strlen("io3t_sensors_test/nodes/") + 12] = 0;

    WiFI_debugEnable(true);
    SDU_debugEnable(true);
    SDU_init(&comm_params, ENCRYPTED_COMM, WIFI_MQTT, SERVER_IP, 1883, "io3t", "SecretPassword", "ecdh", (uint8_t*) gateaway_mac, key);
    SDU_setWIFIparams(&comm_params, "Test", "12344321");
    SDU_setMQTTparams(&comm_params, "eb8bf6c0-3212-11ea-8221-599f77add413", "io3t_sensors_test/server", (char *)topic_to_subscribe);
    
    ret = SDU_updateIV(&comm_params);
    SDU_debugPrintError(ret);
    ret = SDU_handshake(&comm_params);
    SDU_debugPrintError(ret);

    uint8_t sensor_data[128];
    memset(sensor_data, 0x48, 64);
    ret = SDU_sendData(&comm_params, sensor_data, 64);
    SDU_debugPrintError(ret);

    while(1);
  }


}
*/
