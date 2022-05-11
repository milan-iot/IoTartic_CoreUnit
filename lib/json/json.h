#ifndef _JSON_H
#define _JSON_H

#include <ArduinoJson.h>
#include <stdint.h>
#include "sdu.h"
#include "ldu.h"

// Types of devices in network
typedef enum {
    CORE,
    SENSOR
} DEVICE_TYPE;

/// Configuration structure to be initialized from config.json file
typedef struct {
    // Type of device
    DEVICE_TYPE device_type;
    // Sensor dependency on communication to server
    //      1 - Direct communication to server
    //      0 - Communication to server via Core device
    bool standalone;

    // type of communication in terms of security
    COMM_MODE comm_mode;

    // type of tunnel
    SERVER_TUNNEL_MODE server_tunnel;
    LOCAL_TUNNEL_MODE local_tunnel;

    // WiFi security parameters
    char wifi_ssid[32];
    char wifi_pass[32];

    // BG96 parameters
    char apn[32];
    char apn_user[32];
    char apn_password[32];

    // type of protocol and server parameters
    PROTOCOL_MODE protocol;
    char ip[32];
    uint16_t port;
    
    // mqtt topics
    char subscribe_topic[64];
    char publish_topic[64];
    char client_id[64];

    // BLE parameters
    char serv_uuid[40];
    char char_uuid[40];

    // Encryption parameters
    char server_salt[32];
    char server_password[32];
    char ble_password[32];
} json_config;

/**
 * Function that parses configuration from config json document
 * @param jc - Pointer to json_config structure to be created
 * @param config - Pointer to json document from which configuration should be parsed
 * @return Returns true on succesful parse
**/
bool getJsonConfig(json_config *jc, DynamicJsonDocument *config);

#endif