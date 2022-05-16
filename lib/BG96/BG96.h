#ifndef __BG96
#define __BG96

#include <Arduino.h>

#define SERVER_IP "95.179.159.100"
#define UDP_PORT  2345

#define MQTT_URL "95.179.159.100"

//#define _TELENOR_SRB
//#define _VIP

#ifdef _TELENOR_SRB
#define APN      "internet"
#define APN_USER  "telenor"
#define APN_PASS  "gprs"
#endif

#ifdef _VIP
#define APN     "vip.iot"
#define APN_USER  ""
#define APN_PASS  ""
#endif

void BG96_debugEnable(bool enable);
bool BG96_turnOn();
bool BG96_nwkRegister(char *apn, char *apn_user, char *apn_password);
bool BG96_TxRxUDP(char payload[], char server_IP[], uint16_t port);
bool BG96_TxRxSensorData(char server_IP[], uint16_t port, uint8_t payload[], uint8_t len);

bool BG96_turnGpsOn();
bool BG96_getGpsFix();
bool BG96_getGpsPosition(char position[]);

// to be done
bool BG96_setAwsCredential(String crd, String filename);
void BG96_MQTTconfigureSSL(char ClientID[]);

void BG96_serialBridge();

/**
 * Function that check if device is connected on network
 * @return Returns true if connected, false if not
 */
bool BG96_checkConnectivity();

// UDP functions
/**
 * Function that opens UDP socket
 * @return Returns true on success
 */
bool BG96_OpenSocketUDP();

/**
 * Function that sends data via UDP
 * @param server_IP - Server IP address
 * @param port - Server port
 * @param payload - Pointer to array of bytes to be sent
 * @param len - Number of bytes to be sent
 * @return Returns true on success
 */
bool BG96_SendUDP(char server_IP[], uint16_t port, uint8_t payload[], uint8_t len);

/**
 * Function that reads recieved data via UDP
 * @param payload - Pointer to array of bytes to which data will be written
 * @param output_len - Maximum number of recieved bytes. If number of recieved bytes 
 * is smaller then expected, len will be updated.
 * @return Returns true on success
 */
bool BG96_RecvUDP(uint8_t *output, uint16_t *output_len);

/**
 * Function that closes UDP socket
 * @return Returns true on success
 */
bool BG96_CloseSocketUDP();

// TCP functions
/**
 * Function that opens TCP socket
 * @param server_IP - Server IP address
 * @param port - Server port
 * @return Returns true on success
 */
bool BG96_OpenSocketTCP(char server_IP[], uint16_t port);

/**
 * Function that sends data via TCP
 * @param payload - Pointer to array of bytes to be sent
 * @param len - Number of bytes to be sent
 * @return Returns true on success
 */
bool BG96_SendTCP(uint8_t payload[], uint8_t len);

/**
 * Function that reads recieved data via TCP
 * @param payload - Pointer to array of bytes to which data will be written
 * @param output_len - Maximum number of recieved bytes. If number of recieved bytes 
 * is smaller then expected, len will be updated.
 * @return Returns true on success
 */
bool BG96_RecvTCP(uint8_t *output, uint16_t *output_len);

/**
 * Function that closes TCP socket
 * @return Returns true on success
 */
bool BG96_CloseSocketTCP();

// MQTT functions
/**
 * Function that establishes connection to MQTT broker
 * @param client_id - Device's MQTT ID
 * @param broker - Broker with whom connection is established
 * @param port - Broker's port
 * @return Returns true on success
 */
bool BG96_MQTTconnect(char client_id[], char broker[], int port);

/**
 * Function that subscribes to MQTT topic
 * @param topic_to_sub - Topic to which device subscribes
 * @return Returns true on success
 */
bool BG96_MQTTsubscribe(char topic_to_sub[]);

/**
 * Function that publishes data to MQTT topic
 * @param topic_to_pub - Topic to which device publishes data
 * @param payload - Array of bytes to be published
 * @param len - Number of bytes to be sent
 * @return Returns true on success
 */
bool BG96_MQTTpublish(char *topic_to_pub, uint8_t *payload, uint8_t len);

/**
 * Function that collects data recieved from subscribed topic via MQTT
 * @param output - Pointer to array of bytes to which data will be written
 * @param output_len - Maximum number of recieved bytes. If number of recieved bytes 
 * is smaller then expected, len will be updated.
 * @return Returns true on success
 */
void BG96_MQTTcollectData(uint8_t *output, uint16_t *output_len);

/**
 * Function that disconnects from MQTT broker
 * @return Returns true on success
 */
bool BG96_MQTTdisconnect(void);

#endif