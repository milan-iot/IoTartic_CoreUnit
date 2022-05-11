#ifndef _WIFI_CLIENT_H
#define _WIFI_CLIENT_H

/// used libraries
#include <WiFi.h>

/**
* Function used to connect to WIFI network.
* @param ssid - pointer to string that represents WIFI service set identifier (ssid)
* @param pass - pointer to string that represents WIFI password
* @return - true if operation is successful, otherwise false
*/
bool WiFi_setup(const char* ssid, const char* pass);
/**
* Function used to reconnect to WIFI network.
* @return - no return value
*/
void WiFi_reconnect();
/**
* Function used to disconnect from WIFI network.
* @return - no return value
*/
void WiFi_disconnect();
/**
* Function that returns connection status.
* @return - returns status code accordant to WiFi.status() function
*/
int WIFI_status();

/**
* Function used to send UDP packet.
* @param ip - pointer to peer IP address
* @param port - number of port to be used
* @param udp_packet - pointer to array of bytes to be sent
* @param size - length of bytes to be sent
* @return - true if operation is successful, otherwise false
*/
bool WiFi_UDPsend(const char* ip, uint16_t port, uint8_t udp_packet[], uint16_t size);
/**
* Function used to receive UDP packet.
* @param rx_buffer - pointer to array where bytes of received data will be stored
* @param size - length od received data
* @return - true if operation is successful, otherwise false
*/
bool WiFi_UDPrecv(char rx_buffer[], uint16_t *size);

/**
* Function used to connect to MQTT broker.
* @param broker - pointer to string that represents MQTT broker
* @param port - number of port to be used
* @param client_id - pointer to string that represents client id
* @return - true if operation is successful, otherwise false
*/
bool WiFi_MQTTconnect(char *broker, int port, char *client_id);
/**
* Function used to send MQTT packet to dedicated topic.
* @param topic - pointer to string that represents topic
* @param mqtt_packet - pointer to array of bytes to be sent
* @param size - length of bytes to be sent
* @return - true if operation is successful, otherwise false
*/
bool WiFi_MQTTsend(char *topic, uint8_t mqtt_packet[], uint16_t size);
/**
* Function used to receive MQTT packet from subscribed topic.
* @param rx_buffer - pointer to array where bytes of received data will be stored
* @param size - length od received data
* @return - true if operation is successful, otherwise false
*/
bool WiFi_MQTTrecv(uint8_t *rx_buffer, uint16_t *size);
/**
* Function used to subcribe to chosen topic.
* @param topic - pointer to string that represents topic
* @return - true if operation is successful, otherwise false
*/
bool WiFi_MQTTsubscribe(char *topic);

/**
* Function used to connect to TCP server.
* @param ip - pointer to server IP address
* @param port - number of port to be used
* @return - true if operation is successful, otherwise false
*/
bool WiFi_TCPconnect(const char *ip, uint16_t port);
/**
* Function used to send TCP packet.
* @param tcp_packet - pointer to array of bytes to be sent
* @param size - length of bytes to be sent
* @return - true if operation is successful, otherwise false
*/
bool WiFi_TCPsend(uint8_t tcp_packet[], uint16_t size);
/**
* Function used to receive TCP packet.
* @param rx_buffer - pointer to array where bytes of received data will be stored
* @param size - length od received data
* @return - true if operation is successful, otherwise false
*/
bool WiFi_TCPrecv(char rx_buffer[], uint16_t *size);
/**
* Function used to disconnect from TCP server (close socket).
* @return - no return value
*/
void WiFi_TCPdisconnect();


/**
* Utility function used to enable/disable debug prints via UART.
* @param enable - parameter used for enabling debug prints (true-enable, false-disable)
* @return - no return value
*/
void WiFI_debugEnable(bool enable);
/**
* Utility function used print status of connection.
* @param wifi_status - status of network to be printed
* @return - no return value
*/
void WiFi_printStatus(wl_status_t wifi_status);

#endif ///_WIFI_CLIENT_H
