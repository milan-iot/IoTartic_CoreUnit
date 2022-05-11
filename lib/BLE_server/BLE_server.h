#ifndef _BLE_SERVER_H
#define _BLE_SERVER_H

// packet related macros
#define HEADER_LENGTH 2
#define MAC_LENGTH 6
#define PAYLOAD_LENGTH 1
#define HASH_LENGTH 4

/**
 * Function that sets up Bluetooth Low Energy server
 * @param serv_uuid - Service Universally Unique Identifier, must be 16 bytes long
 * @param char_uuid - Characteristic Universally Unique Identifier, must be 16 bytes long
 **/
bool BLE_serverSetup(char *serv_uuid, char *char_uuid);

/**
 * Function that checks if there is new data recieved via BLE
 * @return Returns true if there is new data recieved via BLE
 **/
bool BLE_available();

/**
 * Function that sends data via BLE
 * @param data - Buffer that contains data to be sent
 * @param data_length - Number of bytes that need to be sent
 **/
void BLE_send(uint8_t *data, uint16_t data_length);

/**
 * Function that reads recieved data via BLE
 * @param data - Buffer to which data will be written to
 * @param data_length - ???
 * @param timeout - Time in milliseconds that function waits if there is no recieved data
 * @return ???
 **/
bool BLE_recv(char *data, uint16_t *data_length, uint32_t timeout);

/**
 * Function that gets device's BLE MAC address when BLE is NOT used
 * @param data - Buffer to which BLE MAC address will be written to
 **/
void BLE_getMACStandalone(uint8_t *data);

void BLE_debugEnable(bool enable);

void BLE_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

#endif
