#ifndef _LDU_H
#define _LDU_H

#include <stdint.h>
#include "CRC32.h"
#include "crypto_utils.h"
#include "RS485.h"
#include "BLE_server.h"

#define DEBUG_STREAM Serial

/// default 32 polynomial
#define CRC32_DEFAULT_VALUE   0x04C11DB7
#define CRC32_LENGTH            0x04

/// Modes of local comunication
typedef enum {BLE, RS485} LOCAL_TUNNEL_MODE;

#define LDU_OK            0x00   

#define RS485_ERROR       0x48
#define BLE_ERROR         0xBE

#define INVALID_AUTH      0xBA

#define CRYPTO_FUNC_ERROR 0xCF
#define BAD_COM_STRUCTURE 0xBC

/// core headers
#define SENSOR_MAC_ADDRESS_REQUEST_HEADER 0x4D52
#define SENSOR_DATA_REQUEST_HEADER        0x4452
#define CORE_RESPONSE_HEADER              0x4352

/// sensor headers
#define SENSOR_MAC_ADDRESS_VALUE_HEADER   0x4D56
#define SENSOR_DATA_VALUE_HEADER          0x4456

/// packet lengths
#define HEADER_LENGTH                     2
#define HASH_LENGTH                       4
#define SENSOR_MAC_ADDRESS_VALUE_LENGTH   6
#define IDENTITY_HASH                     32

#define SERVER_ERROR(x) (SERVER_ERROR_BASE + x)
#define LOCAL_ERROR(x) (LOCAL_ERROR_BASE + x)

#define SERVER_ERROR_BASE              0xD0
#define LOCAL_ERROR_BASE               0xE0

#define INVALID_HEADER                0x00
#define INVALID_NUM_OF_BYTES          0x01
#define INTEGRITY_ERROR               0x02

/// Configuration structure for local communication
typedef struct ldu
{
   LOCAL_TUNNEL_MODE mode;
   
   // BLE parameters
   char *serv_uuid;
   char *char_uuid;
   char *ble_password;
   
   // RS485 parameters
   uint32_t rs485_baudrate;
} LDU_struct;

/**
 * Function that enables printing of debug messages for LDU library
 * @param enable - True if debug prints will be enabled
 * @return No return value
 */
void LDU_debugEnable(bool enable);

/**
 * Function that prints debug messages for LDU library
 * @param title - Name of data that will be printed
 * @param data - Buffer that contains data that will be printed
 * @param data_len - Number of bytes of data that will be pritned
 * @return No return value
 */
void LDU_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

/**
 * Function that sets parameters for BLE local communication
 * @param comm_params - Configuration structure for local communication
 * @param serv_uuid - Service Universally Unique Identifier, must be 16 bytes long
 * @param char_uuid - Characteristic Universally Unique Identifier, must be 16 bytes long
 * @param ble_password - Password used as key during HMAC derivation of digest in BLE communication
 * @return No return value
 */
void LDU_setBLEParams(LDU_struct *comm_params, char *serv_uuid, char *char_uuid, char *ble_password);

/**
 * Function that sets parameters for RS485 local communication in configuration structure
 * @param comm_params - Configuration structure for local communication
 * @param rs485_baudrate - Baud rate used in communication channel
 * @return No return value
 */
void LDU_setRS485Params(LDU_struct *comm_params, uint32_t rs485_baudrate);

/**
 * Function that sets up local communication channel
 * @param comm_params - Configuration structure for local communication
 * @return No return value
 */
uint8_t LDU_init(LDU_struct *comm_params);

/**
 * Function that closes local communication channel
 * @param comm_params - Configuration structure for local communication
 * @return No return value
 */
uint8_t LDU_deinit(LDU_struct *comm_params);

/**
 * Function that sends data via local communication channel
 * @param comm_params - Configuration structure for local communication
 * @param packet - Buffer that contains data to be sent
 * @param size - Number of bytes that need to be sent
 * @return No return value
 */
uint8_t LDU_send(LDU_struct *comm_params, uint8_t packet[], uint16_t size);

/**
 * Function that reads recieved data via local communication channel
 * @param comm_params - Configuration structure for local communication
 * @param packet -  Buffer to which data will be written to
 * @param size - ???
 * @return ???
 */
uint8_t LDU_recv(LDU_struct *comm_params, uint8_t rx_buffer[], uint16_t *size, uint32_t timeout);

uint8_t LDU_getServerMac(LDU_struct *comm_params, uint8_t *server_mac);
uint8_t LDU_checkSensorData(LDU_struct *comm_params, uint8_t *sensor_data, uint16_t sensor_data_len);

uint8_t LDU_requestDataRS485(LDU_struct *comm_params, uint8_t *sensor_data, uint16_t *sensor_data_len);


uint8_t LDU_waitForData(LDU_struct *comm_params, uint8_t *output_data, uint16_t *output_data_len, uint16_t timeout);

// deprecated
uint8_t LDU_requestMAC(LDU_struct *comm_params, uint8_t *sensor_mac, uint16_t *sensor_mac_length);

#endif
