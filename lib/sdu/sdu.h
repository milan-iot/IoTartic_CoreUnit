// Server Data Update (SDU) library
#ifndef _SDU_H
#define _SDU_H

/// used libraries
#include <Arduino.h>
#include <ESP32Time.h>
#include "CRC8.h"
#include "crypto_utils.h"
#include "BG96.h"
#include "sensors.h"
#include "WiFi_client.h"

/// communication mode type
typedef enum {NON_ENCRYPTED_COMM, ENCRYPTED_COMM} COMM_MODE;
/// protocol mode type
typedef enum {UDP, MQTT, TCP} PROTOCOL_MODE;
/// network mode type
typedef enum {BG96, WIFI} SERVER_TUNNEL_MODE;

/*
    Sensor Data Update structure
    Note: Used for storing main parameters needed for communication
*/
/// Sensor Data Update structure (Used for storing main parameters needed for communication)
typedef struct
{
    COMM_MODE mode_of_work; // type of communication in terms of security
    PROTOCOL_MODE type_of_protocol; // type of protocol
    SERVER_TUNNEL_MODE type_of_tunnel; // type of tunnel
    // MQTT
    char *client_id; // client id in case of using MQTT protocol (sets using set function)
    char *topic_to_subs; // topic to subscribe in case of using MQTT protocol (sets using set function)
    char *topic_to_pub; // topic to publish in case of using MQTT protocol (sets using set function)
    // BG96
    char *apn; // access point name in case of usage of BG96
    char *apn_user; // access point name username in case of usage of BG96
    char *apn_pass; // access point name password in case of usage of BG96
    // WIFI
    char *ssid; // ssid in case of usage of wifi connection
    char *pass; // pass in case of usage of wifi connection
    // UDP
    char *server_IP; // server ip address
    uint16_t port; // port
    char *hmac_salt; // salt for hmac function
    char *password; // password used for encrypted eke communication
    char *personalization_info; // salt for random number generator
    uint8_t *device_mac; // device mac address
    char *BLE_password; // password for ble communication
} SDU_struct;


#define CODE_VERSION_LEN 7
#define CODE_START_ADDRESS_LEN 4
#define CODE_LENGTH_LEN 4
#define CODE_CRC_LEN 1

typedef struct
{
    uint8_t code_version[7];
    uint8_t code_start_address[4];
    uint8_t code_length[4];
    uint8_t code_crc;
} FOTA_Info_struct;


/// CRC polynomial value definition
#define CRC8_DEFAULT_VALUE           0x07

/// client headers
#define DATE_REQUEST_HEADER         0x5452
#define CLIENT_HELLO_HEADER         0x4348
#define CLIENT_VERIFY_HEADER        0x4356
#define SENSOR_ENC_DATA_HEADER      0x5345
#define SENSOR_DATA_HEADER          0x5350
#define FOTA_INFO_REQUEST_HEADER    0xF152
#define FOTA_CODE_REQUEST_HEADER    0xFC52

// server headers
#define DATE_UPDATE_HEADER          0x5455
#define SERVER_HELLO_HEADER         0x5348             
#define SERVER_VERIFY_HEADER        0x5356
#define ERROR_CODE_HEADER           0x4552
#define SENSOR_RESPONSE_HEADER      0x5352
#define FOTA_INFO_RESPONSE_HEADER   0xF144
#define FOTA_CODE_RESPONSE_HEADER   0xFC44

/// error packets (sent by server)
#define S_PACKET_OK                   0x00
#define S_INVALID_MAC                 0xA0
#define S_INVALID_HEADER              0xA1
#define S_INVALID_NUM_OF_BYTES        0xA2
#define S_INTEGRITY_ERROR             0xA3
#define S_VERIFICATION_ERROR          0xA4
#define S_INVALID_NUM_OF_BYTES_SENS   0xB0
#define S_FORMAT_ERROR                0xB1
#define S_SUCCESS                     0xCC

// BLE error code
//#define BLE_INVALID_AUTH              0xBA

/// error codes (produced by bad usage of functions locally or incorrect server packets)
#define SDU_OK                       0x00

#define SERVER_ERROR(x) (SERVER_ERROR_BASE + x)
#define LOCAL_ERROR(x) (LOCAL_ERROR_BASE + x)

#define SERVER_ERROR_BASE              0xD0
#define LOCAL_ERROR_BASE               0xE0

#define INVALID_HEADER                0x00
#define INVALID_NUM_OF_BYTES          0x01
#define INTEGRITY_ERROR               0x02

#define CRYPTO_FUNC_ERROR             0xCF
#define BG96_ERROR                    0x96
#define WIFI_ERROR                    0x97
#define BAD_COMM_STRUCTURE            0xBC

/// packet lengths on core side
#define MAC_LENGTH                  6
#define CLIENT_HELLO_DATA_LENGTH    64
#define CLIENT_VERIFY_DATA_LENGTH   32
#define HEADER_LENGTH               2
#define DATA_LENGTH                 1
#define CRC8_LENGTH                 1

/// packet lengths on server side
#define SERVER_HELLO_LENGTH     80
#define SERVER_VERIFY_LENGTH    16
#define DATE_UPDATE_LEN         16
#define ERROR_CODE_LENGTH       1
#define SENSOR_RESPONSE_LENGTH  1
#define INFO_RESPONSE_LEN       16
#define CODE_RESPONSE_LEN       16

// offsets
#define PUBLIC_KEY_OFFSET       64

/**
* Debug enable function
* @param enable - parameter used for enabling debug 
* @return no return value
*/
void SDU_debugEnable(bool enable);
/**
* Debug function that prints data in the following format:
* title: data bytes
* @param title - string used to entitle data
* @param data - array of bytes to be printed
* @param data_len - number of data bytes to be printed
* @return no return value
*/
void SDU_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);
/**
* Debug functions used to print error codes 
* @param error_code - error code to be printed 
* @return no return value
*/
void SDU_debugPrintError(uint8_t error_code);

// main functions
/**
* Function used to initialize communication structure. Should be called first. 
* @param comm_params - pointer to communication structure that will be used
* @param mode_of_work - value that represents mode of communication (encrypted or non-encrypted/plaintext)
* @param type_of_protocol - value that represents protocol (UDP, TCP, MQTT) to be used
* @param type_of_tunnel - value that represents communication channel (BG96(NB-IoT) or WIFI) to be used
* @param server_IP - pointer to server IP address
* @param port - port number to be used
* @param device_mac - mac address of CORE device
* @return - no return value
*/
void SDU_init(SDU_struct *comm_params, COMM_MODE mode_of_work, PROTOCOL_MODE type_of_protocol, SERVER_TUNNEL_MODE type_of_tunnel, char server_IP[], uint16_t port, uint8_t *device_mac);
/**
* Function used to establish network registration according to communication channel (BG96 or WIFI). Should be called after SDU_init() and set functions.
* @param comm_params - pointer to communication structure that will be used
* @return - error code
*/
uint8_t SDU_setup(SDU_struct *comm_params);

/**
* Function used to check network connectivity status
* @param comm_params - pointer to communication structure that will be used
* @return - error code
*/
uint8_t SDU_checkConnectivity(SDU_struct *comm_params);

/**
* Function used to update IV seed according to documentation. Should be called before SDU_handshake() function.
* @param comm_params - pointer to communication structure that will be used
* @return - error code
*/
uint8_t SDU_updateIV(SDU_struct *comm_params);

/**
 * Function that returns day value of RTC
 * @param day - pointer to variable that stores day number
 * @return - error code 
 */
uint8_t SDU_getDay(int16_t *day);

/**
 * Function that returns hour value of RTC
 * @param hay - pointer to variable that stores hour number
 * @return - error code
 */
uint8_t SDU_getHour(int16_t *hour);

/**
 * Function that returns minute value of RTC
 * @param hay - pointer to variable that stores minute number
 * @return - error code
 */
uint8_t SDU_getMinute(int16_t *minute);

/**
* Function used to perform handshake in case of encrypted communication. It uses DH-EKE (Diffie-Hellman encrypted key exchange) scheme and stores shared secret in internal data buffer.
* @param comm_params - pointer to communication structure
* @return - error code
*/
uint8_t SDU_handshake(SDU_struct *comm_params);
/**
* Function used to send data according to parameteres in communication structure.
* @param comm_params - pointer to communication structure that will be used
* @param raw_data - pointer to array of bytes to be sent
* @param raw_data_len - length of bytes to be sent
* @return - error code
*/
uint8_t SDU_sendData(SDU_struct *comm_params, uint8_t *raw_data, uint16_t raw_data_len);


uint8_t SDU_fotaGetInfo(SDU_struct *comm_params, FOTA_Info_struct *info_s);

uint8_t SDU_fotaGetCode(SDU_struct *comm_params, uint8_t address[4], uint8_t num_of_bytes[4], uint8_t *code, uint16_t *code_len);


/**
* Function used set MQTT parameters in communication. Should be used after SDU_init() function and before SDU_updateIV(), SDU_handshake() and SDU_sendData() functions in case of encrypted communication.
* @param comm_params - pointer to communication structure that will be used
* @param client_id - pointer to string that represents client id
* @param topic_to_pub - pointer to string that represents topic to publish
* @param topic_to_subs - pointer to string that represents topic to be subscribed on
* @return - error code
*/
uint8_t SDU_setMQTTparams(SDU_struct *comm_params, char *client_id, char *topic_to_pub, char *topic_to_subs);
/**
* Function used set BG96 parameters in communication. Should be used after SDU_init() function and before SDU_updateIV(), SDU_handshake() and SDU_sendData() functions.
* @param comm_params - pointer to communication structure that will be used
* @param apn - pointer to string that represents access point name for network (APN)
* @param apn_user - pointer to string that access point name for network username
* @param apn_pass - pointer to string that access point name for network password
* @return - error code
*/
uint8_t SDU_setBG96params(SDU_struct *comm_params, char *apn, char *apn_user, char *apn_pass);
/**
* Function used set WIFI parameters in communication. Should be used after SDU_init() function and before SDU_updateIV(), SDU_handshake() and SDU_sendData() functions.
* @param comm_params - pointer to communication structure that will be used
* @param ssid - pointer to string that represents WIFI service set identifier (ssid)
* @param pass - pointer to string that represents WIFI password
* @return - error code
*/
uint8_t SDU_setWIFIparams(SDU_struct *comm_params, char *ssid, char *pass);
/**
* Function used set Encryption parameters in communication. Should be used after SDU_init() function and before SDU_updateIV(), SDU_handshake() and SDU_sendData() functions.
* @param comm_params - pointer to communication structure that will be used
* @param hmac_salt - pointer to array that represents hmac salt value used in key generation according to documentation
* @param password - pointer to array that represents shared password used in key generation according to documentation
* @return - error code
*/
uint8_t SDU_setEncryptionParams(SDU_struct *comm_params,  char *hmac_salt, char *password);
/**
* Function used to close network connection.
* @param comm_params - pointer to communication structure that will be used
* @return - no return code
*/
void SDU_end(SDU_struct *comm_params);


// utility functions
/**
* Utility function used to construct packet according to documentation.
* @param mac - MAC address of CORE device
* @param header_type - message header value for given packet
* @param in_data - pointer to bytes of (raw) data that represents useful information (according to documentation)
* @param in_data_len - length of input data (in bytes)
* @param out_data - pointer to bytes of data that stores packet constructed (according to documentation)
* @param output_length - length of output data (in bytes)
* @return - error code
*/
uint8_t SDU_constructPacket(uint8_t *mac, uint16_t header_type, uint8_t *in_data, uint8_t in_data_len, uint8_t *out_data, uint16_t *out_data_len);
/**
* Utility function used to parse packet information and returns raw bytes according to documentation.
* @param input - pointer to bytes of data that stores packet to be parsed
* @param input_length - length of input data (in bytes)
* @param output - pointer to bytes of data where parsed information (raw data without header and CRC) will be stored
* @param output_length - length of output data (in bytes) 
* @return - error code
*/
uint8_t SDU_parsePacket(uint8_t *input, uint16_t input_length, uint8_t *output, uint16_t *output_length);
/**
* Utility function that generates initialization vector (IV).
* @param iv - pointer to buffer of data where IV value will be stored
* @return - error code
*/
uint8_t SDU_genIV(uint8_t *iv);

uint8_t SDU_parseFotaInfo(uint8_t *info, FOTA_Info_struct *info_s);

uint8_t SDU_receiveProc(SDU_struct *comm_params, uint8_t *response_data, uint16_t expected_len);
uint8_t SDU_sendProc(SDU_struct *comm_params, uint8_t *data, uint16_t data_len);

#endif // _SDU_H


// to do:
// disconnect wifi on end of stage
