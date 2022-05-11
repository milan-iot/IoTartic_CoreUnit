#ifndef _RS485_H
#define _RS485_H

#define RS485_STREAM Serial1
#define DEBUG_STREAM Serial

#include <stdint.h>

/// RS485 modes
typedef enum {RS485_OFF, RS485_TX, RS485_RX} RS485_MODE;

/**
 * Function that enables printing of debug messages for RS485 library
 * @param enable - True if debug prints will be enabled
 * @return No return value
 */
void RS485_debugEnable(bool enable);

/**
 * Function that prints debug messages for RS485 library
 * @param title - Name of data that will be printed
 * @param data - Buffer that contains data that will be printed
 * @param data_len - Number of bytes of data that will be pritned
 * @return No return value
 */
void RS485_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

/**
 * Function that sets up RS485 communication channel
 * @param baudrate - Baud rate used in communication channel
 * @return No return value
 */
void RS485_begin(uint32_t baudrate);

/**
 * Function that stops RS485 communication channel
 * @return No return value
 */
void RS485_end();

/**
 * Function that sets mode of RS485 communication channel
 * @param mode - RS485 modes 
 * @return No return value
 */
void RS485_setMode(RS485_MODE mode);

/**
 * Function that sends data via RS485 communication channel
 * @param packet - Buffer that contains data to be sent
 * @param size - Number of bytes that need to be sent
 * @return Returns true on successful transmission
 */
bool RS485_send(uint8_t packet[], uint16_t size);

/**
 * Function that reads recieved data via RS485 communication channel
 * @param packet -  Buffer to which data will be written to
 * @param size - ???
 * @return ??
 */
bool RS485_recv(uint8_t rx_buffer[], uint16_t *size, uint32_t timeout);

#endif