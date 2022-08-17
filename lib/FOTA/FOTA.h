#ifndef _FOTA_H
#define _FOTA_H

#define DEBUG_STREAM Serial

#include <Update.h>
#include <FS.h>
//#include <SD_MMC.h>
#include <EEPROM.h>
#include <stdint.h>

#define FW_PATH "/tmp/fw_patch.tar.gz"
#define FW_PATH_NEW "/firmware.bin"

#define CODE_VERSION_ADDRESS 0x00
#define VALID_FIRMWARE_ADDRESS 0x07

#define FOTA_OK 0x00
#define FOTA_ERROR 0x01
#define FOTA_ALREADY_NEWEST_VERSION 0x02

/**
 * Function that enable FOTA serial debbuging
 * @return No return value
 */
void FOTA_debugEnable(bool enable);

/**
* Debug function that prints data in the following format:
* title: data bytes
* @param title - string used to entitle data
* @param data - array of bytes to be printed
* @param data_len - number of data bytes to be printed
* @return no return value
*/
void FOTA_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

/**
* Function that communicates with server and checks new version of firmware to be updated
* @param comm_params - pointer to communication structure that will be used
* @return error code
*/
uint8_t FOTA_checkNewVersion(SDU_struct *comm_params);

/**
* Function that communicates with server and pulls new version of firmware to be updated
* @param comm_params - pointer to communication structure that will be used
* @return error code
*/
uint8_t FOTA_pullCode(SDU_struct *comm_params);

/**
* Function that updates flash memory of microcontroller
* @param title - string used to entitle data
* @return error code
*/
uint8_t FOTA_updateFromSD(fs::FS &fs);

#endif // _FOTA_H