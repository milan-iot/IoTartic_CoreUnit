#ifndef _SD_CARD_H
#define _SD_CARD_H

#include <Arduino.h>

#include "FS.h"
//#include "SD_MMC.h"
#include "SD.h"
#include "SPI.h"

#define DEBUG_STREAM Serial

// error codes
#define SD_OK   0x00
#define SD_FAIL 0xFF

void SD_debugEnable(bool enable);
void SD_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

uint8_t SD_listDir(fs::FS &fs, const char * dirname, uint8_t levels);
uint8_t SD_createDir(fs::FS &fs, const char * path);

uint8_t SD_removeDir(fs::FS &fs, const char * path);
uint8_t SD_readFile(fs::FS &fs, const char * path);

uint8_t SD_writeFile(fs::FS &fs, const char * path, const char * message);
uint8_t SD_appendFile(fs::FS &fs, const char * path, char * message, uint16_t message_len);

uint8_t SD_createFile(fs::FS &fs, const char * path);
uint8_t SD_existsFile(fs::FS &fs, const char * path);
uint8_t SD_renameFile(fs::FS &fs, const char * path1, const char * path2);
uint8_t SD_deleteFile(fs::FS &fs, const char * path);

#endif //_SD_CARD_H