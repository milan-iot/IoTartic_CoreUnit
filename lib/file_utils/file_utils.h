#ifndef _FILE_UTILS_H
#define _FILE_UTILS_H

#include "FS.h"
#include "SPIFFS.h"

/* You only need to format SPIFFS the first time you run a
   test or else use the SPIFFS plugin to create a partition
   https://github.com/me-no-dev/arduino-esp32fs-plugin */
#define FORMAT_SPIFFS_IF_FAILED true

/**
 * Function that lists content of directory
 * @param fs - File sistem
 * @param dirname - Name of directory for which content is listed
 * @param levels - Maximum number of subdirectory layers to be listed
 **/
void FS_listDir(fs::FS &fs, const char * dirname, uint8_t levels);

/**
 * Function that reads file from file system
 * @param fs - File system
 * @param path - Path to file that neads to be read
 * @param output_buffer - Buffer in which content of file is written to
 * @return Number of characters read from file
 **/
int16_t FS_readFile(fs::FS &fs, const char * path, char output_buffer[]);

/**
 * Function that writes data in file
 * @param fs - File system
 * @param path - Path to file that data will be written in
 * @param message - Data that will be written in file
 **/
void FS_writeFile(fs::FS &fs, const char * path, const char * message);

/**
 * Function that appends data to content of file 
 * @param fs - File system
 * @param path - Path to file that data will be appended in
 * @param message - Data that will be appended to content of file
 **/
void FS_appendFile(fs::FS &fs, const char * path, const char * message);

/**
 * Function that renames file
 * @param fs - File system
 * @param path1 - Current name of the file
 * @param path2 - New name of the file
 **/
void FS_renameFile(fs::FS &fs, const char * path1, const char * path2);

/**
 * Function that deletes file
 * @param fs - File system
 * @param path - File that needs to be deleted
 **/
void FS_deleteFile(fs::FS &fs, const char * path);

/**
 * Function that sets up File system
 **/
bool FS_setup();

#endif