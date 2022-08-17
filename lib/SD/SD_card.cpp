#include "SD_card.h"

bool SD_debug_enable = false;

void SD_debugEnable(bool enable)
{
    SD_debug_enable = enable;
}

void SD_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
{
  DEBUG_STREAM.print(String((char *)title) + ":");
  for(uint16_t i = 0; i < data_len; i++)
  {
    char str[3];
    sprintf(str, "%02x", (int)data[i]);
    DEBUG_STREAM.print(str);
  }
  DEBUG_STREAM.println();
}

uint8_t SD_listDir(fs::FS &fs, const char * dirname, uint8_t levels)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Listing directory: %s\n", dirname);

  File root = fs.open(dirname);
  if(!root)
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Failed to open directory");
    return SD_FAIL;
  }

  if(!root.isDirectory())
  {
      if (SD_debug_enable)
        DEBUG_STREAM.println("Not a directory");
      return SD_FAIL;
  }

  File file = root.openNextFile();
  while(file)
  {
      if(file.isDirectory())
      {
        DEBUG_STREAM.print("DIR : ");
        DEBUG_STREAM.println(file.name());
      
      if(levels)
      {
        SD_listDir(fs, file.name(), levels -1);
      }

      }
      else
      {
        DEBUG_STREAM.print("  FILE: ");
        DEBUG_STREAM.print(file.name());
        DEBUG_STREAM.print("  SIZE: ");
        DEBUG_STREAM.println(file.size());
      }
      file = root.openNextFile();
  }
}

uint8_t SD_createDir(fs::FS &fs, const char * path)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Creating Dir: %s\n", path);
  
  if(fs.mkdir(path))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Dir created");
  }
  else
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("mkdir failed");
    return SD_FAIL;
  }

  return SD_OK;
}

uint8_t SD_removeDir(fs::FS &fs, const char * path)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Removing Dir: %s\n", path);
  
  if(fs.rmdir(path))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Dir removed");
  }
  else
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("rmdir failed");
    return SD_FAIL;
  }
  return SD_OK;
}

uint8_t SD_readFile(fs::FS &fs, const char * path)
{
  DEBUG_STREAM.printf("Reading file: %s\n", path);

  File file = fs.open(path);
  if(!file)
  {
    DEBUG_STREAM.println("Failed to open file for reading");
    return SD_FAIL;
  }

  DEBUG_STREAM.print("Read from file: ");
  
  while(file.available())
  {
    DEBUG_STREAM.write(file.read());
  }

  file.close();
  return SD_OK;
}

uint8_t SD_writeFile(fs::FS &fs, const char * path, const char * message)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Writing file: %s\n", path);

  File file = fs.open(path, FILE_WRITE);
  if(!file)
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Failed to open file for writing");
    return SD_FAIL;
  }

  if(file.print(message))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("File written");
  }
  else
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Write failed");
    return SD_FAIL;
  }

  file.close();
  return SD_OK;
}

uint8_t SD_appendFile(fs::FS &fs, const char * path, char * message, uint16_t message_len)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Appending to file: %s\n", path);
  
  File file = fs.open(path, FILE_APPEND);
  if(!file)
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Failed to open file for appending");
    return SD_FAIL;
  }
  if(file.write((const uint8_t *)message, message_len))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Message appended");
  }
  else
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Append failed");
    file.close();
    return SD_FAIL;
  }
  file.close();
  
  return SD_OK;
}

uint8_t SD_createFile(fs::FS &fs, const char * path)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Creating file: %s\n", path);
  
  if(fs.exists(path))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("File already exists");
    return SD_FAIL;
  }
  
  File file = fs.open(path, FILE_WRITE);
  file.close();

  return SD_OK;
}

uint8_t SD_existsFile(fs::FS &fs, const char * path)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Checking existance of file: %s\n", path);
  
  if(fs.exists(path))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("File exists");
  }
  else
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("File does not exist");
    return SD_FAIL;
  }
  return SD_OK;
}

uint8_t SD_renameFile(fs::FS &fs, const char * path1, const char * path2)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Renaming file %s to %s\n", path1, path2);
  
  if (fs.rename(path1, path2))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("File renamed");
  }
  else
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Rename failed");
    return SD_FAIL;
  }

  return SD_OK;
}

uint8_t SD_deleteFile(fs::FS &fs, const char * path)
{
  if (SD_debug_enable)
    DEBUG_STREAM.printf("Deleting file: %s\n", path);
  
  if(fs.remove(path))
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("File deleted");
  }
  else
  {
    if (SD_debug_enable)
      DEBUG_STREAM.println("Delete failed");
    return SD_FAIL;
  }
  return SD_OK;
}