#include <Arduino.h>
#include <sdu.h>
#include <SD_card.h>
#include "FOTA.h"

#include <Update.h>

// utility functions
uint8_t FOTA_updateFromFS(fs::FS &fs, int8_t *file_path);
uint8_t FOTA_performUpdate(Stream &updateSource, size_t updateSize);

bool FOTA_debug_enable = false;

void FOTA_debugEnable(bool enable)
{
  FOTA_debug_enable = enable;
}

void FOTA_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
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

void FOTA_convert32BytesToArray(uint32_t input, uint8_t output[4])
{
    output[0] = input & 0xff;
    output[1] = (input >> 8) & 0xff;
    output[2] = (input >> 16) & 0xff;
    output[3] = (input >> 24) & 0xff;
}

uint8_t FOTA_checkNewVersion(SDU_struct *comm_params)
{
  uint8_t ret;
  FOTA_Info_struct info;

  Serial.println("CHECK NEW VERSION");

  CRC8 crc;
  crc.setPolynome(CRC8_DEFAULT_VALUE);
 
  ret = SDU_fotaGetInfo(comm_params, &info);

  if (FOTA_debug_enable)
    SDU_debugPrintError(ret);

  if (ret != SDU_OK)
    return ret;
  
  uint64_t code_version_server_var = 0; 
  
  for (int i = 0; i < 7; i++)
    code_version_server_var |= info.code_version[i] << 8*i;

  uint8_t code_version_local[7];
  uint64_t code_version_local_var = 0;

  for (int i = 0; i < 7; i++)
    code_version_local[i] = EEPROM.read(CODE_VERSION_ADDRESS + i);

  FOTA_debugPrint((int8_t *)"code version local", code_version_local, 7);
  FOTA_debugPrint((int8_t *)"code version server", info.code_version, 7);
  
  for (int i = 0; i < 7; i++)
    code_version_local_var |= code_version_local[i] << 8*i;

  if (code_version_server_var == code_version_local_var)
  {
    return FOTA_ALREADY_NEWEST_VERSION;
  }

  return FOTA_OK;
}

uint8_t FOTA_pullCode(SDU_struct *comm_params)
{
  uint8_t ret;
  FOTA_Info_struct info;
  uint8_t code[1096];
  uint16_t code_len;
  uint8_t address[4];
  uint8_t num_of_bytes[4];

  Serial.println("PULL CODE");

  CRC8 crc;
  crc.setPolynome(CRC8_DEFAULT_VALUE);
  
  ret = SD_existsFile(SD, FW_PATH);
  if(ret == SD_OK)
  {
    ret = SD_deleteFile(SD, FW_PATH);
    if (ret != SD_OK)
      return ret;
  }
  
  //Serial.println("test0");

  ret = SD_createFile(SD, FW_PATH);
  if(ret != SD_OK)
    return ret;
  
  //Serial.println("test1");

  ret = SDU_fotaGetInfo(comm_params, &info);

  //Serial.println("test2");

  if (FOTA_debug_enable)
    SDU_debugPrintError(ret);

  if (ret != SDU_OK)
    return ret;
  
  //Serial.println("test3");

  uint64_t code_version_server_var = 0;
  
  for (int i = 0; i < 7; i++)
    code_version_server_var |= info.code_version[i] << 8*i;

  uint8_t code_version_local[7];
  uint64_t code_version_local_var = 0;

  for (int i = 0; i < 7; i++)
    code_version_local[i] = EEPROM.read(CODE_VERSION_ADDRESS + i);

  FOTA_debugPrint((int8_t *)"code version local", code_version_local, 7);
  FOTA_debugPrint((int8_t *)"code version server", info.code_version, 7);
  
  for (int i = 0; i < 7; i++)
    code_version_local_var |= code_version_local[i] << 8*i;

  if (code_version_server_var == code_version_local_var)
  {
    return FOTA_ALREADY_NEWEST_VERSION;
  }

 /* uint8_t valid_fw = EEPROM.read(VALID_FIRMWARE_ADDRESS);
  if (valid_fw == 0x00)
  {
    return FOTA_ALREADY_NEWEST_VERSION; 
  }

  if (code_version_server_var != code_version_local_var)
  {
    for (int i = 0; i < 7; i++)
    {
      EEPROM.write(CODE_VERSION_ADDRESS + i, info.code_version[i]);
      EEPROM.commit();
    }

    EEPROM.write(VALID_FIRMWARE_ADDRESS, 0x01);
    EEPROM.commit();
  }*/

  uint32_t address_start = (info.code_start_address[3] << 24) | (info.code_start_address[2] << 16) | (info.code_start_address[1] << 8) | (info.code_start_address[0]);
  uint32_t address_var = address_start;

  FOTA_convert32BytesToArray(address_var, address);

  uint32_t num_of_bytes_info = (info.code_length[3] << 24) | (info.code_length[2] << 16) | (info.code_length[1] << 8) | (info.code_length[0]);
  uint32_t num_of_bytes_var = 1024;

  FOTA_convert32BytesToArray(num_of_bytes_var, num_of_bytes);

  //bool vrednost = Update.begin(num_of_bytes_info);

  while(address_var < address_start + num_of_bytes_info)
  {
    vTaskDelay(10 / portTICK_PERIOD_MS);

    if (FOTA_debug_enable)
    {
      DEBUG_STREAM.println(address_var);
      DEBUG_STREAM.println(num_of_bytes_var);
    }
    
    uint8_t num_of_attempts = 10;

    do {
      ret = SDU_fotaGetCode(comm_params, address, num_of_bytes, code, &code_len);
      SDU_debugPrintError(ret);

      if (FOTA_debug_enable)
        SDU_debugPrintError(ret);

      num_of_attempts--;
    } while ((ret != SDU_OK) && (num_of_attempts > 0));

    //Serial.println("test4");

    if (ret != SDU_OK)
      return ret;

    crc.add((uint8_t*)code, num_of_bytes_var);

    //Serial.println("test5");

    SD_appendFile(SD, FW_PATH, (char *)code, num_of_bytes_var);

    //Serial.println("test6");

    //Update.write(code, num_of_bytes_var);

    if(num_of_bytes_var < 1024)
      break;

    address_var += num_of_bytes_var;

    if (address_var + num_of_bytes_var >= address_start + num_of_bytes_info)
    {
      num_of_bytes_var = num_of_bytes_info + address_start - address_var;
      FOTA_convert32BytesToArray(num_of_bytes_var, num_of_bytes);
    }
    
    FOTA_convert32BytesToArray(address_var, address);
  }

  if (FOTA_debug_enable)
  {
    DEBUG_STREAM.println("CRC8 calculated: " + String(crc.getCRC()));
    DEBUG_STREAM.println("CRC8 received: " + String(info.code_crc));
  }

  if (crc.getCRC() == info.code_crc)
  {
      //Update.end(true);
      return FOTA_OK;
  }
  else
    return FOTA_ERROR;
}

uint8_t FOTA_updateFromSD(fs::FS &fs)
{
  return FOTA_updateFromFS(fs, (int8_t *)FW_PATH_NEW);
}


uint8_t FOTA_performUpdate(Stream &updateSource, size_t updateSize)
{ 
   if (Update.begin(updateSize))
   {
      size_t written = Update.writeStream(updateSource);

      if (written == updateSize)
      {
        if (FOTA_debug_enable)
          DEBUG_STREAM.println("Written : " + String(written) + " successfully");
      }
      else
      {
        if (FOTA_debug_enable)
          DEBUG_STREAM.println("Written only : " + String(written) + "/" + String(updateSize) + ". Retry?");
        return FOTA_ERROR;
      }
      
      if (Update.end())
      {
         if (FOTA_debug_enable)
          DEBUG_STREAM.println("OTA done!");

         if (Update.isFinished())
         {
            if (FOTA_debug_enable)
              DEBUG_STREAM.println("Update successfully completed. Rebooting.");
            return FOTA_OK;
         }
         else
         {
            if (FOTA_debug_enable)
              DEBUG_STREAM.println("Update not finished? Something went wrong!");
            return FOTA_ERROR;
         }
      }
      else
      {
        if (FOTA_debug_enable)
          DEBUG_STREAM.println("Error Occurred. Error #: " + String(Update.getError()));
        return FOTA_ERROR;
      }
   }
   else
   {
    if (FOTA_debug_enable)
      DEBUG_STREAM.println("Not enough space to begin OTA");
    return FOTA_ERROR;
   }
}

// check given FS for valid update.bin and perform update if available
uint8_t FOTA_updateFromFS(fs::FS &fs, int8_t *file_path)
{
   uint8_t ret = FOTA_ERROR;
   File updateBin = fs.open((char *)file_path);

   if (updateBin)
   {
      if(updateBin.isDirectory())
      {
        if (FOTA_debug_enable)
          DEBUG_STREAM.println("Error, update.bin is not a file");
        updateBin.close();
        return FOTA_ERROR;
      }

      size_t updateSize = updateBin.size();

      if (updateSize > 0)
      {
        if (FOTA_debug_enable)
          DEBUG_STREAM.println("Try to start update");
        ret = FOTA_performUpdate(updateBin, updateSize);
      }
      else
      {
        if (FOTA_debug_enable)
          DEBUG_STREAM.println("Error, file is empty");
      }

      updateBin.close();
   }
   else
   {
    if (FOTA_debug_enable)
      DEBUG_STREAM.println("Could not load update.bin from sd root");
    return FOTA_ERROR;
   }

  if (ret == FOTA_OK)
    //ESP.restart();
    return FOTA_OK;
  else
    return FOTA_ERROR;
}