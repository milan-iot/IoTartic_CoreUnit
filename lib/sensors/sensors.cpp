#include <Arduino.h>
#include "sensors.h"

void formUDPpacket(sensor_data_hashed sd, uint8_t *udp_packet)
{
  // copy mac
  memcpy(udp_packet, sd.mac, sizeof(sd.mac));

  // copy data
  memcpy(udp_packet + sizeof(sd.mac), &sd.sd, sizeof(sd.sd));

  // copy hash
  memcpy(udp_packet + sizeof(sd.mac) + sizeof(sd.sd), sd.hash, sizeof(sd.hash));
}

void printSensorData(sensor_data sd)
{
  String s;
  
  //BH1750FVI
  Serial.println("*** BH1750FVI ***");
  Serial.println("\tL = " + (String)(sd.lum) + " lux");
  
  // DS18B20
  Serial.println("*** DS18B20 ***");
  Serial.println("\tT = " + (String)(sd.soil_temp_1 / 100) + "." + (String)(sd.soil_temp_1 % 100) + " C");
  Serial.println("\tT = " + (String)(sd.soil_temp_2 / 100) + "." + (String)(sd.soil_temp_2 % 100) + " C");

  // Soil moisture
  Serial.println("*** Soil moisture ***");
  Serial.println("\tH = " + (String)sd.soil_moist_1 + " %");
  Serial.println("\tH = " + (String)sd.soil_moist_2 + " %");

  // BME280
  Serial.println("*** BME280 ***");
  Serial.println("\tH = " + String(sd.air_hum / 100) + "." + (String)(sd.air_hum % 100) + " \%");
  Serial.println("\tT = " + String(sd.air_temp / 100) + "." + (String)(sd.air_temp % 100) + " C");
  Serial.println("\tP = " + String(sd.air_pres / 100) + "." + (String)(sd.air_pres % 100) + " mBar");
}
