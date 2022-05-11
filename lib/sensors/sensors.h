#ifndef _SENSORS_H
#define _SENSORS_H

typedef struct sensors_config
{
  //air parameters
  bool air_temp;
  bool air_hum;
  bool air_pres;
  //soil parameters
  bool soil_temp_1;
  bool soil_temp_2;
  bool soil_moist_1;
  bool soil_moist_2;
  //luminosity
  bool lum;
} sensors_config;

typedef struct
{
  //air parameters
  int16_t air_temp;
  int16_t air_hum;
  int32_t air_pres;
  //soil parameters
  int16_t soil_temp_1;
  int16_t soil_temp_2;
  int8_t soil_moist_1;
  int8_t soil_moist_2;
  //luminosity
  uint16_t lum;
} sensor_data;

typedef struct
{
  // sensor data mac
  uint8_t mac[6];
  // sensor data
  sensor_data sd;
  // hash
  uint8_t hash[32];
} sensor_data_hashed;

void formUDPpacket(sensor_data_hashed sd, uint8_t *udp_packet);
void printSensorData(sensor_data sd);

#endif
