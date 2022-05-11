#ifndef _RTOS_UTILS_H
#define _RTOS_UTILS_H

#include <Arduino.h>
#include <RGB_LED.h>
#include <json.h>
#include <sdu.h>

typedef enum {CORE_SERVER, CORE_SENSOR, CORE_ACTUATOR} TASK_TYPE;

#define DEBUG_STREAM Serial

#define CORE_SENSOR_QUEUE_SIZE 10
#define CORE_ACTUATOR_QUEUE_SIZE 10

// error codes
#define RTOS_OK           0x00
#define RTOS_BAD_TYPE     0xB0

typedef struct serverCommunicationTaskParams_s {
  SDU_struct *sdu_s;
  json_config *json_c;
} serverCommunicationTaskParams_s;

typedef struct sensorCommunicationTaskParams_s {
  LDU_struct *ldu_s;
  json_config *json_c;
} sensorCommunicationTaskParams_s;

typedef struct serverPacket_s {
  uint8_t packet[128];
  uint16_t packet_len;
} serverPacket_s;

// private
void serverCommunicationTask(void * parameter);
void sensorCommunicationTask(void * parameter);
void actuatorCommunicationTask(void * parameter);

// public
void RTOS_debugEnable(bool enable);
void RTOS_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

void RTOS_init();
uint8_t RTOS_createTask(TASK_TYPE type, void *params, int16_t stack_size, int8_t priority);


#endif