#ifndef _RTOS_UTILS_H
#define _RTOS_UTILS_H

#include <Arduino.h>
#include <RGB_LED.h>
#include <json.h>
#include <sdu.h>
#include <FOTA.h>

typedef enum {CORE_SERVER, CORE_SENSOR, CORE_ACTUATOR} TASK_TYPE;

#define DEBUG_STREAM Serial

/// queue sizes
#define CORE_SENSOR_QUEUE_SIZE 10
#define CORE_ACTUATOR_QUEUE_SIZE 10

/// error codes
#define RTOS_OK           0x00
#define RTOS_BAD_TYPE     0xB0
#define RTOS_SEM_ERROR    0x01

/// communication structures
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

// private functions
void serverCommunicationTask(void * parameter);
void sensorCommunicationTask(void * parameter);
void actuatorCommunicationTask(void * parameter);

// public functions
/**
 * Function that enable RTOS serial debbuging
 * @return No return value
 */
void RTOS_debugEnable(bool enable);

/**
* Debug function that prints data in the following format:
* title: data bytes
* @param title - string used to entitle data
* @param data - array of bytes to be printed
* @param data_len - number of data bytes to be printed
* @return no return value
*/
void RTOS_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

/**
 * Function that initializes all things required for RTOS
 * @return No return value
 */
void RTOS_init();

/**
 * Function that creates and runs RTOS task as configured through parameters
 * @param type - type of task to be created (CORE_SERVER, CORE_SENSOR, CORE_ACTUATOR)
 * @param params - task parameteres
 * @param stack_size - size of stack to be allocated for given task
 * @param priority - task priority (1,2,3...)
 * @return Error code
 */
uint8_t RTOS_createTask(TASK_TYPE type, void *params, uint32_t stack_size, int8_t priority);

uint8_t RTOS_takeSem();

void RTOS_deinit();

#endif