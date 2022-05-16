#include "RTOS_utils.h"

static QueueHandle_t server_sensor_queue;
bool RTOS_debug_enable = false;

void RTOS_debugEnable(bool enable)
{
  RTOS_debug_enable = enable;
}

void RTOS_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
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

void RTOS_init()
{
  // create queue for sensor-server task communication
  server_sensor_queue = xQueueCreate(CORE_SENSOR_QUEUE_SIZE, sizeof(serverPacket_s));
}

uint8_t RTOS_createTask(TASK_TYPE type, void *params, int16_t stack_size, int8_t priority)
{
  if (type == CORE_ACTUATOR)
  {
    xTaskCreate(
            actuatorCommunicationTask,                           // Function that should be called
            "actuatorCommunicationTask",                         // Name of the task (for debugging)
            stack_size,                                          // Stack size (bytes) // bilo: 20000
            (void *)params,                                      // Parameter to pass
            priority,                                            // Task priority // bilo: 1
            NULL                                                 // Task handle
            );
  }
  else if (type == CORE_SENSOR)
  {
    xTaskCreate(
              sensorCommunicationTask,                           // Function that should be called
              "sensorCommunicationTask",                         // Name of the task (for debugging)
              stack_size,                                        // Stack size (bytes) // bilo: 20000
              (void *)params,                                    // Parameter to pass
              priority,                                          // Task priority // bilo: 1
              NULL                                               // Task handle
              );
  }
  else if (type == CORE_SERVER)
  {
    xTaskCreate(
                serverCommunicationTask,                           // Function that should be called
                "serverCommunicationTask",                         // Name of the task (for debugging)
                stack_size,                                        // Stack size (bytes) // bilo: 6000
                (void *)params,                                    // Parameter to pass
                priority,                                          // Task priority // bilo: 2
                NULL                                               // Task handle
              );
  }
  else
  {
    return RTOS_BAD_TYPE;
  }

  return RTOS_OK;
}

// task definitions
void serverCommunicationTask(void *parameter)
{
  uint8_t ret;
  serverPacket_s serverPacket;
  static int16_t day_old, day_new;

  // set variables
  SDU_getDay(&day_old);
  SDU_getDay(&day_new);

  for(;;)
  {
    vTaskDelay(10 / portTICK_PERIOD_MS);

    // check connectivity status
    if (SDU_checkConnectivity((*(serverCommunicationTaskParams_s *)parameter).sdu_s) != SDU_OK)
        while(SDU_setup((*(serverCommunicationTaskParams_s *)parameter).sdu_s) != SDU_OK)
          vTaskDelay(5000 / portTICK_PERIOD_MS);

    if((*(serverCommunicationTaskParams_s *)parameter).json_c->comm_mode == ENCRYPTED_COMM)
    {
      // check if IV should be updated (each day)
      SDU_getDay(&day_new);

      if(day_old != day_new)
      {
        // updating IV
        ret = SDU_updateIV((*(serverCommunicationTaskParams_s *)parameter).sdu_s);
        if (RTOS_debug_enable)
          SDU_debugPrintError(ret);
        
        // handshaking
        ret = SDU_handshake((*(serverCommunicationTaskParams_s *)parameter).sdu_s);
        if (RTOS_debug_enable)
          SDU_debugPrintError(ret);
        
        // save to old value
        if (ret == SDU_OK)
          day_old = day_new;
      }
    }

    // collect data from queue (if not empty)
    if(xQueueReceive(server_sensor_queue, (void *) &serverPacket, (TickType_t)10))
    { 
      if (RTOS_debug_enable)
        RTOS_debugPrint((int8_t *)"collected from queue", serverPacket.packet, serverPacket.packet_len);

      ret = SDU_sendData((*(serverCommunicationTaskParams_s *)parameter).sdu_s, serverPacket.packet, serverPacket.packet_len);
      if (RTOS_debug_enable)
        SDU_debugPrintError(ret);
    }
  }
}

void sensorCommunicationTask(void * parameter)
{
  uint8_t packet[256];
  uint16_t packet_len;
  serverPacket_s serverPacket;

  for(;;)
  {
    vTaskDelay(10 / portTICK_PERIOD_MS);
    
    // init
    packet_len = 0;
    memset(packet, 0x00, sizeof(packet));

    if ((*(sensorCommunicationTaskParams_s *)parameter).json_c->local_tunnel == BLE)
    {
        if(LDU_waitForData((*(sensorCommunicationTaskParams_s *)parameter).ldu_s, packet, &packet_len, 5000) != LDU_OK)
          DEBUG_STREAM.println("LDU_waitForData ERROR");
        
        if (RTOS_debug_enable)
          RTOS_debugPrint((int8_t *)"packet received from sensor", packet, packet_len);

        // copy packet length
        serverPacket.packet_len = packet_len;
        // copy packet data
        memcpy(serverPacket.packet, packet, packet_len);

        xQueueSend(server_sensor_queue, (void *)&serverPacket, (TickType_t) 0);
    }
  }
}

void actuatorCommunicationTask(void * parameter)
{
    // to do...
    for(;;)
    {
      vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}