#include <Arduino.h>
#include "RS485.h"

//RS-485 pins
#define RE  25
#define DE  33

#define RS485_RX_ON  digitalWrite(RE, LOW)  //receiver enable (active LOW)
#define RS485_RX_OFF digitalWrite(RE, HIGH)
#define RS485_TX_ON  digitalWrite(DE, HIGH) //driver enable (active HIGH)
#define RS485_TX_OFF digitalWrite(DE, LOW)

bool RS485_debug_enable = false;

void RS485_debugEnable(bool enable)
{
  RS485_debug_enable = enable;
}

void RS485_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
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


void RS485_begin(uint32_t baudrate)
{
  RS485_STREAM.begin(baudrate, SERIAL_8N1, 26, 32); //RXD1=26, TXD1=32
  //RS485_setMode(mode);
}

void RS485_end()
{
  RS485_STREAM.end();
}

void RS485_setMode(RS485_MODE mode)
{
  switch (mode)
  {
    case RS485_OFF:
      pinMode(RE, INPUT);
      pinMode(DE, INPUT);
      break;
    case RS485_TX:
      pinMode(RE, OUTPUT);
      pinMode(DE, OUTPUT);
      RS485_RX_OFF;
      RS485_TX_ON;
      break;
    case RS485_RX:
      pinMode(RE, OUTPUT);
      pinMode(DE, OUTPUT);
      RS485_RX_ON;
      RS485_TX_OFF;
      break;
  }
}

bool RS485_send(uint8_t packet[], uint16_t size)
{
  if (RS485_STREAM.write(packet, size) != size)
  {
    RS485_STREAM.flush();
    return false;
  }
  RS485_STREAM.flush();
  return true;
}

bool RS485_recv(uint8_t rx_buffer[], uint16_t *size, uint32_t timeout)
{
  uint32_t t0 = millis();
  while (!RS485_STREAM.available() && (millis() - t0) < timeout);
  delay(100);

  if (*size > RS485_STREAM.available())
    *size = RS485_STREAM.available();
 
  if (*size != 0)
  {
    RS485_STREAM.readBytes(rx_buffer, *size);
    rx_buffer[*size] = 0;
  }

  if (RS485_debug_enable)
  {
    RS485_debugPrint((int8_t *) "rs485 rec", (uint8_t *) rx_buffer, *size);
  }

  return true;
}


// from old main
void dummy()
{
  //TODO: RS-485 code
  /*while (!RS485.available());
  delay(50);

  if (RS485.available() == sizeof(sensor_data))
  {
    LED_setColor(BLUE);

    //read sensor data from the serial buffer
    uint8_t *ptr = &packet[6];
    for (uint8_t i = 0; i < sizeof(sensor_data); i++)
    {
      *ptr = RS485.read();
      ptr++;
    }
    sensor_data *sd = (sensor_data *)(&packet[6]);
    printSensorData(*sd);
    BG96_TxRxSensorData(SERVER_IP, 58088, packet, sizeof(packet));
    
    LED_setColor(BLACK); 
  }*/

//  String cmd = RS485.readString();
//  Serial.println(cmd);
}

