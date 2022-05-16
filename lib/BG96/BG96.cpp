#include "BG96.h"
#include <crypto_utils.h>

//BG96 UART pins
#define U2RXD 16
#define U2TXD 17

#define NBIOT_STREAM  Serial2
#define DEBUG_STREAM  Serial

#define BG96_PWRKEY 27

char ca_cert[] = "-----BEGIN CERTIFICATE-----\r\n"\
"MIIDSzCCAjOgAwIBAgIUS7akZ7vdcx8zSTauu1LYPMuXGscwDQYJKoZIhvcNAQEL\r\n"\
"BQAwNTELMAkGA1UEBhMCUlMxDTALBgNVBAoMBGlvM3QxFzAVBgNVBAMMDjk1LjE3\r\n"\
"OS4xNTkuMTAwMB4XDTIxMTEyOTEzMzgwOFoXDTI2MTEyOTEzMzgwOFowNTELMAkG\r\n"\
"A1UEBhMCUlMxDTALBgNVBAoMBGlvM3QxFzAVBgNVBAMMDjk1LjE3OS4xNTkuMTAw\r\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5yFmzcWkMA/Y2hD5tGPZ\r\n"\
"dvbbeU+tDFGVUNzwRNeegtognuE5eZwDaYzGkGVa34xhxCPkG27FjKgQYri7TwCD\r\n"\
"kkrPjpBcRH9KvLQbhnjxlKTuRHlsTRw2Wzypm3dbTPqPzWfgA3ZNV1b3A7IevdS/\r\n"\
"jxCb6hlpJuuIEup+ZW6Q1mDWENGlKUTQ2CSTDY0ydt0OKXWz+vFWrkB8m3J95XXF\r\n"\
"Opmjsxaa0tnNnTnSxphm29x12b1+Y4dg32qiZpqPEX//WgDwdWhKxdgUpv2mp83T\r\n"\
"5vWJbmbjuQ19TgBf23siYQZX+4zausjGXRZFtn2/4WEaxGYP9CgEsKElioyJ6jgc\r\n"\
"TwIDAQABo1MwUTAdBgNVHQ4EFgQUK2kO2s0FBby6cDV75Fu3BxyCxoAwHwYDVR0j\r\n"\
"BBgwFoAUK2kO2s0FBby6cDV75Fu3BxyCxoAwDwYDVR0TAQH/BAUwAwEB/zANBgkq\r\n"\
"hkiG9w0BAQsFAAOCAQEA3CiryHuy2EAhtJMRi0eROS8lrN4zgtpO8QDGYMyQBzy6\r\n"\
"jadtiA5IFuHtjjiPkCDbsBak9H0/yse+Ljc3SL7S55pagsUBnBBcwLA+++lJqJMC\r\n"\
"cG2a89L2w1sTFTINZ7ebUgZSGjqd0SDgWPhejW/mKrhm8EMJC50gI+3qvvip/ruL\r\n"\
"rFb96ScT6YKGK424GDREq5mCrkPQCXZ3Dy8nfdslh4yUsS7vXdtRGEroeGuEB0Cg\r\n"\
"zVvJcc3S27mVTJfoDyBrbiTU03tbLy4Vq3ynE0vPMVJG42S99Gkvz1MZbrkNC+RF\r\n"\
"9YbpztOHw33NAIb86YGMiga1+rt18Quc9k9R/fAOYQ==\r\n"\
"-----END CERTIFICATE-----";

char password[] = "SecretPassword";

bool BG96_debug_enable = false;

const char* strcheck(const char* X, const char* Y, int  x_length);

void BG96_debugEnable(bool enable)
{
  BG96_debug_enable = enable;
}

bool getBG96response(char command[], char exp_response[], char response[], uint32_t timeout)
{
  uint8_t count = 0;
  bool resp_OK = false;

  response[0] = '\0';
  
  //DEBUG_STREAM.print(command);  
  NBIOT_STREAM.print(command);
  
  uint32_t t0 = millis();
  while ((millis() - t0) < timeout)
  {
    if (NBIOT_STREAM.available())
    {
      response[count] = NBIOT_STREAM.read();
      if (BG96_debug_enable)
        DEBUG_STREAM.write(response[count]);
      response[++count] = '\0';
    }
    else
    {
      vTaskDelay(10 / portTICK_PERIOD_MS);
    }
    if (strcheck(response, exp_response, count))
    {
      resp_OK = true;
      break;
    }
  }
  
  //delay(200);
  vTaskDelay(200 / portTICK_PERIOD_MS);
  
  while (NBIOT_STREAM.available())
  { 
    response[count] = NBIOT_STREAM.read();
    if (BG96_debug_enable)
      DEBUG_STREAM.write(response[count]);
    response[++count] = '\0';
  }
  if (BG96_debug_enable)
    DEBUG_STREAM.print("\r\n");
  
  return resp_OK;
}

bool BG96_turnOn()
{
  Serial2.begin(115200, SERIAL_8N1, U2RXD, U2TXD);

  //turn on BG96
  if (BG96_debug_enable)
    DEBUG_STREAM.print("BG96 reset...");
  
  pinMode(BG96_PWRKEY, OUTPUT);
  digitalWrite(BG96_PWRKEY, HIGH);
  delay(1000);
  digitalWrite(BG96_PWRKEY, LOW);

  if (BG96_debug_enable)
    DEBUG_STREAM.println("DONE!");
  
  char response[256];
  //  check FW version
  if (getBG96response("", "APP RDY", response, 8000))
    return true;
  return false;
}

bool BG96_nwkRegister(char *apn, char *apn_user, char *apn_password)
{
  char response[256];
  if (!getBG96response("AT+GMR\r\n", "OK", response, 1000))
    return false;
   
  //Switch the modem to minimum functionality
  if (!getBG96response("AT+CFUN=0,0\r\n", "OK", response, 5000))
    return false;

  // Verbose Error Reporting to get understandable error reporting (optional)
  if (!getBG96response("AT+CMEE=2\r\n", "OK", response, 5000))
    return false;

  //scan sequence: first NB-IoT, then GSM
  if (!getBG96response("AT+QCFG=\"nwscanseq\",0301,1\r\n", "OK", response, 1000))
    return false;
  //Automatic (GSM and LTE)
  if (!getBG96response("AT+QCFG=\"nwscanmode\",0,1\r\n", "OK", response, 1000))
    return false;
  //Network category to be searched under LTE RAT: eMTC and NB-IoT
  if (!getBG96response("AT+QCFG=\"iotopmode\",2,1\r\n", "OK", response, 1000))
    return false;

  //  turn on full module functionality
  if (!getBG96response("AT+CFUN=1,0\r\n", "OK", response, 5000))
    return false;

  //  check IMSI
  char IMSI[20];
  if (!getBG96response("AT+CIMI\r\n", "OK", response, 2000))
    return false;

//  //set APN
//  if (!getBG96response("AT+CGDCONT=1,\"IP\",\"VIP.IOT\"\r\n", "OK", response, 3000))
//    return false;

  
  //  error reporting
  if (!getBG96response("AT+CMEE=1\r\n", "OK", response, 10000))
    return false;
  
  //  automatically report network registration status
  if (!getBG96response("AT+CEREG=1\r\n", "OK", response, 3000))
    return false;

  // connect
  if (!getBG96response("AT+COPS=0\r\n", "OK", response, 5000))
    return false;

  //polling the network registration status
  bool reg_ok;
  uint8_t attempt_cnt = 0; 
  do 
  {
    reg_ok = getBG96response("AT+CGATT?\r\n", "+CGATT: 1", response, 5000);
    if (!reg_ok)
    {
      if (++attempt_cnt == 30)
        return false; 
    }
  } while (!reg_ok);

  getBG96response("AT+CSQ\r\n", "OK", response, 3000);
  getBG96response("AT+CCLK?\r\n", "OK", response, 3000);

    char cmd[128];
  sprintf(cmd, "AT+QICSGP=1,1,\"%s\",\"%s\",\"%s\",1\r\n", String(apn), String(apn_user), String(apn_password));
  if (!getBG96response(cmd, "OK", response, 3000))
    return false;

  if (!getBG96response("AT+QIACT=1\r\n", "OK", response, 3000))
    return false;

  if (!getBG96response("AT+QIACT?\r\n", "OK", response, 5000))
    return false;
  
  return true;
}

bool BG96_checkConnectivity()
{
  char response[256];
  //  automatically report network registration status
  if (!getBG96response("AT+CREG?\r\n", "OK", response, 3000))
    return false;

  char exp_response[] = "+CREG:";
  uint8_t flag, start_index = 0;
  while(start_index < 256)
  {
    flag = 1;
    for(uint8_t i = 0; i < strlen(exp_response); i++)
    {
      if(response[start_index + i] != exp_response[i])
      {
        flag = 0;
      }
    }
    if(flag == 1)
      break;

    start_index++;
  }

  start_index += 9;

  if (start_index > 255)
    return false;

  /*Serial.print("CREG vrednost: ");
  Serial.println(response[start_index]);*/

  if (response[start_index] == '1' || response[start_index] == '5')
    return true;
  else
    return false;
}

bool BG96_TxRxUDP(char payload[], char server_IP[], uint16_t port)
{
  char response[256], cmd[128];

  if (!getBG96response("AT+QIOPEN=1,2,\"UDP SERVICE\",\"127.0.0.1\",0,3030,0\r\n", "+QIOPEN: 2,0", response, 5000))
    return false;

  if (!getBG96response("AT+QISTATE=0,1\r\n", "OK", response, 3000))
    return false;

  sprintf(cmd, "AT+QISEND=2,%d,\"%s\",%d\r\n", strlen(payload), server_IP, port);
  getBG96response(cmd, ">", response, 3000);
  getBG96response(payload, "+QIURC: \"recv\",2", response, 10000);

  if (!getBG96response("AT+QIRD=2\r\n", "OK", response, 5000))
    return false;

  if (!getBG96response("AT+QICLOSE=2\r\n", "OK", response, 3000))
    return false;
  return true;
}

bool BG96_TxRxSensorData(char server_IP[], uint16_t port, uint8_t payload[], uint8_t len)
{
  char response[256], cmd[128];

  if (!getBG96response("AT+QIOPEN=1,2,\"UDP SERVICE\",\"127.0.0.1\",0,3030,0\r\n", "+QIOPEN: 2,0", response, 5000))
    return false;

  if (!getBG96response("AT+QISTATE=0,1\r\n", "OK", response, 3000))
    return false;

  sprintf(cmd, "AT+QISEND=2,%d,\"%s\",%d\r\n", len, server_IP, port);
  getBG96response(cmd, ">", response, 3000);

  for (uint8_t i = 0; i < len; i++)
    NBIOT_STREAM.write(payload[i]);
  
  //getBG96response("", "+QIURC: \"recv\",2", response, 10000);
  getBG96response("", "SEND OK", response, 10000);

  if (!getBG96response("AT+QIRD=2\r\n", "OK", response, 5000))
    return false;

  if (!getBG96response("AT+QICLOSE=2\r\n", "OK", response, 3000))
    return false;
  return true; 
}

bool BG96_OpenSocketUDP()
{
  char response[256];

  if (!getBG96response("AT+QIOPEN=1,2,\"UDP SERVICE\",\"127.0.0.1\",0,3030,0\r\n", "+QIOPEN: 2,0", response, 5000))
    return false;

  if (!getBG96response("AT+QISTATE=0,1\r\n", "OK", response, 3000))
    return false;
  
  return true;
}

bool BG96_SendUDP(char server_IP[], uint16_t port, uint8_t payload[], uint8_t len)
{
    char cmd[128], response[128];

    sprintf(cmd, "AT+QISEND=2,%d,\"%s\",%d\r\n", len, server_IP, port);
    if (!getBG96response(cmd, ">", response, 3000))
      return false;

    for (uint8_t i = 0; i < len; i++)
      NBIOT_STREAM.write(payload[i]);
    
    if (!getBG96response("", "SEND OK", response, 10000))
      return false;
      
    return true;
}

// za sada ovako, modifikovati da bude univerzalno kasnije
bool BG96_RecvUDP(uint8_t *output, uint16_t *output_len)
{
  uint16_t start_index = 0, cnt = 0;
  char response[256];

  if (!getBG96response("AT+QIRD=2\r\n", "OK", response, 5000))
    return false;

  char exp_response[] = "+QIRD:";
  uint8_t flag;
  while(1)
  {
    flag = 1;
    for(uint8_t i = 0; i < strlen(exp_response); i++)
    {
      if(response[start_index + i] != exp_response[i])
      {
        flag = 0;
      }
    }
    if(flag == 1)
      break;

    start_index++;
  }
  
  uint16_t actual_size = 0;
  while (response[start_index] != ',')
  {
      char c = response[start_index];
      if (c >= '0' && c <= '9')
      {
        actual_size = actual_size * 10 + (c - '0');
      }
      start_index++;
  }

  while(response[start_index] != 0x0a)
  {
    start_index++;
  }

  start_index++;

  //DEBUG_STREAM.println("rec.size: " + String(actual_size));

  if (actual_size < *output_len)
  {
    *output_len = actual_size;
    memcpy(output, response + start_index, *output_len);
  }
  else
  {
    memcpy(output, response + start_index, *output_len);
  }

  return true;
}

bool BG96_CloseSocketUDP()
{
    char response[128];
    if (!getBG96response("AT+QICLOSE=2\r\n", "OK", response, 3000))
      return false;
    return true;
}

bool BG96_MQTTconnect(char client_id[], char broker[], int port)
{
  char response[128], cmd[256];
  //char user[] = "node";
  
  sprintf(cmd, "AT+QMTOPEN=0,\"%s\",%d\r\n", broker, port);
  if (!getBG96response(cmd, "+QMTOPEN: 0,0", response, 5000))
  {
    BG96_MQTTdisconnect();
    return false;
  }
  
  //sprintf(cmd, "AT+QMTCONN=0,\"%s\",\"%s\",\"%s\"\r\n", client_id, user, user);
  sprintf(cmd, "AT+QMTCONN=0,\"%s\"\r\n", client_id);
  
  if (!getBG96response(cmd, "+QMTCONN: 0,0,0", response, 5000))
  {
    BG96_MQTTdisconnect();
    return false;
  }

  return true;
}

bool BG96_MQTTpublish(char *topic_to_pub, uint8_t *payload, uint8_t len)
{
  char response[128], topic[128];

  sprintf(topic, "AT+QMTPUB=0,0,0,0,\"%s\",%d\r\n", topic_to_pub, len);
  if (!getBG96response(topic, ">", response, 5000))
    return false;
  
  for (uint8_t i = 0; i < len; i++)
  {
    //char str[3];
    //sprintf(str, "%02x", payload[i]);
    //DEBUG_STREAM.println(str);
    //Serial.println(payload[i]);
    NBIOT_STREAM.write(payload[i]);
  }
  if (!getBG96response("\x1a", "+QMTPUB: 0,0,0", response, 5000))
    return false;

  return true;
}

bool BG96_MQTTsubscribe(char topic_to_sub[])
{
  char response[128], cmd[256];
  
  sprintf(cmd, "AT+QMTSUB=0,1,\"%s\",0\r\n", topic_to_sub);
  if (!getBG96response(cmd, "OK", response, 5000))
    return false;

  return true;
}

void BG96_MQTTcollectData(uint8_t *output, uint16_t *output_len)
{
  uint8_t count = 0;
  char response[256];

  uint32_t t0 = millis();
  while ((millis() - t0) < 5000)
  { 
    if (NBIOT_STREAM.available())
    {
      response[count] = NBIOT_STREAM.read();
      if (BG96_debug_enable)
        DEBUG_STREAM.write(response[count]);
      response[++count] = '\0';
    }
    else
    {
      vTaskDelay(5 / portTICK_PERIOD_MS);      
    }
  }
  if (BG96_debug_enable)
    DEBUG_STREAM.print("\r\n");

  char exp_response[] = "+QMTRECV:";
  uint16_t start_index = 0;
  uint8_t flag;

  //t0 = millis();
  //while((millis() - t0) < 15000)
  while(start_index < 256)
  {
    flag = 1;
    for(uint8_t i = 0; i < strlen(exp_response); i++)
    {
      if(response[start_index + i] != exp_response[i])
      {
        flag = 0;
      }
    }

    if(flag == 1)
      break;
    
    start_index++;
    //if(start_index == 256)
      //return;
  }
 
  uint16_t end_response = count;
  count = 0;
  while(count != 3)
  {
    if (response[start_index] == ',')
      count++;
    
    start_index++;
    if (start_index == 256)
      break;
  }

  start_index++;

  memcpy(output, response + start_index, *output_len);
  if (BG96_debug_enable)
    DEBUG_STREAM.println((char *)output);
}


bool BG96_MQTTdisconnect(void)
{
  char response[64];
  
  if (!getBG96response("AT+QMTDISC=0\r\n", "+QMTDISC: 0,0", response, 5000))
    return false;
  
  return true;
}


bool BG96_OpenSocketTCP(char server_IP[], uint16_t port)
{
  char response[256], cmd[256];
  
  sprintf(cmd, "AT+QIOPEN=1,0,\"TCP\",\"%s\",%d,0,0\r\n", server_IP, port);

  if (!getBG96response(cmd, "+QIOPEN: 0,0", response, 5000))
  {
    BG96_CloseSocketTCP();
    return false;
  }

  if (!getBG96response("AT+QISTATE=1,0\r\n", "OK", response, 3000))
    return false;
  
  return true;
}

bool BG96_SendTCP(uint8_t payload[], uint8_t len)
{
  char cmd[128], response[128];

  sprintf(cmd, "AT+QISEND=0,%d\r\n", len);
  if (!getBG96response(cmd, ">", response, 3000))
    return false;

  for (uint8_t i = 0; i < len; i++)
    NBIOT_STREAM.write(payload[i]);
  
  if (!getBG96response("", "SEND OK", response, 10000))
    return false;
    
  return true;
}

bool BG96_RecvTCP(uint8_t *output, uint16_t *output_len)
{
  uint16_t start_index = 0, cnt = 0;
  char response[256], cmd[128];

  sprintf(cmd, "AT+QIRD=0,%d\r\n", *output_len);
  if (!getBG96response(cmd, "OK", response, 5000))
    return false;

  char exp_response[] = "+QIRD:";
  uint8_t flag;
  while(1)
  {
    flag = 1;
    for(uint8_t i = 0; i < strlen(exp_response); i++)
    {
      if(response[start_index + i] != exp_response[i])
      {
        flag = 0;
      }
    }
    if(flag == 1)
      break;

    start_index++;
    if(start_index == 256)
      return false;
  }

  uint16_t actual_size = 0;
  start_index += strlen("+QIRD: ");

  while (response[start_index] >= '0' && response[start_index] <= '9')
  {
      char c = response[start_index];
      actual_size = actual_size * 10 + (c - '0');
      start_index++;
      if(start_index == 256)
        return false;
  }

  while(response[start_index] != 0x0a)
  {
    start_index++;
    if(start_index == 256)
      return false;
  }

  start_index++;

  if (actual_size < *output_len)
  {
    *output_len = actual_size;
    memcpy(output, response + start_index, *output_len);
  }
  else
  {
    memcpy(output, response + start_index, *output_len);
  }

  return true;
}

bool BG96_CloseSocketTCP()
{
  char response[128];
 
  if (!getBG96response("AT+QICLOSE=0\r\n", "OK", response, 10000))
  {
    if (!getBG96response("AT+QICLOSE=0\r\n", "OK", response, 10000))
    {
      return false;
    }
  }
  return true;
}




bool BG96_setAwsCredential(String crd, String filename)
{
   char response[64], cmd[2048];

   String Cmd = "AT+QFUPL=\"" + filename + "\"," + String(crd.length())+",100\r\n";
   Cmd.toCharArray(cmd, Cmd.length());
   getBG96response(cmd, "CONNECT", response, 6000);

   crd += "\r\n";
   crd.toCharArray(cmd, crd.length());
   getBG96response(cmd, "OK", response, 6000);
   return true;
}

void BG96_MQTTconfigureSSL(char ClientID[])
{
  char response[32], cmd[1300];
  
  // configure session in ssl mode
  sprintf(cmd, "AT+QMTCFG=\"SSL\",0,1,2\r\n");
  getBG96response(cmd, "OK", response, 10000);

  // ssl cert load
  sprintf(cmd, "AT+QFUPL=\"cacert.pem\", %d, 100\r\n", strlen(ca_cert));
  getBG96response(cmd, "CONNECT", response, 5000);

  for (uint16_t i = 0; i < strlen(ca_cert) - 1; i++)
    NBIOT_STREAM.write(ca_cert[i]);

  getBG96response(&ca_cert[strlen(ca_cert) - 1], "OK", response, 5000);

  // configure ca cert
  sprintf(cmd, "AT+QSSLCFG=\"cacert\",2,\"cacert.pem\"\r\n");
  getBG96response(cmd, "OK", response, 5000);

  //Configure SSL parameters.  
  //SSL authentication mode: server authentication
  sprintf(cmd, "AT+QSSLCFG=\"seclevel\",2,1\r\n");
  getBG96response(cmd, "OK", response, 5000);

  //SSL authentication version
  sprintf(cmd, "AT+QSSLCFG=\"sslversion\",2,4\r\n");
  getBG96response(cmd, "OK", response, 5000);

  //Cipher suite
  sprintf(cmd, "AT+QSSLCFG=\"ciphersuite\",2,0xFFFF\r\n");
  getBG96response(cmd, "OK", response, 5000);

  //Ignore the time of authentication
  sprintf(cmd, "AT+QSSLCFG=\"ignorelocaltime\",1\r\n");
  getBG96response(cmd, "OK", response, 5000);

  // open and connect
  sprintf(cmd, "AT+QMTOPEN=0,\"%s\",8883\r\n", MQTT_URL);
  getBG96response(cmd, "+QMTOPEN: 0,0", response, 5000);
  sprintf(cmd, "AT+QMTCONN=0,\"%s\"\r\n", ClientID);
  getBG96response(cmd, "+QMTCONN: 0,0,0", response, 5000);
}


bool BG96_turnGpsOn()
{
  char response[256];
  getBG96response("AT+QGPS?\r\n", "OK", response, 3000);
  
  if (strstr(response, "+QGPS: 1"))
    return true;
  else
    return getBG96response("AT+QGPS=1\r\n", "OK", response, 10000);
}

bool BG96_getGpsFix()
{
  char response[256];
  
  if (BG96_debug_enable)
    DEBUG_STREAM.println("Getting GPS fix...");
  while (!getBG96response("AT+QGPSLOC?\r\n", "OK", response, 5000))
  {
    if (BG96_debug_enable)
      DEBUG_STREAM.print(".");
    delay(3000);
  }
  if (BG96_debug_enable)
    DEBUG_STREAM.print("\r\nGPS fix OK!\r\n");

  return true;
}

bool BG96_getGpsPosition(char position[])
{
  char response[128], *start, *end;

  if (!getBG96response("AT+QGPSLOC=2\r\n", "OK", response, 3000))
    return false;
  start = strstr(response, "+QGPSLOC:");
  start = strstr(start, ",") + 1;
  end = strstr(start, ",") + 1;
  end = strstr(end, ",");
  *end = '\0';
  strcpy(position, start);
      
  return true;
}


void BG96_serialBridge()
{
  DEBUG_STREAM.println("Serial bridge...");
  while (1)
  {
    if (DEBUG_STREAM.available())
    {
      delay(100);
      char str[64];
      int len = DEBUG_STREAM.available();
      DEBUG_STREAM.readBytes(str, len);
      str[len] = '\0';
      
      if (strstr(str, "EXIT"))
      {
        DEBUG_STREAM.print("Exit bridge mode...\r\n");
        break;
      }
    
      DEBUG_STREAM.print("CMD -> ");
      DEBUG_STREAM.print(str);
      
      NBIOT_STREAM.print(str);
    }
    if (NBIOT_STREAM.available())
      DEBUG_STREAM.write(NBIOT_STREAM.read());  
  }
}


int compare(const char *X, const char *Y)
{
	while (*X && *Y)
	{
		if (*X != *Y) {
			return 0;
		}
		
		X++;
		Y++;
	}
	return (*Y == '\0');
}

// Function to implement `strstr()` function
const char* strcheck(const char* X, const char* Y, int  x_length)
{
	for(int i = 0; i < x_length; i++)
	{
		if ((*X == *Y) && compare(X, Y)) {
			return X;
		}
		X++;
	}
	
	return NULL;
}