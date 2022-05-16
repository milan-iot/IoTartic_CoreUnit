#include "sdu.h"

#define NUM_OF_ATTEMPTS_ON_RECEIVE 3

ESP32Time rtc;
bool SDU_debug_enable = false;
unsigned char session_key[32];

void SDU_debugEnable(bool enable)
{
    SDU_debug_enable = enable;
}

void SDU_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
{
    Crypto_debugPrint(title, data, data_len);
}

void SDU_debugPrintError(uint8_t error_code)
{
    switch(error_code)
    {
        case SDU_OK:
            DEBUG_STREAM.println("SDU_OK");
        break;

        case S_INVALID_MAC:
            DEBUG_STREAM.println("INVALID_MAC");
        break;

        case S_INVALID_HEADER:
            DEBUG_STREAM.println("INVALID_HEADER");
        break;

        case S_INVALID_NUM_OF_BYTES:
            DEBUG_STREAM.println("INVALID_NUM_OF_BYTES");
        break;

        case S_INTEGRITY_ERROR:
            DEBUG_STREAM.println("INTEGRITY_ERROR");
        break;

        case S_VERIFICATION_ERROR:
            DEBUG_STREAM.println("VERIFICATION_ERROR");
        break;

        case S_INVALID_NUM_OF_BYTES_SENS:
            DEBUG_STREAM.println("S_INVALID_NUM_OF_BYTES_SENS");
        break;

        case S_FORMAT_ERROR:
            DEBUG_STREAM.println("S_FORMAT_ERROR");
        break;

        case S_SUCCESS:
            DEBUG_STREAM.println("S_SUCCESS");
        break;

        case SERVER_ERROR(INVALID_HEADER):
            DEBUG_STREAM.println("SERVER_ERROR(INVALID_HEADER)");
        break;

        case SERVER_ERROR(INVALID_NUM_OF_BYTES):
            DEBUG_STREAM.println("SERVER_ERROR(INVALID_NUM_OF_BYTES)");
        break;

        case SERVER_ERROR(INTEGRITY_ERROR):
            DEBUG_STREAM.println("SERVER_ERROR(INTEGRITY_ERROR)");
        break;

        case LOCAL_ERROR(INVALID_HEADER):
            DEBUG_STREAM.println("LOCAL_ERROR(INVALID_HEADER)");
        break;

        case LOCAL_ERROR(INVALID_NUM_OF_BYTES):
            DEBUG_STREAM.println("LOCAL_ERROR(INVALID_NUM_OF_BYTES)");
        break;

        case LOCAL_ERROR(INTEGRITY_ERROR):
            DEBUG_STREAM.println("LOCAL_ERROR(INTEGRITY_ERROR)");
        break;

        case CRYPTO_FUNC_ERROR:
            DEBUG_STREAM.println("CRYPTO_FUNC_ERROR");
        break;

        case BG96_ERROR:
            DEBUG_STREAM.println("BG96_ERROR");
        break;

        case WIFI_ERROR:
            DEBUG_STREAM.println("WIFI_ERROR");
        break;

        case BAD_COMM_STRUCTURE:
            DEBUG_STREAM.println("BG96_ERROR");
        break;

        default:
            DEBUG_STREAM.println("UNKNOWN_ERROR_CODE");
    }
}

/*UTILITY FUNCTIONS*/

uint8_t checkBytes(uint8_t input1, uint8_t input2)
{
    return (input1 == input2) ? 0x00 : 0xFF;   
}

uint8_t SDU_establishConnection(SDU_struct *comm_params)
{
    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_OpenSocketUDP())
            return BG96_ERROR;
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_OpenSocketTCP(comm_params->server_IP, comm_params->port))
            return BG96_ERROR;
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        if(!BG96_MQTTconnect(comm_params->client_id, comm_params->server_IP, comm_params->port))
            return BG96_ERROR;
        if (!BG96_MQTTsubscribe(comm_params->topic_to_subs))
            return BG96_ERROR;
    }
    else if (comm_params->type_of_tunnel == WIFI)
    {
        if (comm_params->type_of_protocol == TCP)
        {
            if (!WiFi_TCPconnect(comm_params->server_IP, comm_params->port))
                return WIFI_ERROR;
        }

        if (comm_params->type_of_protocol == MQTT)
        {
            if (!WiFi_MQTTconnect(comm_params->server_IP, comm_params->port, comm_params->client_id))
                return WIFI_ERROR;
            if (!WiFi_MQTTsubscribe(comm_params->topic_to_subs))
                return WIFI_ERROR;
        }
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }

    return SDU_OK;
}

uint8_t SDU_closeConnection(SDU_struct *comm_params)
{
    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_CloseSocketUDP())
            return BG96_ERROR;
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_CloseSocketTCP())
            return BG96_ERROR;
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_MQTTdisconnect())
            return BG96_ERROR;
    }
    else if (comm_params->type_of_protocol == TCP  && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_TCPdisconnect();
    }

    return SDU_OK;
}


uint8_t SDU_constructPacket(uint8_t *mac, uint16_t header_type, uint8_t *in_data, uint8_t in_data_len, uint8_t *out_data, uint16_t *out_data_len)
{
    CRC8 crc;
    crc.setPolynome(CRC8_DEFAULT_VALUE);

    // copy device mac
    memcpy(out_data, mac, MAC_LENGTH);
    
    // copy header
    uint8_t tmp = header_type >> 8;
    memcpy(out_data + MAC_LENGTH, &tmp, 1);
    tmp = header_type & 0xff;
    memcpy(out_data + MAC_LENGTH + 1, &tmp, 1);

    switch(header_type)
    {
        case CLIENT_HELLO_HEADER:
            if (in_data_len != CLIENT_HELLO_DATA_LENGTH)
                return LOCAL_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(out_data + MAC_LENGTH + HEADER_LENGTH, in_data, in_data_len);
            crc.add((uint8_t*)in_data, in_data_len);
            *out_data_len = MAC_LENGTH + HEADER_LENGTH + in_data_len + CRC8_LENGTH;
        break;

        case CLIENT_VERIFY_HEADER:
            if (in_data_len != CLIENT_VERIFY_DATA_LENGTH)
                return LOCAL_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(out_data + MAC_LENGTH + HEADER_LENGTH, in_data, in_data_len);
            crc.add((uint8_t*)in_data, in_data_len);
            *out_data_len = MAC_LENGTH + HEADER_LENGTH + in_data_len + CRC8_LENGTH;
        break;

        case DATE_REQUEST_HEADER:
            *out_data_len = MAC_LENGTH + HEADER_LENGTH;
            return SDU_OK;
        break;

        case SENSOR_ENC_DATA_HEADER:
            //memcpy(out_data + MAC_LENGTH + HEADER_LENGTH, &in_data_len, 1);
            //memcpy(out_data + MAC_LENGTH + HEADER_LENGTH + DATA_LENGTH, in_data, in_data_len);
            memcpy(out_data + MAC_LENGTH + HEADER_LENGTH, in_data, in_data_len);
            crc.add((uint8_t*)in_data, in_data_len);
            *out_data_len = MAC_LENGTH + HEADER_LENGTH + in_data_len + CRC8_LENGTH;
        break;

        case SENSOR_DATA_HEADER:
            memcpy(out_data + MAC_LENGTH + HEADER_LENGTH, in_data, in_data_len);
            crc.add((uint8_t*)in_data, in_data_len);
            *out_data_len = MAC_LENGTH + HEADER_LENGTH + in_data_len + CRC8_LENGTH;
        break;

        default:
            return LOCAL_ERROR(INVALID_HEADER);
        break;
    }

    uint8_t crc_value = crc.getCRC();
    memcpy(out_data + *out_data_len - 1, &crc_value, 1);
    return SDU_OK;
}

uint8_t SDU_parsePacket(uint8_t *input, uint16_t input_length, uint8_t *output, uint16_t *output_length)
{
    //SDU_debugPrint((int8_t *)"Server: ", input, input_length);
    uint16_t header = ((uint16_t) input[0] << 8) | input[1];

    switch (header)
    {
        case SERVER_HELLO_HEADER:
            if (input_length != HEADER_LENGTH + SERVER_HELLO_LENGTH + CRC8_LENGTH)
                return SERVER_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(output, input + HEADER_LENGTH, SERVER_HELLO_LENGTH);
            *output_length = SERVER_HELLO_LENGTH;
        break;

        case SERVER_VERIFY_HEADER:
            if (input_length != HEADER_LENGTH + SERVER_VERIFY_LENGTH + CRC8_LENGTH)
                return SERVER_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(output, input + HEADER_LENGTH, SERVER_VERIFY_LENGTH);
            *output_length = SERVER_VERIFY_LENGTH;
        break;

        case ERROR_CODE_HEADER:
            if (input_length != HEADER_LENGTH + ERROR_CODE_LENGTH)
                return SERVER_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(output, input + HEADER_LENGTH, ERROR_CODE_LENGTH);
            *output_length = ERROR_CODE_LENGTH;
            return SDU_OK;
        break;

        case DATE_UPDATE_HEADER:
            if (input_length != HEADER_LENGTH + DATE_UPDATE_LEN + CRC8_LENGTH)
                return SERVER_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(output, input + HEADER_LENGTH, DATE_UPDATE_LEN);
            *output_length = DATE_UPDATE_LEN;
        break;

        case SENSOR_RESPONSE_HEADER:
            if (input_length != HEADER_LENGTH + SENSOR_RESPONSE_LENGTH + CRC8_LENGTH)
                return SERVER_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(output, input + HEADER_LENGTH, SENSOR_RESPONSE_LENGTH);
            *output_length = SENSOR_RESPONSE_LENGTH;
            return SDU_OK;
        break;

        default:
            return SERVER_ERROR(INVALID_HEADER);
    }

    // check crc value
    CRC8 crc;
    crc.setPolynome(CRC8_DEFAULT_VALUE);
    crc.add((uint8_t*)output, *output_length);

    return checkBytes(crc.getCRC(), input[*output_length + HEADER_LENGTH]);
}

uint8_t SDU_genIV(uint8_t *iv)
{
    char hash_input[32];
    uint8_t hash_output[32];
    String str;

    str = (rtc.getDay() < 10) ? ("0" + String(rtc.getDay())) : String(rtc.getDay());
    str += ((rtc.getMonth() + 1) < 10) ? ("0" + String(rtc.getMonth() + 1)) : String(rtc.getMonth() + 1);
    str += String(rtc.getYear());

    DEBUG_STREAM.println(str);

    str.toCharArray(hash_input, 32);

    mbedtls_md_context_t ctx;
    Crypto_debugEnable(true);
    
    if (!Crypto_Digest(&ctx, SHA256, (uint8_t *) hash_input, strlen(hash_input), hash_output))
      return CRYPTO_FUNC_ERROR;

    memcpy(iv, hash_output, 16);

    if (SDU_debugEnable)
        SDU_debugPrint((int8_t *)"IV: ", iv, 16);
    
    return SDU_OK;
}


/*MAIN FUNCTIONS*/

void SDU_init(SDU_struct *comm_params, COMM_MODE mode_of_work, PROTOCOL_MODE type_of_protocol, SERVER_TUNNEL_MODE type_of_tunnel, char server_IP[], uint16_t port, uint8_t *device_mac)
{
    comm_params->mode_of_work = mode_of_work;
    comm_params->type_of_protocol = type_of_protocol;
    comm_params->type_of_tunnel = type_of_tunnel;
    comm_params->server_IP = server_IP;
    comm_params->port = port;
    comm_params->device_mac = device_mac;
}

uint8_t SDU_setMQTTparams(SDU_struct *comm_params, char *client_id, char *topic_to_pub, char *topic_to_subs)
{
    if (comm_params->type_of_protocol == MQTT)
    {
        comm_params->client_id = client_id;
        comm_params->topic_to_pub = topic_to_pub;
        comm_params->topic_to_subs = topic_to_subs;
        return SDU_OK;
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }
}

uint8_t SDU_setBG96params(SDU_struct *comm_params, char *apn, char *apn_user, char *apn_pass)
{
    if (comm_params->type_of_tunnel == BG96)
    {
        comm_params->apn = apn;
        comm_params->apn_user = apn_user;
        comm_params->apn_user = apn_pass;
        return SDU_OK;
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }
}

uint8_t SDU_setWIFIparams(SDU_struct *comm_params, char *ssid, char *pass)
{
    if (comm_params->type_of_tunnel == WIFI)
    {
        comm_params->ssid = ssid;
        comm_params->pass = pass;
        return SDU_OK;
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }
}

uint8_t SDU_setEncryptionParams(SDU_struct *comm_params,  char *hmac_salt, char *password)
{
    if (comm_params->mode_of_work == ENCRYPTED_COMM)
    {
        comm_params->hmac_salt = hmac_salt;
        comm_params->password = password;
        comm_params->personalization_info = (char *)comm_params->device_mac;
        return SDU_OK;
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }
}

uint8_t SDU_setup(SDU_struct *comm_params)
{
    if (comm_params->type_of_tunnel == BG96)
    {
        while(!BG96_turnOn());

        if (!BG96_nwkRegister(comm_params->apn, comm_params->apn_user, comm_params->apn_pass))
            return BG96_ERROR;
    }
    else if (comm_params->type_of_tunnel == WIFI)
    {
        if (WIFI_status() != WL_CONNECTED)
            if (!WiFi_setup(comm_params->ssid, comm_params->pass))
                return WIFI_ERROR;
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }

    return SDU_OK;
}


void SDU_end(SDU_struct *comm_params)
{
    if (comm_params->type_of_tunnel == WIFI)
    {
        WiFi_disconnect();
    }
}

uint8_t SDU_checkConnectivity(SDU_struct *comm_params)
{
    if (comm_params->type_of_tunnel == BG96)
    {
       if (!BG96_checkConnectivity())
            return BG96_ERROR;
    }
    else if (comm_params->type_of_tunnel == WIFI)
    {
        if (WIFI_status() != WL_CONNECTED)
            return WIFI_ERROR;
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }

    return SDU_OK;
}


uint8_t SDU_updateIV(SDU_struct *comm_params)
{
    if (comm_params->mode_of_work != ENCRYPTED_COMM)
        return BAD_COMM_STRUCTURE;

    // generate sha of password
    uint8_t ret;
    uint16_t expected_size = 0;
    byte shared_secret[32];
    mbedtls_md_context_t ctx;

    if (SDU_debug_enable)
        Crypto_debugEnable(true);
    
    if (!Crypto_Digest(&ctx, HMAC_SHA256, (uint8_t *) comm_params->hmac_salt, strlen(comm_params->hmac_salt), shared_secret, (uint8_t *) comm_params->password, strlen(comm_params->password)))
      return CRYPTO_FUNC_ERROR;

    ret = SDU_establishConnection(comm_params);
    if (ret != SDU_OK)
        return ret;

    uint8_t date_request[128];
    uint16_t date_request_len;
    ret = SDU_constructPacket(comm_params->device_mac, DATE_REQUEST_HEADER, NULL, 0, date_request, &date_request_len);

    if (ret != 0)
        return ret;

    if (SDU_debug_enable)
    {
        SDU_debugPrint((int8_t *)"Date request", date_request, date_request_len);
    }

    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_SendUDP(comm_params->server_IP, comm_params->port, date_request, date_request_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_SendTCP(date_request, date_request_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_MQTTpublish(comm_params->topic_to_pub, date_request, date_request_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_UDPsend(comm_params->server_IP, comm_params->port, date_request, date_request_len))
            return WIFI_ERROR;
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_TCPsend(date_request, date_request_len))
            return WIFI_ERROR;
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_MQTTsend(comm_params->topic_to_pub, date_request, date_request_len))
            return WIFI_ERROR;
    }

    uint8_t date_update[128];
    uint16_t date_update_length;
    uint8_t date_update_raw[32];
    uint16_t date_update_raw_length;
    uint8_t date[128];

    expected_size = HEADER_LENGTH + DATE_UPDATE_LEN + CRC8_LENGTH;

    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            delay(1000);
            expected_size = HEADER_LENGTH + DATE_UPDATE_LEN + CRC8_LENGTH;
            if (!BG96_RecvUDP(date_update, &expected_size))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
            
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + DATE_UPDATE_LEN + CRC8_LENGTH;
            if (!BG96_RecvTCP(date_update, &expected_size))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
            
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + DATE_UPDATE_LEN + CRC8_LENGTH;
            BG96_MQTTcollectData(date_update, &expected_size);
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_UDPrecv((char *)date_update, &expected_size);
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_TCPrecv((char *)date_update, &expected_size);
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_MQTTrecv(date_update, &expected_size);
    }

    date_update_length = expected_size;
    ret = SDU_parsePacket(date_update, date_update_length, date_update_raw, &date_update_raw_length);
    if (ret != 0)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return ret;
    }
    
    if (date_update_raw_length == ERROR_CODE_LENGTH)
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return date_update_raw[0];
    }
    
    if (SDU_debug_enable)
    {
        SDU_debugPrint((int8_t *)"Date update", date_update_raw, date_update_raw_length);
    }

    uint8_t iv[16];
    memset(iv, 0, 16);
    
    mbedtls_aes_context aes;
    if (!Crypto_AES(&aes, DECRYPT, shared_secret, 256, iv, date_update_raw, date, DATE_UPDATE_LEN))
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return CRYPTO_FUNC_ERROR;   
    }

    if (SDU_debug_enable)
    {
        SDU_debugPrint((int8_t *)"Date decrypted", date, 14);
    }

    ret = SDU_closeConnection(comm_params);
    if (ret != SDU_OK)
        return ret;

    // speedy conversion
    int day = (date[0] - '0') * 10 + (date[1] - '0');
    int month = (date[2] - '0') * 10 + (date[3] - '0');
    int year = (date[4] - '0') * 1000 + (date[5] - '0') * 100 + (date[6] - '0') * 10 + (date[7] - '0');
    int hour = (date[8] - '0') * 10 + (date[9] - '0');
    int min = (date[10] - '0') * 10 + (date[11] - '0');
    int sec = (date[12] - '0') * 10 + (date[13] - '0');

    rtc.setTime(sec, min, hour, day, month, year);

    if (SDU_debug_enable)
        Serial.println(rtc.getDate());
    
    return SDU_OK;
}

uint8_t SDU_getDay(int16_t *day)
{
    *day =  rtc.getDay();
    return SDU_OK;
}

uint8_t SDU_handshake(SDU_struct *comm_params)
{
    if (comm_params -> mode_of_work != ENCRYPTED_COMM)
        return BAD_COMM_STRUCTURE;

    uint8_t ret;
    uint16_t expected_size = 0;
    uint8_t cmd[128], response[128];

    uint8_t iv[16];

     // generate sha of password
    byte shared_secret[32];
    mbedtls_md_context_t ctx;

    //Crypto_debugEnable(true);
    
    if (!Crypto_Digest(&ctx, HMAC_SHA256, (uint8_t *) comm_params->hmac_salt, strlen(comm_params->hmac_salt), shared_secret, (uint8_t *) comm_params->password, strlen(comm_params->password)))
      return CRYPTO_FUNC_ERROR;

    // generate private public key pair
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_ctr_drbg_context drbg_ctx;
    unsigned char priv[32];
    uint8_t public_key_raw[64];

    if (SDU_debug_enable)
        DEBUG_STREAM.println( "Setting up client context..." );
    // init random generator
    if (!Crypto_initRandomGenerator(&drbg_ctx, (int8_t *)comm_params->personalization_info, sizeof(comm_params->personalization_info)))
        return CRYPTO_FUNC_ERROR;
    // public-private key generation
    if (!Crypto_keyGen(&ecdh_ctx, &drbg_ctx, MBEDTLS_ECP_DP_SECP256R1))
        return CRYPTO_FUNC_ERROR;

    // get public key from ecdh ctx struct
    if (!Crypto_getPublicKey(&ecdh_ctx, public_key_raw))
        return CRYPTO_FUNC_ERROR;
    // get private key from ecdh ctx struct
    if (!Crypto_getPrivateKey(&ecdh_ctx, priv))
        return CRYPTO_FUNC_ERROR;
    
    mbedtls_aes_context aes;

    //memset(iv, 0, 16);
    ret = SDU_genIV(iv);
    if (ret != 0)
        return ret;

    uint8_t client_hello[128];
    uint16_t client_hello_len;
    uint8_t client_hello_raw[64];
    if (!Crypto_AES(&aes, ENCRYPT, shared_secret, 256, iv, public_key_raw, client_hello_raw, CLIENT_HELLO_DATA_LENGTH))
        return CRYPTO_FUNC_ERROR;

    if (SDU_debug_enable)
        DEBUG_STREAM.println( "end generation of pvt pub key");

    ret = SDU_establishConnection(comm_params);
    if (ret != SDU_OK)
        return ret;

    ret = SDU_constructPacket(comm_params->device_mac, CLIENT_HELLO_HEADER, client_hello_raw, CLIENT_HELLO_DATA_LENGTH, client_hello, &client_hello_len);

    if (ret != 0)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return ret;
    }

    if (SDU_debug_enable)
    {
        SDU_debugPrint((int8_t *)"Client hello", client_hello, client_hello_len);
    }

    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_SendUDP(comm_params->server_IP, comm_params->port, client_hello, client_hello_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_SendTCP(client_hello, client_hello_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_MQTTpublish(comm_params->topic_to_pub, client_hello, client_hello_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_UDPsend(comm_params->server_IP, comm_params->port, client_hello, client_hello_len))
            return WIFI_ERROR;
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_TCPsend(client_hello, client_hello_len))
            return WIFI_ERROR;
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_MQTTsend(comm_params->topic_to_pub, client_hello, client_hello_len))
            return WIFI_ERROR;
    }

    uint8_t server_hello[128];
    uint16_t server_hello_length;
    uint8_t server_hello_raw[80];
    uint16_t server_hello_raw_length;
    uint8_t server_hello_decrypted[128];

    expected_size = HEADER_LENGTH + SERVER_HELLO_LENGTH + CRC8_LENGTH;

    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + SERVER_HELLO_LENGTH + CRC8_LENGTH;
            if (!BG96_RecvUDP(server_hello, &expected_size))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + SERVER_HELLO_LENGTH + CRC8_LENGTH;
            if (!BG96_RecvTCP(server_hello, &expected_size))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);

        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return BG96_ERROR;
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + SERVER_HELLO_LENGTH + CRC8_LENGTH;
            BG96_MQTTcollectData(server_hello, &expected_size);
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_UDPrecv((char *)server_hello, &expected_size);
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_TCPrecv((char *)server_hello, &expected_size);
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_MQTTrecv(server_hello, &expected_size);
    }

    server_hello_length = expected_size;
    ret = SDU_parsePacket(server_hello, server_hello_length, server_hello_raw, &server_hello_raw_length);
    if (ret != 0)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return ret;
    }
    
    if (server_hello_raw_length == ERROR_CODE_LENGTH)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return server_hello_raw[0];
    }
    
    if (SDU_debug_enable)
    {
        SDU_debugPrint((int8_t *)"Server hello", server_hello_raw, server_hello_raw_length);
    }

    //memset(iv, 0, 16);
    ret = SDU_genIV(iv);
    if (ret != 0)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return ret;
    }
    
    if (!Crypto_AES(&aes, DECRYPT, shared_secret, 256, iv, server_hello_raw, server_hello_decrypted, SERVER_HELLO_LENGTH))
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return CRYPTO_FUNC_ERROR;
    }

    if (SDU_debug_enable)
        DEBUG_STREAM.println("Server reading client key and computing secret...");

    if (!Crypto_setPeerPublicKey(&ecdh_ctx, server_hello_decrypted))
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return CRYPTO_FUNC_ERROR;
    }
    
    if (!Crypto_ECDH(&ecdh_ctx))
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return CRYPTO_FUNC_ERROR;
    }

    if (!Crypto_getSharedSecret(&ecdh_ctx, session_key))
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return CRYPTO_FUNC_ERROR;
    }

    if (SDU_debug_enable)
        DEBUG_STREAM.println("shared secret calculation done");

    uint8_t Rb[16];
    if (!Crypto_Random(&drbg_ctx, Rb, 16))
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return CRYPTO_FUNC_ERROR;
    }

    uint8_t client_verify[128];
    uint16_t client_verify_len;
    uint8_t client_verify_raw[128];

    uint8_t challenge1[32];
    memcpy(challenge1, server_hello_decrypted + PUBLIC_KEY_OFFSET, 16);
    memcpy(challenge1 + 16, Rb, 16);

    //memset(iv, 0, 16);
    ret = SDU_genIV(iv);
    if (ret != 0)
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return ret;
    }

    if (!Crypto_AES(&aes, ENCRYPT, session_key, 256, iv, challenge1, client_verify_raw, CLIENT_VERIFY_DATA_LENGTH))
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return CRYPTO_FUNC_ERROR;
    }

    ret = SDU_constructPacket(comm_params->device_mac, CLIENT_VERIFY_HEADER, client_verify_raw, CLIENT_VERIFY_DATA_LENGTH, client_verify, &client_verify_len);

    if (SDU_debug_enable)
    {
        SDU_debugPrint((int8_t *)"Client verify", client_verify, client_verify_len);
    }

    if (ret != 0)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return ret;
    }

    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_SendUDP(comm_params->server_IP, comm_params->port, client_verify, client_verify_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        ret = SDU_establishConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        if (!BG96_SendTCP(client_verify, client_verify_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        if (!BG96_MQTTpublish(comm_params->topic_to_pub, client_verify, client_verify_len))
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return BG96_ERROR;
        }
    }
    else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_UDPsend(comm_params->server_IP, comm_params->port, client_verify, client_verify_len))
            return WIFI_ERROR;
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
    {
        ret = SDU_establishConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        if (!WiFi_TCPsend(client_verify, client_verify_len))
            return WIFI_ERROR;
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
    {
        if (!WiFi_MQTTsend(comm_params->topic_to_pub, client_verify, client_verify_len))
            return WIFI_ERROR;
    }

    uint8_t server_verify[128];
    uint16_t server_verify_length;
    uint8_t server_verify_raw[80];
    uint16_t server_verify_raw_length;
    uint8_t server_verify_decrypted[128];

    expected_size = HEADER_LENGTH + SERVER_VERIFY_LENGTH + CRC8_LENGTH;
    if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + SERVER_VERIFY_LENGTH + CRC8_LENGTH;
            if (!BG96_RecvUDP(server_verify, &expected_size))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + SERVER_VERIFY_LENGTH + CRC8_LENGTH;
            if (!BG96_RecvTCP(server_verify, &expected_size))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
    {
        uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
        do
        {
            //delay(1000);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            expected_size = HEADER_LENGTH + SERVER_VERIFY_LENGTH + CRC8_LENGTH;
            BG96_MQTTcollectData(server_verify, &expected_size);
            num_of_attempts--;
        } while(expected_size == 0 && num_of_attempts != 0);
    }
    else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_UDPrecv((char *)server_verify, &expected_size);
    }
    else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_TCPrecv((char *)server_verify, &expected_size);
    }
    else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
    {
        WiFi_MQTTrecv(server_verify, &expected_size);
    }

    if (SDU_debug_enable)
        SDU_debugPrint((int8_t *)"Server verify", server_verify, expected_size);

    server_verify_length = expected_size;
    ret = SDU_parsePacket(server_verify, server_verify_length, server_verify_raw, &server_verify_raw_length);
    if (ret != 0)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return ret;
    }
    
    if (server_verify_raw_length == ERROR_CODE_LENGTH)
    {
        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;
        return server_verify_raw[0];
    }
    
    if (SDU_debug_enable)
    {
        SDU_debugPrint((int8_t *)"Server verify", server_verify_raw, server_verify_raw_length);
    }

    uint8_t challenge2_decrypted[80];
    //memset(iv, 0, 16);
    ret = SDU_genIV(iv);
    if (ret != 0)
    {
        uint8_t ret1 = SDU_closeConnection(comm_params);
        if (ret1 != SDU_OK)
            return ret1;
        return ret;
    }
    
    if (!Crypto_AES(&aes, DECRYPT, session_key, 256, iv, server_verify_raw, challenge2_decrypted, SERVER_VERIFY_LENGTH))
        return CRYPTO_FUNC_ERROR;

    ret = SDU_closeConnection(comm_params);
    if (ret != SDU_OK)
        return ret;

    return SDU_OK;
}


uint8_t SDU_sendData(SDU_struct *comm_params, uint8_t *raw_data, uint16_t raw_data_len)
{
    uint8_t ret;
    uint16_t expected_size = 0;

    if (comm_params -> mode_of_work == ENCRYPTED_COMM)
    {
        uint8_t iv[16];
        mbedtls_aes_context aes;

        ret = SDU_genIV(iv);
        if (ret != 0)
            return ret;

        uint8_t sensor_data[256];
        uint16_t sensor_data_len;
        uint8_t enc_sensor_data_raw[128];

        if (!Crypto_AES(&aes, ENCRYPT, session_key, 256, iv, raw_data, enc_sensor_data_raw, raw_data_len))
            return CRYPTO_FUNC_ERROR;

        // pad data to 16 or 32
        raw_data_len += 16 - raw_data_len % 16;

        ret = SDU_establishConnection(comm_params);
        if (ret != SDU_OK)
            return ret;

        ret = SDU_constructPacket(comm_params->device_mac, SENSOR_ENC_DATA_HEADER, enc_sensor_data_raw, raw_data_len, sensor_data, &sensor_data_len);

        if (ret != 0)
        {
            uint8_t ret1 = SDU_closeConnection(comm_params);
            if (ret1 != SDU_OK)
                return ret1;
            return ret;
        }

        if (SDU_debug_enable)
        {
            SDU_debugPrint((int8_t *)"Sensor data", sensor_data, sensor_data_len);
        }

        if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
        {
            if (!BG96_SendUDP(comm_params->server_IP, comm_params->port, sensor_data, sensor_data_len))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
        {
            if (!BG96_SendTCP(sensor_data, sensor_data_len))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
        {
            if (!BG96_MQTTpublish(comm_params->topic_to_pub, sensor_data, sensor_data_len))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
        }
        else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
        {
            if (!WiFi_UDPsend(comm_params->server_IP, comm_params->port, sensor_data, sensor_data_len))
                return WIFI_ERROR;
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
        {
            if (!WiFi_TCPsend(sensor_data, sensor_data_len))
                return WIFI_ERROR;
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
        {
            if (!WiFi_MQTTsend(comm_params->topic_to_pub, sensor_data, sensor_data_len))
                return WIFI_ERROR;
        }

        uint8_t sensor_response[64];
        uint16_t sensor_response_length;
        uint8_t sensor_response_raw[32];
        uint16_t sensor_response_raw_length;

        expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;

        if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
        {
            uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
            do
            {
                delay(1000);
                expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;
                if (!BG96_RecvUDP(sensor_response, &expected_size))
                {
                    ret = SDU_closeConnection(comm_params);
                    if (ret != SDU_OK)
                        return ret;
                    return BG96_ERROR;
                }
                num_of_attempts--;
            } while(expected_size == 0 && num_of_attempts != 0);
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
        {
            uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
            do
            {
                delay(1000);
                //vTaskDelay(1000 / portTICK_PERIOD_MS);
                expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;
                if (!BG96_RecvTCP(sensor_response, &expected_size))
                {
                    ret = SDU_closeConnection(comm_params);
                    if (ret != SDU_OK)
                        return ret;
                    return BG96_ERROR;
                }
                num_of_attempts--;
            } while(expected_size == 0 && num_of_attempts != 0);
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
        {
            uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
            do
            {
                delay(1000);
                expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;
                BG96_MQTTcollectData(sensor_response, &expected_size);
                num_of_attempts--;
            } while(expected_size == 0 && num_of_attempts != 0);
        }
        else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
        {
            WiFi_UDPrecv((char *)sensor_response, &expected_size);
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
        {
            WiFi_TCPrecv((char *)sensor_response, &expected_size);
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
        {
            WiFi_MQTTrecv(sensor_response, &expected_size);
        }

        if (SDU_debug_enable)
            SDU_debugPrint((int8_t *)"Sensor response", sensor_response, expected_size);

        sensor_response_length = expected_size;
        ret = SDU_parsePacket(sensor_response, sensor_response_length, sensor_response_raw, &sensor_response_raw_length);

        if (ret != 0)
        {
            uint8_t ret1 = SDU_closeConnection(comm_params);
            if (ret1 != SDU_OK)
                return ret1;
            return ret;
        }
        
        if (sensor_response_raw_length != SENSOR_RESPONSE_LENGTH)
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return SERVER_ERROR(INVALID_NUM_OF_BYTES);
        }
        
        if (SDU_debug_enable)
        {
            SDU_debugPrint((int8_t *)"Sensor response", sensor_response_raw, sensor_response_raw_length);
        }

        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;

        return sensor_response_raw[0];
    }
    else if (comm_params -> mode_of_work == NON_ENCRYPTED_COMM)
    {
        uint8_t sensor_data[256];
        uint16_t sensor_data_len;

        ret = SDU_establishConnection(comm_params);
        if (ret != SDU_OK)
            return ret;

        ret = SDU_constructPacket(comm_params->device_mac, SENSOR_DATA_HEADER, raw_data, raw_data_len, sensor_data, &sensor_data_len);

        if (ret != 0)
        {
            uint8_t ret1 = SDU_closeConnection(comm_params);
            if (ret1 != SDU_OK)
                return ret1;
            return ret;
        }

        if (SDU_debug_enable)
        {
            SDU_debugPrint((int8_t *)"Sensor data", sensor_data, sensor_data_len);
        }

        if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
        {
            if (!BG96_SendUDP(comm_params->server_IP, comm_params->port, sensor_data, sensor_data_len))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
        {
            if (!BG96_SendTCP(sensor_data, sensor_data_len))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
        {
            if (!BG96_MQTTpublish(comm_params->topic_to_pub, sensor_data, sensor_data_len))
            {
                ret = SDU_closeConnection(comm_params);
                if (ret != SDU_OK)
                    return ret;
                return BG96_ERROR;
            }
        }
        else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
        {
            if (!WiFi_UDPsend(comm_params->server_IP, comm_params->port, sensor_data, sensor_data_len))
                return WIFI_ERROR;
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
        {
            if (!WiFi_TCPsend(sensor_data, sensor_data_len))
                return WIFI_ERROR;
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
        {
            if (!WiFi_MQTTsend(comm_params->topic_to_pub, sensor_data, sensor_data_len))
                return WIFI_ERROR;
        }

        uint8_t sensor_response[64];
        uint16_t sensor_response_length;
        uint8_t sensor_response_raw[16];
        uint16_t sensor_response_raw_length;

        expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;

        if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == BG96)
        {
            uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
            do
            {
                delay(1000);
                expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;
                if (!BG96_RecvUDP(sensor_response, &expected_size))
                {
                    ret = SDU_closeConnection(comm_params);
                    if (ret != SDU_OK)
                        return ret;
                    return BG96_ERROR;
                }
                num_of_attempts--;
            } while(expected_size == 0 && num_of_attempts != 0);
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == BG96)
        {
            uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
            do
            {
                vTaskDelay(1000 / portTICK_PERIOD_MS);
                expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;
                if (!BG96_RecvTCP(sensor_response, &expected_size))
                {
                    ret = SDU_closeConnection(comm_params);
                    if (ret != SDU_OK)
                        return ret;
                    return BG96_ERROR;
                }
                num_of_attempts--;
            } while(expected_size == 0 && num_of_attempts != 0);
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == BG96)
        {
            uint8_t num_of_attempts = NUM_OF_ATTEMPTS_ON_RECEIVE;
            do
            {
                vTaskDelay(1000 / portTICK_PERIOD_MS);
                expected_size = HEADER_LENGTH + SENSOR_RESPONSE_LENGTH;
                BG96_MQTTcollectData(sensor_response, &expected_size);
                num_of_attempts--;
            } while(expected_size == 0 && num_of_attempts != 0);
        }
        else if (comm_params->type_of_protocol == UDP && comm_params->type_of_tunnel == WIFI)
        {
            WiFi_UDPrecv((char *)sensor_response, &expected_size);
        }
        else if (comm_params->type_of_protocol == TCP && comm_params->type_of_tunnel == WIFI)
        {
            WiFi_TCPrecv((char *)sensor_response, &expected_size);
        }
        else if (comm_params->type_of_protocol == MQTT && comm_params->type_of_tunnel == WIFI)
        {
            WiFi_MQTTrecv(sensor_response, &expected_size);
        }

        sensor_response_length = expected_size;
        ret = SDU_parsePacket(sensor_response, sensor_response_length, sensor_response_raw, &sensor_response_raw_length);

        if (ret != 0)
        {
            uint8_t ret1 = SDU_closeConnection(comm_params);
            if (ret1 != SDU_OK)
                return ret1;
            return ret;
        }
        
        if (sensor_response_raw_length != SENSOR_RESPONSE_LENGTH)
        {
            ret = SDU_closeConnection(comm_params);
            if (ret != SDU_OK)
                return ret;
            return SERVER_ERROR(INVALID_NUM_OF_BYTES);
        }
        
        if (SDU_debug_enable)
        {
            SDU_debugPrint((int8_t *)"Sensor response", sensor_response_raw, sensor_response_raw_length);
        }

        ret = SDU_closeConnection(comm_params);
        if (ret != SDU_OK)
            return ret;

        return sensor_response_raw[0];
    }
    else
    {
        return BAD_COMM_STRUCTURE;
    }
}