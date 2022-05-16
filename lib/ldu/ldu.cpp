#include "ldu.h"

bool LDU_debug_enable = false;

void LDU_debugEnable(bool enable)
{
    LDU_debug_enable = enable;
}

void LDU_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
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

uint8_t LDU_constructPacket(uint16_t header_type, uint8_t *input, uint8_t input_length, uint8_t *output, uint16_t *output_length)
{
    uint8_t tmp;
    // copy header
    memcpy(output, input, input_length);
    *output_length = input_length;

    switch(header_type)
    {
         case SENSOR_MAC_ADDRESS_REQUEST_HEADER:
            //if (input_length != HEADER_LENGTH + IDENTITY_HASH)
                //return LOCAL_ERROR(INVALID_NUM_OF_BYTES);
            tmp = header_type >> 8;
            memcpy(output + input_length, &tmp, 1);
            tmp = header_type & 0xff;
            memcpy(output + input_length + 1, &tmp, 1);
        break;

        case SENSOR_DATA_REQUEST_HEADER:
            //if (input_length != HEADER_LENGTH + IDENTITY_HASH)
                //return LOCAL_ERROR(INVALID_NUM_OF_BYTES);
            tmp = header_type >> 8;
            memcpy(output + input_length, &tmp, 1);
            tmp = header_type & 0xff;
            memcpy(output + input_length + 1, &tmp, 1);
        break;

        case CORE_RESPONSE_HEADER:


        break;

        default:
            return LOCAL_ERROR(INVALID_HEADER);
        break;
    }

    *output_length += HEADER_LENGTH;
}


uint8_t LDU_parsePacket(LDU_struct *comm_params, uint16_t header, uint8_t *input, uint16_t input_length, uint8_t *output, uint16_t *output_length)
{
    uint16_t rec_header = ((uint16_t) input[0] << 8) | input[1];

    if (rec_header != header)
        return SERVER_ERROR(INVALID_HEADER);

    switch (rec_header)
    {
        case SENSOR_MAC_ADDRESS_VALUE_HEADER:
            if (input_length != HEADER_LENGTH + SENSOR_MAC_ADDRESS_VALUE_LENGTH + CRC32_LENGTH)
                return SERVER_ERROR(INVALID_NUM_OF_BYTES);
            memcpy(output, input + HEADER_LENGTH, SENSOR_MAC_ADDRESS_VALUE_LENGTH);
            *output_length = SENSOR_MAC_ADDRESS_VALUE_LENGTH;
        break;

        case SENSOR_DATA_VALUE_HEADER:
            memcpy(output, input + HEADER_LENGTH, input_length - HEADER_LENGTH - HASH_LENGTH);
            *output_length = input_length - HEADER_LENGTH - HASH_LENGTH;
        break;

        default:
            if (LDU_debug_enable)
                DEBUG_STREAM.println("Default case");
            return SERVER_ERROR(INVALID_HEADER);
        break;
    }

    // check crc value
    CRC32 crc;
    crc.setPolynome(CRC32_DEFAULT_VALUE);

    uint8_t hmac_result[32];
    mbedtls_md_context_t ctx;
    if (!Crypto_Digest(&ctx, HMAC_SHA256, output, *output_length, hmac_result, (uint8_t *) comm_params->ble_password, strlen(comm_params->ble_password)))
      return CRYPTO_FUNC_ERROR;

    crc.add((uint8_t*)hmac_result, 32);

    uint32_t received_hmac = (input[*output_length + HEADER_LENGTH])            |
                             (input[*output_length + HEADER_LENGTH + 1] << 8)   |
                             (input[*output_length + HEADER_LENGTH + 2] << 16)  |
                             (input[*output_length + HEADER_LENGTH + 3] << 24);

    if (LDU_debug_enable)
    {
        DEBUG_STREAM.println(crc.getCRC(), HEX);
        DEBUG_STREAM.println(received_hmac, HEX);
    }

    return !(crc.getCRC() == received_hmac);
}


void LDU_setBLEParams(LDU_struct *comm_params, char *serv_uuid, char *char_uuid, char *ble_password)
{
    comm_params->mode = BLE;
    comm_params->serv_uuid = serv_uuid;
    comm_params->char_uuid = char_uuid;
    comm_params->ble_password = ble_password;
}

void LDU_setRS485Params(LDU_struct *comm_params, uint32_t rs485_baudrate)
{
    comm_params->mode = RS485;
    comm_params->rs485_baudrate = rs485_baudrate;
}

uint8_t LDU_init(LDU_struct *comm_params)
{
    if (comm_params->mode == RS485)
    {
        RS485_begin(comm_params->rs485_baudrate);
        RS485_setMode(RS485_RX);
    }
    else if (comm_params->mode == BLE)
    {
        BLE_serverSetup(comm_params->serv_uuid, comm_params->char_uuid);
    }
    else
    {
        return BAD_COM_STRUCTURE;
    }

    return LDU_OK;
}


uint8_t LDU_send(LDU_struct *comm_params, uint8_t packet[], uint16_t size)
{
    if (comm_params->mode == RS485)
    {
        RS485_setMode(RS485_TX);
        RS485_send(packet, size);
        RS485_setMode(RS485_RX);
        return LDU_OK;
    }
    else if (comm_params->mode == BLE)
    {
        //BLE_connectToServer();
        BLE_send(packet, size);
        return LDU_OK;
    }
    else
    {
        return BAD_COM_STRUCTURE;
    }
}

uint8_t LDU_getServerMac(LDU_struct *comm_params, uint8_t *server_mac)
{
    if (comm_params->mode == BLE)
    {
        BLE_getMACStandalone(server_mac);
    }
    else if (comm_params->mode == RS485)
    {
        BLE_getMACStandalone(server_mac);
    }
    else
    {
        return BAD_COM_STRUCTURE;
    }
}

uint8_t LDU_calculateDeviceHash(LDU_struct *comm_params, uint8_t *output)
{
    uint8_t hmac_input[64];
    uint16_t hmac_input_length;

    memcpy(hmac_input, comm_params->serv_uuid, strlen(comm_params->serv_uuid));
    memcpy(hmac_input + strlen(comm_params->serv_uuid), comm_params->char_uuid, strlen(comm_params->char_uuid));

    hmac_input_length = strlen(comm_params->serv_uuid) + strlen(comm_params->char_uuid);

    if (LDU_debug_enable)
        LDU_debugPrint((int8_t *)"hmac_input", hmac_input, hmac_input_length);

    mbedtls_md_context_t ctx;
    if (!Crypto_Digest(&ctx, HMAC_SHA256, hmac_input, hmac_input_length, output, (uint8_t *) comm_params->ble_password, strlen(comm_params->ble_password)))
        return CRYPTO_FUNC_ERROR;

    return LDU_OK;
}

uint8_t LDU_recv(LDU_struct *comm_params, uint8_t rx_buffer[], uint16_t *size, uint32_t timeout)
{
    if (comm_params->mode == RS485)
    {
        RS485_recv((uint8_t *)rx_buffer, size, timeout);
    }
    else if (comm_params->mode == BLE)
    {
        BLE_recv((char *)rx_buffer, size, 5000); // to do: timeout
    }
    else
    {
        return BAD_COM_STRUCTURE;
    }

    return LDU_OK;
}


uint8_t LDU_waitForData(LDU_struct *comm_params, uint8_t *output_data, uint16_t *output_data_len, uint16_t timeout)
{
    uint8_t ret = LDU_OK;
    uint16_t t0 = 0;
    uint8_t response[128];
    uint16_t response_len = 0;

    while(response_len == 0)
    {
        LDU_recv(comm_params, response, &response_len, 5000);
    }

    if (LDU_debug_enable)
        LDU_debugPrint((int8_t*)"raw", response, response_len);

    ret = LDU_parsePacket(comm_params, SENSOR_DATA_VALUE_HEADER, response, response_len, output_data, output_data_len);
    if(ret != LDU_OK)
    {
        if (LDU_debug_enable)
            DEBUG_STREAM.println("Parse error");
        return ret;
    }

    // ubaciti i komandu za azuriranje senzorske strane
    uint8_t core_command[3] = {0x43, 0x52, 0xCC};
    ret = LDU_send(comm_params, core_command, 3);
    if(ret != LDU_OK)
    {
        if (LDU_debug_enable)
            DEBUG_STREAM.println("Send error");
        return ret;
    }

    return ret;
}


uint8_t LDU_request(LDU_struct *comm_params, uint16_t header, uint8_t *output_data, uint16_t *output_data_len)
{
    uint8_t request_raw[64];
    uint16_t request_raw_len;
    uint8_t request[64];
    uint16_t request_len;
    uint8_t response[64];
    uint16_t response_len = sizeof(response);

    if (comm_params->mode == BLE)
    {
        LDU_constructPacket(header, NULL, 0, request, &request_len);
    }
    else if (comm_params->mode == RS485)
    {
        request_raw_len = IDENTITY_HASH;
        LDU_calculateDeviceHash(comm_params, request_raw);
        LDU_constructPacket(header, request_raw, IDENTITY_HASH, request, &request_len);
    }
    else
    {
        return BAD_COM_STRUCTURE;
    }

    LDU_send(comm_params, request, request_len);

    LDU_recv(comm_params, response, &response_len, 5000);

    uint8_t ret;
    if (header == SENSOR_MAC_ADDRESS_REQUEST_HEADER)
        ret = LDU_parsePacket(comm_params, SENSOR_MAC_ADDRESS_VALUE_HEADER, response, response_len, output_data, output_data_len);
    else if (header == SENSOR_DATA_REQUEST_HEADER)
        ret = LDU_parsePacket(comm_params, SENSOR_DATA_VALUE_HEADER, response, response_len, output_data, output_data_len);
    else
        ret = LOCAL_ERROR(INVALID_HEADER);

    return ret;
}

uint8_t LDU_requestDataRS485(LDU_struct *comm_params, uint8_t *sensor_data, uint16_t *sensor_data_len)
{
   return LDU_request(comm_params, SENSOR_DATA_REQUEST_HEADER, sensor_data, sensor_data_len);
}





/*************************************************************************************************************************************************************/
// deprecated
uint8_t LDU_requestMAC(LDU_struct *comm_params, uint8_t *sensor_mac, uint16_t *sensor_mac_length)
{
    return LDU_request(comm_params, SENSOR_MAC_ADDRESS_REQUEST_HEADER, sensor_mac, sensor_mac_length);
}

