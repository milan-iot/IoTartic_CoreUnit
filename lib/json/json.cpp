#include "json.h"

/**
 * Function that copies data from json to array
 * @param _data - Pointer to data in json document
 * @param data - Pointer to array
 * @param data_size - Size of array
 * @return Returns true on succesful parse
**/
bool getJsonArray(const char *_data, char *data, uint16_t data_size)
{
  memset(data, 0x00, data_size);
  if (strlen(_data) <= data_size)
  {
    memcpy(data, _data, strlen(_data));
    return true;
  }
  else
    return false;
}


bool getJsonConfig(json_config *jc, DynamicJsonDocument *config)
{
    const char* _device_type = (*config)["device_type"];
    String device_type = String(_device_type);
    if (device_type == "SENSOR")
        jc->device_type = SENSOR;
    else if (device_type == "CORE")
        jc->device_type = CORE;
    else 
        return false;

    if (jc->device_type == SENSOR)
    {
        const uint16_t _standalone = (*config)["standalone"];
        if(_standalone == 1)
            jc->standalone = true;
        else 
            jc->standalone = false;
    }

    if ((jc->device_type == CORE) || ((jc->device_type == SENSOR) && jc->standalone))
    {
        const char* _comm_mode = (*config)["comm_mode"];
        String comm_mode = String(_comm_mode);
        if (comm_mode == "NON_ENCRYPTED_COMM")
            jc->comm_mode = NON_ENCRYPTED_COMM;
        else if (comm_mode == "ENCRYPTED_COMM")
            jc->comm_mode = ENCRYPTED_COMM;
        else
            return false;

        const char* _server_tunnel = (*config)["server_tunnel"];
        String server_tunnel = String(_server_tunnel);
        if (server_tunnel == "WIFI")
        {
            jc->server_tunnel = WIFI;

            const char *_wifi_ssid = (*config)["wifi"]["ssid"];
            getJsonArray(_wifi_ssid, jc->wifi_ssid, sizeof(jc->wifi_ssid));

            const char *_wifi_pass = (*config)["wifi"]["pass"];
            getJsonArray(_wifi_pass, jc->wifi_pass, sizeof(jc->wifi_pass));
        }
        else if (server_tunnel == "BG96")
        {
            jc->server_tunnel = BG96;

            const char *_apn = (*config)["bg96"]["apn"];
            getJsonArray(_apn, jc->apn, sizeof(jc->apn));

            const char *_apn_user = (*config)["bg96"]["apn_user"];
            getJsonArray(_apn_user, jc->apn_user, sizeof(jc->apn_user));

            const char *_apn_password = (*config)["bg96"]["apn_password"];
            getJsonArray(_apn_password, jc->apn_password, sizeof(jc->apn_password));
        }
        else
            return false;

        const char* _protocol = (*config)["protocol"];
        String protocol = String(_protocol);
        if (protocol == "UDP")
            jc->protocol = UDP;
        else if (protocol == "TCP")
            jc->protocol = TCP; 
        else if (protocol == "MQTT")
            jc->protocol = MQTT;
        else
            return false;

        switch (jc->protocol)
        {
            case UDP:
            {
                const char *_ip_udp = (*config)["udp_server"]["ip"];
                getJsonArray(_ip_udp, jc->ip, sizeof(jc->ip));         
                jc->port = (*config)["udp_server"]["port"];
                break;
            }
            case TCP:
            {
                const char *_ip_tcp = (*config)["tcp_server"]["ip"];
                getJsonArray(_ip_tcp, jc->ip, sizeof(jc->ip));
                jc->port = (*config)["tcp_server"]["port"];
                break;
            }
            case MQTT:
            {
                const char *_ip_mqtt = (*config)["mqtt_server"]["ip"];
                getJsonArray(_ip_mqtt, jc->ip, sizeof(jc->ip));
                jc->port = (*config)["mqtt_server"]["port"];

                const char *_subscribe_topic = (*config)["mqtt_server"]["mqtt_topics"]["subscribe_topic"];
                getJsonArray(_subscribe_topic, jc->subscribe_topic, sizeof(jc->subscribe_topic));
                const char *_publish_topic = (*config)["mqtt_server"]["mqtt_topics"]["publish_topic"];
                getJsonArray(_publish_topic, jc->publish_topic, sizeof(jc->publish_topic));
                const char *_client_id = (*config)["mqtt_server"]["client_id"];
                getJsonArray(_client_id, jc->client_id, sizeof(jc->client_id));
                break;
            }
        }

        const char *_server_salt = (*config)["cryptography"]["server_salt"];
        getJsonArray(_server_salt, jc->server_salt, sizeof(jc->server_salt));
        const char *_server_password = (*config)["cryptography"]["server_password"];
        getJsonArray(_server_password, jc->server_password, sizeof(jc->server_password));
    }

    if ((jc->device_type == CORE) || ((jc->device_type == SENSOR) && !jc->standalone))
    {
        const char* _local_tunnel = (*config)["local_tunnel"];
        String local_tunnel = String(_local_tunnel);
        if (local_tunnel == "BLE")
        {
            jc->local_tunnel = BLE;

            const char *_serv_uuid = (*config)["ble"]["SERV_UUID"];
            getJsonArray(_serv_uuid, jc->serv_uuid, sizeof(jc->serv_uuid));
            const char *_char_uuid = (*config)["ble"]["CHAR_UUID"];
            getJsonArray(_char_uuid, jc->char_uuid, sizeof(jc->char_uuid));

            const char *_ble_password = (*config)["cryptography"]["ble_password"];
            getJsonArray(_ble_password, jc->ble_password, sizeof(jc->ble_password));
        }
        else if (local_tunnel == "RS485")
            jc->local_tunnel = RS485;
        else
            return false;
    }
    
    return true;
}