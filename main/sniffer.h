#pragma once

#include <iostream>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <string.h>
#include <cctype>
#include <ArduinoJson.h>

class sniffer {
    public:
        sniffer();

        static void sniff(int duration);
        static void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);
    private:
        static void stop_callback();

        static void get_mac(char *addr, const unsigned char *buff, int offset);
        static std::string extract_mac(const unsigned char *buff);

        static void start_monitor_mode();
        static void stop_monitor_mode();

        static void initialize_nvs();

        static bool found;

        wifi_init_config_t wifi_init_config;
        wifi_country_t wifi_country;

        typedef struct {
            int16_t fctl;
            int16_t duration;
            uint8_t da;
            uint8_t sa;
            uint8_t bssid;
            int16_t seqctl;
            unsigned char payload[];
          } __attribute__((packed)) WifiMgmtHdr;
        
          typedef struct {
            uint8_t payload[0];
            WifiMgmtHdr hdr;
          } wifi_ieee80211_packet_t;
};