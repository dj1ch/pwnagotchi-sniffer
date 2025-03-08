#include <sniffer.h>
#include <arpa/inet.h>

bool found = false;

/**
 * @brief start the sniffer upon boot
 */
sniffer::sniffer()
{
    // create configs
    wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    wifi_country = {
        .cc = "US",
        .schan = 1,
        .nchan = 13,
        .max_tx_power = 20,
        .policy = WIFI_COUNTRY_POLICY_AUTO
    };
    
    // weird hack but i guess it works
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    initialize_nvs();

    // initialize wifi
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_country((const wifi_country_t *)&wifi_country));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // start monitor mode
    start_monitor_mode();

    printf("Sniffer Initialized!\n"); // call me weird, but I prefer printf over std::cout
}

/**
 * @brief clear NVS if called
 */
void sniffer::initialize_nvs()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
}

/**
 * @brief start monitor mode for sniffing
 */
void sniffer::start_monitor_mode()
{
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
}

/**
 * @brief stop monitor mode
 */
void sniffer::stop_monitor_mode()
{
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
}

/**
 * @brief get mac address
 */
void sniffer::get_mac(char *addr, const unsigned char *buff, int offset)
{
    snprintf(addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x", buff[offset],
        buff[offset + 1], buff[offset + 2], buff[offset + 3],
        buff[offset + 4], buff[offset + 5]);
}

/**
 * @brief extract mac address and put into a string
 */
std::string sniffer::extract_mac(const unsigned char *buff)
{
    char addr[] = "00:00:00:00:00:00";
    get_mac(addr, buff, 10);
    return std::string(addr);
}

/**
 * @brief the callback to use for the sniffer
 */
void sniffer::sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t *)buf;
    // WifiMgmtHdr *frameControl = (WifiMgmtHdr *)snifferPacket->payload;
    // wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)snifferPacket->rx_ctrl;
    int len = snifferPacket->rx_ctrl.sig_len;
  
    // start off false
    found = false;
  
    if (type == WIFI_PKT_MGMT) {
        len -= 4;
        // int fctl = ntohs(frameControl->fctl);
        // const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)snifferPacket->payload;
        // const WifiMgmtHdr *hdr = &ipkt->hdr;
  
        // check if it is a beacon frame
        if (snifferPacket->payload[0] == 0x80) {
            // extract mac
            char addr[] = "00:00:00:00:00:00";
            get_mac(addr, snifferPacket->payload, 10);
            std::string src = addr;
  
            // check if the source MAC matches the target
            if (src == "de:ad:be:ef:de:ad") {
                found = true;
                printf("Pwnagotchi detected!\n");
  
                // extract the ESSID from the beacon frame
                std::string essid = "";
  
                // "borrowed" from ESP32 Marauder
                for (int i = 38; i < len; i++) {
                    if (isascii(snifferPacket->payload[i])) {
                        essid += (char)snifferPacket->payload[i];
                    } else {
                        essid += "?";
                    }
                }
  
                // network related info
                printf("RSSI: %d\n", snifferPacket->rx_ctrl.rssi);
                printf("Channel: %d\n", snifferPacket->rx_ctrl.channel);
                printf("BSSID: %s\n", addr);
                printf("ESSID: %s\n", essid.c_str());
  
                // parse the ESSID as JSON
                JsonDocument jsonBuffer;
                DeserializationError error = deserializeJson(jsonBuffer, essid);
  
                // check if json parsing is successful
                if (error) {
                    printf("Could not parse Pwnagotchi json: %s\n", error.c_str());
                } else {
                    printf("Successfully parsed json!\n");
                    // find minigotchi/palnagotchi
                    bool pal = jsonBuffer["pal"].as<bool>();
                    bool minigotchi = jsonBuffer["minigotchi"].as<bool>();
  
                    // find out some stats
                    std::string name = jsonBuffer["name"].as<std::string>();
                    std::string pwndTot = jsonBuffer["pwnd_tot"].as<std::string>();
  
                    if (name == "null") {
                        name = "N/A";
                    }
  
                    if (pwndTot == "null") {
                        pwndTot = "N/A";
                    }
  
                    std::string deviceType = "";
  
                    // minigotchi or palnagotchi stuff
                    if (minigotchi || pal) {
                        if (minigotchi) {
                            deviceType = "Minigotchi";
                        }
  
                        if (pal) {
                            deviceType = "Palnagotchi";
                        }
  
                        // show corresponding type
                        printf("%s name: %s\n", deviceType.c_str(), name.c_str());
                        printf("Pwned Networks: %s\n", pwndTot.c_str());
                    } else {
                        // this should be a pwnagotchi
                        printf("Pwnagotchi name: %s\n", name.c_str());
                        printf("Pwned Networks: %s\n", pwndTot.c_str());
                    }
  
                    // clear json buffer
                    jsonBuffer.clear();
                }
            }
        }
    }   
}

/**
 * @brief stop the sniffer
 */
void sniffer::stop_callback() { esp_wifi_set_promiscuous_rx_cb(NULL); };

/**
 * @brief start the sniffer
 */
void sniffer::sniff(int duration)
{
    // start the sniffer
    esp_wifi_set_promiscuous_rx_cb(sniffer_callback);

    if (duration != NULL)
    {
        vTaskDelay(pdMS_TO_TICKS(duration));
    }
    else
    {
        printf("No duration set, sniffing indefinitely\n");
    }

    if (!found)
    {
        stop_monitor_mode();
        stop_callback();

        printf("No Pwnagotchi found!\n");
    }
    else
    {
        stop_monitor_mode();
        stop_callback();

        if (found)
        {
            printf("Pwnagotchi found!\n");
        }
        else
        {
            printf("How did this happen?\n");
        }
    }
}