
#include <string.h>
#include "global.h"
#include "esp_event.h"
#include "driver/gpio.h"
#include "freertos/event_groups.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "tcpip_adapter.h"
#include "esp_http_client.h"
#include "esp_tls.h"
#include "esp32/rom/crc.h"
#include "esp_sntp.h"


#define WIFI_ESP_MAXIMUM_RETRY  3
#define DEFAULT_SNTP_SERVER     "pool.ntp.org"


/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

bool wifi_is_init = false;
bool wifi_is_connected = false;
bool wifi_connect_failed = false;
char wifi_ip_address[16] = {0};
char wifi_netmask[16] = {0};
char wifi_gateway[16] = {0};
uint8_t sta_ssid[32] = "LoBoInternet";      // SSID of target AP. Null terminated string.
uint8_t sta_password[64] = "1412lobo956";   // Password of target AP. Null terminated string.
uint8_t ap_ssid[32] = "ESP32_AP";           // SSID of ESP32 AP. Null terminated string.
uint8_t ap_password[64] = "";               // Password of target AP. Null terminated string.

static EventGroupHandle_t s_wifi_event_group = NULL;

#ifdef CONFIG_MKM_CONNECT_IPV6
static esp_ip6_addr_t s_ipv6_addr;
#endif

static const char *TAG = "[WIFI_STA_AP]";
static int s_retry_num = 0;
static bool tcpip_adapter_is_init = false;

//------------------------------------------------
void time_sync_notification_cb(struct timeval *tv)
{
    uint32_t seconds = tv->tv_sec;

    if (sntp_enabled()) sntp_stop();

    time_t now = seconds;
    struct tm timeinfo;
    char strftime_buf[64];
    // Set time zone
    setenv("TZ", "CET-1CEST", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    if (debug_log >= 1) ESP_LOGI(TAG, "Time synchronized: %s (%u)", strftime_buf, seconds);
    k210_status_send(ESP32_STATUS_CODE_TIME, seconds);
}

//-------------------------------
static void initialize_sntp(void)
{
    if (debug_log >= 1) ESP_LOGI(TAG, "Initializing SNTP");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, DEFAULT_SNTP_SERVER);
    sntp_set_time_sync_notification_cb(time_sync_notification_cb);
#ifdef CONFIG_SNTP_TIME_SYNC_METHOD_SMOOTH
    sntp_set_sync_mode(SNTP_SYNC_MODE_SMOOTH);
#else
    sntp_set_sync_mode(SNTP_SYNC_MODE_IMMED);
#endif
    sntp_init();
}

//---------------------------------------------------------------------------------------------------
static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        setStatus(~ESP32_STATUS_WIFI_CONNECTED, SET_STATUS_OP_AND);
        wifi_is_connected = false;
        wifi_connect_failed = false;
        if (debug_log >= 2) ESP_LOGI(TAG, "Connect...");
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (sntp_enabled()) sntp_stop();
        if (s_retry_num < WIFI_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            if (debug_log >= 2) ESP_LOGI(TAG, "retry to connect to the AP (%d)", s_retry_num);
        }
        else {
            if (debug_log >= 1) ESP_LOGE(TAG,"connect to the AP failed [ssid=%s, pass=%s)", (char *)sta_ssid, (char *)sta_password);
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
            wifi_connect_failed = true;
        }
        wifi_is_connected = false;
        setStatus(~ESP32_STATUS_WIFI_CONNECTED, SET_STATUS_OP_AND);
        // Send to K210
        k210_status_send(ESP32_STATUS_CODE_STATUS, getStatus());
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        strcpy(wifi_ip_address, ip4addr_ntoa(&event->ip_info.ip));
        strcpy(wifi_netmask, ip4addr_ntoa(&event->ip_info.netmask));
        strcpy(wifi_gateway, ip4addr_ntoa(&event->ip_info.gw));
        if (debug_log >= 1) ESP_LOGI(TAG, "  IP: %s", wifi_ip_address);
        if (debug_log >= 1) ESP_LOGI(TAG, "MASK: %s", wifi_netmask);
        if (debug_log >= 1) ESP_LOGI(TAG, "  GW: %s\r\n", wifi_gateway);
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        wifi_is_connected = true;
        setStatus(ESP32_STATUS_WIFI_CONNECTED, SET_STATUS_OP_OR);
        wifi_connect_failed = false;
        k210_status_send(ESP32_STATUS_CODE_STATUS, getStatus());

        initialize_sntp();

        if (debug_log >= 1) getStatsInfo(false, true);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_START) {
        setStatus(ESP32_STATUS_WIFI_MODEAP | ESP32_STATUS_WIFI_CONNECTED, SET_STATUS_OP_OR);
        wifi_is_connected = true;
        if (debug_log >= 2) ESP_LOGI(TAG, "AP mode start...");
        k210_status_send(ESP32_STATUS_CODE_STATUS, getStatus());
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STOP) {
        setStatus(~(ESP32_STATUS_WIFI_MODEAP | ESP32_STATUS_WIFI_CONNECTED), SET_STATUS_OP_AND);
        wifi_is_connected = false;
        if (debug_log >= 2) ESP_LOGI(TAG, "AP mode stop...");
        k210_status_send(ESP32_STATUS_CODE_STATUS, getStatus());
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        if (debug_log >= 2) {
            wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
            ESP_LOGI(TAG, "Station connected "MACSTR" join, AID=%d", MAC2STR(event->mac), event->aid);
        }
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        if (debug_log >= 2) {
            wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
            ESP_LOGI(TAG, "Station disconnected "MACSTR" leave, AID=%d", MAC2STR(event->mac), event->aid);
        }
    }
}

//===========================
void wifi_deinit_sta_ap(void)
{
    if (sntp_enabled()) sntp_stop();
    if (s_wifi_event_group) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = NULL;
    }

    esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler);
    esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler);
    esp_wifi_stop();
    esp_wifi_deinit();

    wifi_is_init = false;
    wifi_is_connected = false;
    setStatus(~(ESP32_STATUS_WIFI_INIT | ESP32_STATUS_WIFI_MODEAP), SET_STATUS_OP_AND);
    if (debug_log >= 2) ESP_LOGI(TAG, "Wifi deinitialized");
}

//====================================
int wifi_init_sta_ap(wifi_mode_t mode)
{
    if (s_wifi_event_group == NULL) s_wifi_event_group = xEventGroupCreate();
    if (s_wifi_event_group == NULL) return -1;

    if (!tcpip_adapter_is_init) {
        tcpip_adapter_init();
        tcpip_adapter_is_init = true;
    }

    if (esp_event_loop_create_default() != ESP_OK) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = NULL;
        return -2;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&cfg) != ESP_OK) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = NULL;
        return -3;
    }

    if (esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL) != ESP_OK) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = NULL;
        return -4;
    }
    if (esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL) != ESP_OK) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = NULL;
        esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler);
        return -5;
    }

    setStatus(~ESP32_STATUS_WIFI_MODEAP, SET_STATUS_OP_AND);
    wifi_config_t wifi_config = {0};
    if (mode == WIFI_MODE_STA) {
        memcpy(wifi_config.sta.ssid, sta_ssid, 32);
        memcpy(wifi_config.sta.password, sta_password, 64);
        if (debug_log >= 2) ESP_LOGI(TAG, "Connect to AP: %s, %s", (char *)wifi_config.sta.ssid, (char *)wifi_config.sta.password);
    }
    else if (mode == WIFI_MODE_AP) {
        memcpy(wifi_config.ap.ssid, ap_ssid, 32);
        memcpy(wifi_config.ap.password, ap_password, 64);
        if (strlen((char *)wifi_config.ap.password) == 0) wifi_config.ap.authmode = WIFI_AUTH_OPEN;
        else wifi_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
        wifi_config.ap.max_connection = 8;
        if (debug_log >= 2) ESP_LOGI(TAG, "AP mode: %s, %s", (char *)wifi_config.ap.ssid, (char *)wifi_config.ap.password);
    }
    else {
        return -6;
    }
    // Set WiFi mode
    if (esp_wifi_set_mode(mode) != ESP_OK) goto error;
    if (esp_wifi_set_config((mode == WIFI_MODE_STA) ? ESP_IF_WIFI_STA : ESP_IF_WIFI_AP, &wifi_config) != ESP_OK) goto error;
    if (esp_wifi_start() != ESP_OK) goto error;

    wifi_is_init = true;
    setStatus(ESP32_STATUS_WIFI_INIT, SET_STATUS_OP_OR);
    if (debug_log >= 1) ESP_LOGI(TAG, "WiFi initialized.");

    int8_t power;
    if (esp_wifi_get_max_tx_power(&power) == ESP_OK) {
        if (debug_log >= 1) ESP_LOGI(TAG, "Max WiFi Tx power: %.2f dBm", (float)power * 0.25);
    }
    /*
    // Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
    // number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above)
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    // xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually happened.
    if (bits & WIFI_CONNECTED_BIT) {
        if (debug_log >= 2) ESP_LOGI(TAG, "connected to AP, SSID: %s,  password: %s", sta_ssid, sta_password);
    }
    else if (bits & WIFI_FAIL_BIT) {
        if (debug_log >= 2) ESP_LOGI(TAG, "Failed to connect to SSID: %s, password: %s", sta_ssid, sta_password);
    }
    else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
        goto error;
    }
    */

    return 0;

error:
    wifi_deinit_sta_ap();
    return -7;
}

//=======================================================================================================

// Web server

//-----------------------------------------------
esp_err_t start_web_server(const char *base_path)
{
    if ((getStatus() & ESP32_STATUS_FS_OK) && (wifi_is_connected)) {
        struct stat entry_stat;
        if (stat("/spiffs/www", &entry_stat) == -1) {
            mkdir("/spiffs/www", 0);
        }
        if (debug_log >= 1) ESP_LOGI(TAG, "Starting file server");
        esp_err_t ret = start_file_server(base_path);
        if (ret == ESP_OK)setStatus(ESP32_STATUS_WEBSERVER_OK, SET_STATUS_OP_OR);
        else {
            setStatus(~ESP32_STATUS_WEBSERVER_OK, SET_STATUS_OP_AND);
            return ESP_FAIL;
        }
        return ESP_OK;
    }
    else return ESP_FAIL;
}


//=======================================================================================================

// Http client

#define MAX_HTTP_RECV_BUFFER 512
static const char *TAG_HTTP = "[HTTPCLIENT]";
static uint8_t *body_buff = NULL;
static char *rqheader = NULL;
static uint32_t body_length, body_ptr;
static int rqheader_ptr = 0;
static int rqheader_len = 0;
static bool send_to_master = false;
static uint32_t sent_bytes = 0;
static uint32_t spi_time = 0;


//------------------------------
static void send_block_to_host()
{
    // Command was received and requires response, prepare response
    *((uint16_t *)(SPI_RW_BUFFER)) = esp_cmdstat;
    *((uint16_t *)(SPI_RW_BUFFER + 2)) = esp_len;
    uint32_t crc = crc32_le(0, SPI_RW_BUFFER, esp_len+4);
    memcpy(SPI_RW_BUFFER + esp_len + 4, (void *)&crc, 4);
    setCRC(SPI_RW_BUFFER, esp_len+8);

    uint64_t tstart = esp_timer_get_time();
    int ret = transferData(SLAVE_CMD_WRITE | SLAVE_CMD_OPT_CRC, SLAVE_BUFFER_CMD_ADDRESS, esp_len+8, NULL);
    spi_time += (esp_timer_get_time() - tstart);

    if (ret == ESP_OK) {
        sent_bytes += esp_len;
        // wait for confirmation handshake pulse
        ret = k210_wait_handshake();
        if (ret != ESP_OK) {
            send_to_master = false;
            if (debug_log >= 1) ESP_LOGW(TAG_HTTP, "Send to K210: no handshake (%d)", ret);
            return;
        }
    }
    else send_to_master = false;
}

//=========================================================
esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            if (debug_log >= 3) ESP_LOGI(TAG_HTTP, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            if (debug_log >= 3) ESP_LOGI(TAG_HTTP, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADERS_SENT:
            if (debug_log >= 3) ESP_LOGI(TAG_HTTP, "HTTP_EVENT_HEADERS_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            if (debug_log >= 3) ESP_LOGI(TAG_HTTP, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            if (rqheader) {
                int len = strlen(evt->header_key) + strlen(evt->header_value) + rqheader_ptr + 5;
                if (len < rqheader_len) {
                    strcat(rqheader, evt->header_key);
                    strcat(rqheader, ": ");
                    strcat(rqheader, evt->header_value);
                    strcat(rqheader, "\r\n");
                    rqheader_ptr = strlen(rqheader);
                }
            }
            break;
        case HTTP_EVENT_ON_DATA:
            if (debug_log >= 3) ESP_LOGI(TAG_HTTP, "HTTP_EVENT_ON_DATA, len=%d%s (%d)", evt->data_len, (esp_http_client_is_chunked_response(evt->client)) ? " chunked" : "", send_to_master);
            if ((body_buff) && (send_to_master)) {
                for (int i=0; i<evt->data_len; i++) {
                    body_buff[body_ptr++] = ((uint8_t *)evt->data)[i];
                    if (body_ptr >= body_length) {
                        // Buffer full, send it to K210
                        esp_len = body_ptr;
                        esp_cmdstat &= 0x00FF;
                        esp_cmdstat |= ESP_STATUS_MULTIBLOCK;
                        send_block_to_host();
                        body_ptr = 0;
                        if (!send_to_master) break;
                    }
                }
            }
            CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);

            break;
        case HTTP_EVENT_ON_FINISH:
            if (debug_log >= 3) ESP_LOGI(TAG_HTTP, "HTTP_EVENT_ON_FINISH");
            if ((body_ptr > 0) && (send_to_master)) {
                // Buffer not empty, send it to K210
                esp_len = body_ptr;
                esp_cmdstat &= 0x00FF;
                esp_cmdstat |= ESP_STATUS_MULTIBLOCK;
                send_block_to_host();
            }
            break;
        case HTTP_EVENT_DISCONNECTED:
            if (debug_log >= 2) ESP_LOGI(TAG_HTTP, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                if (debug_log >= 2) ESP_LOGI(TAG_HTTP, "Last esp error code: 0x%x", err);
                if (debug_log >= 2) ESP_LOGI(TAG_HTTP, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            break;
    }
    return ESP_OK;
}

//==========================
void requests_GET(char *url)
{
    if (!wifi_is_connected) {
        if (debug_log >= 1) ESP_LOGE(TAG_HTTP, "GET: WiFi not conected");
        esp_cmdstat |= ESP_ERROR_NOTCONNECTED;
        esp_len = 0;
        return;
    }
    body_buff = SPI_RW_BUFFER+4;
    body_length = spi_master_buffer_size - 64;
    body_ptr = 0;
    rqheader = NULL;
    rqheader_len = 0;
    rqheader_ptr = 0;
    sent_bytes = 0;
    spi_time = 0;
    if (rqheader) memset(rqheader, 0, rqheader_len);

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .buffer_size = 2048,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        if (debug_log >= 1) ESP_LOGE(TAG_HTTP, "GET: HttpClient init failed");
        esp_cmdstat &= 0x00FF;
        esp_cmdstat |= ESP_ERROR_PROCESS;
        esp_len = 0;
        return;
    }

    // GET
    send_to_master = true;
    uint64_t tstart = esp_timer_get_time();

    esp_err_t err = esp_http_client_perform(client);

    uint64_t tend = esp_timer_get_time();
    body_buff = NULL;
    rqheader = NULL;
    if (err == ESP_OK) {
        if (debug_log >= 1) ESP_LOGI(TAG_HTTP, "GET: Status = %d, content_length = %d, sent=%u, time=%llu us (spi: %u)",
                esp_http_client_get_status_code(client), esp_http_client_get_content_length(client),
                sent_bytes, tend - tstart, spi_time);
        int cont_len = esp_http_client_get_content_length(client);
        esp_cmdstat &= 0x00FF;
        esp_cmdstat |= ESP_STATUS_RQFINISH;
        memcpy(SPI_RW_BUFFER+4, (void *)&cont_len, sizeof(int));
        esp_len = sizeof(int);
    }
    else {
        if (debug_log >= 1) ESP_LOGE(TAG_HTTP, "GET: request failed: %s", esp_err_to_name(err));
        esp_cmdstat &= 0x00FF;
        esp_cmdstat |= ESP_ERROR_PROCESS;
        esp_len = 0;
    }

    esp_http_client_cleanup(client);
}

