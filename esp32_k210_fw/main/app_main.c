/* ESP32 as Kendryte K210 peripheral

   Copyright LoBo 2020
*/

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>


#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/igmp.h"

#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "soc/rtc_periph.h"
#include "esp_spi_flash.h"
#include "driver/gpio.h"
#include "esp32/rom/rtc.h"
#include "driver/rtc_io.h"
#include "esp_sleep.h"
#include "esp_spiffs.h"
#include "driver/adc.h"
#include "esp_ota_ops.h"

#include "global.h"

#define GPIO_MASK       0x0000000F0EEFFFFFULL

#define ID_RTC_TIME     0x5AA5D17A
#define DEFAULT_TIME    1595592000

bool vdd_enabled = false;
xQueueHandle main_evt_queue = NULL;
QueueHandle_t status_mutex = NULL;
uint8_t debug_log = 0;

static const char *TAG = "[MAIN]";
static uint32_t reset_reason;
static esp_sleep_source_t wake_reason;
static bool use_vcc_en  = false;
const uint32_t wakeup_intervals[6] = {300, 600, 900, 1200, 1800, 3600};
uint32_t esp32_status = ESP32_STATUS_KPAD_MASK;

// === Variables preserved during Deep sleep ===
RTC_NOINIT_ATTR struct timeval sleep_enter_time;
RTC_NOINIT_ATTR struct timeval sleep_exit_time;
RTC_NOINIT_ATTR struct timeval wakeup_time;
RTC_NOINIT_ATTR uint32_t rtc_time_id;
RTC_NOINIT_ATTR uint32_t wakeup_interval;

RTC_NOINIT_ATTR uint8_t rtc_ram[RTCRAM_BUFF_SIZE];

//-----------------------------------------
void setStatus(uint32_t status, uint8_t op)
{
    bool f = pdTRUE;
    if (status_mutex) f = xSemaphoreTake(status_mutex, 1000);
    if (op == SET_STATUS_OP_SET) esp32_status = status;
    else if (op == SET_STATUS_OP_AND) esp32_status &= status;
    else if (op == SET_STATUS_OP_OR) esp32_status |= status;
    if ((status_mutex) && (f)) xSemaphoreGive(status_mutex);
}

//------------------
uint32_t getStatus()
{
    bool f = pdTRUE;
    uint32_t status = 0;
    if (status_mutex) f = xSemaphoreTake(status_mutex, 1000);
    status = esp32_status;
    if ((status_mutex) && (f)) xSemaphoreGive(status_mutex);
    return status;
}

// Function to initialize SPIFFS
//--------------------------------
static esp_err_t init_spiffs(void)
{
    if (debug_log >= 1) ESP_LOGI(TAG, "Initializing SPIFFS");

    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = NULL,
      .max_files = 5,   // This decides the maximum number of files could be open at the same time
      .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            if (debug_log >= 1) ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            if (debug_log >= 1) ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            if (debug_log >= 1) ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return ESP_FAIL;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
        return ESP_FAIL;
    }

    if (debug_log >= 1) ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    return ESP_OK;
}


//--------------------------------
static void vccEnable(bool enable)
{
    if (use_vcc_en) {
        gpio_set_level(VCC_EN_PIN, enable);
        if (enable) vTaskDelay(pdMS_TO_TICKS(500));
        vdd_enabled = enable;
    }
}

//--------------------------
static void init_times(void)
{
    sleep_exit_time.tv_sec = DEFAULT_TIME;
    sleep_exit_time.tv_usec = 0;
    sleep_enter_time.tv_sec = DEFAULT_TIME;
    sleep_enter_time.tv_usec = 0;
    settimeofday(&sleep_exit_time, NULL);
    setStatus(ESP32_STATUS_TIME_BAD, SET_STATUS_OP_OR);
    wakeup_time.tv_sec = DEFAULT_TIME;
    wakeup_time.tv_usec = 0;
    wakeup_interval = 1800;
}

//----------------------------------
static void prepare_pins_for_sleep()
{
    gpio_config_t pin_conf;

    gpio_pad_select_gpio(VCC_EN_PIN);
    gpio_pad_select_gpio(GPIO_HANDSHAKE);
    gpio_pad_select_gpio(GPIO_CS);
    gpio_pad_select_gpio(GPIO_MOSI);
    gpio_pad_select_gpio(GPIO_MISO);
    gpio_pad_select_gpio(GPIO_SCLK);
    gpio_pad_select_gpio(GPIO_NUM_25);
    gpio_pad_select_gpio(GPIO_NUM_26);
    gpio_pad_select_gpio(ADC1_PIN);
    gpio_pad_select_gpio(ADC2_PIN);

    pin_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    pin_conf.mode = GPIO_MODE_OUTPUT;
    pin_conf.pin_bit_mask = (1ULL<<WDT_RESET_PIN) | (1ULL<<GPIO_HANDSHAKE) |
                            (1ULL<<GPIO_CS) | (1ULL<<GPIO_MOSI) | (1ULL<<GPIO_MISO) |
                            (1ULL<GPIO_SCLK) | (1ULL<GPIO_NUM_25) | (1ULL<GPIO_NUM_26);
    if (use_vcc_en) {
        pin_conf.pin_bit_mask |= (1ULL<<VCC_EN_PIN);
    }
    pin_conf.pull_down_en = 0;
    pin_conf.pull_up_en = 0;

    gpio_config(&pin_conf);

    if (use_vcc_en) gpio_set_level(VCC_EN_PIN, false);
    gpio_set_level(WDT_RESET_PIN, true);
    gpio_set_level(GPIO_HANDSHAKE, false);
    gpio_set_level(GPIO_CS, false);
    gpio_set_level(GPIO_MOSI, false);
    gpio_set_level(GPIO_MISO, false);
    gpio_set_level(GPIO_SCLK, false);
    gpio_set_level(GPIO_NUM_25, false);
    gpio_set_level(GPIO_NUM_26, false);

    gpio_reset_pin(ADC1_PIN);
    gpio_reset_pin(ADC2_PIN);
    gpio_reset_pin(KPAD1);

    for (int i = 1; i < GPIO_PIN_COUNT; i++) {
        if (rtc_gpio_is_valid_gpio(i)) {
            if ((i != VCC_EN_PIN) & (i != GPIO_HANDSHAKE) & (i != GPIO_MISO) & (i != GPIO_SCLK) & (i != GPIO_MOSI) & (i != GPIO_CS) & (i != 32) & (i != 33)) rtc_gpio_isolate(i);
        }
    }
    // Hold pins state during sleep
    // gpio_deep_sleep_hold_en();

    esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_OFF);
    esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_SLOW_MEM, ESP_PD_OPTION_ON);
    esp_sleep_pd_config(ESP_PD_DOMAIN_XTAL, ESP_PD_OPTION_ON);
    // Enable EXT1 wakeup on pin KPAD2
    esp_sleep_enable_ext1_wakeup((1ULL << KPAD2), ESP_EXT1_WAKEUP_ALL_LOW);
    // Enable EXT0 wakeup on pin KPAD1
    //esp_sleep_enable_ext0_wakeup((gpio_num_t)KPAD1, 0);
}

//Main application
//=================
void app_main(void)
{
    struct tm *tm_info;
    char str_time[128];
    time_t sleep_time;
    int sleep_time_ms = 0;

    status_mutex = xSemaphoreCreateMutex();

    printf("* ESP32-K210 ver. %s\r\n", VERSION_STR);
    // Get the time at reset
    if (rtc_time_id == ID_RTC_TIME) {
        printf("* RTC memory ok.\r\n");
        gettimeofday(&sleep_exit_time, NULL);
        sleep_time_ms = (sleep_exit_time.tv_sec - sleep_enter_time.tv_sec) * 1000 + (sleep_exit_time.tv_usec - sleep_enter_time.tv_usec) / 1000;
        if (sleep_exit_time.tv_sec < DEFAULT_TIME) {
            printf("* RTC memory sleep exit time corrupted\r\n");
            init_times();
        }
    }
    else {
        printf("* RTC memory corrupted\r\n");
        rtc_time_id = ID_RTC_TIME;
        init_times();
    }
    // check wakeup interval
    int wkupint = 6;
    for (wkupint=0; wkupint<6; wkupint++) {
        if (wakeup_interval == wakeup_intervals[wkupint]) break;
    }
    if (wkupint >= 6) wakeup_interval = 1800;

    rtc_gpio_deinit(KPAD2);
    gpio_pad_select_gpio(VCC_EN_PIN);
    gpio_pad_select_gpio(GPIO_HANDSHAKE);
    gpio_pad_select_gpio(GPIO_CS);
    gpio_pad_select_gpio(GPIO_MOSI);
    gpio_pad_select_gpio(GPIO_MISO);
    gpio_pad_select_gpio(GPIO_SCLK);
    gpio_pad_select_gpio(GPIO_NUM_25);
    gpio_pad_select_gpio(GPIO_NUM_26);
    gpio_pad_select_gpio(KPAD1);
    gpio_pad_select_gpio(KPAD2);
    gpio_pad_select_gpio(KPAD3);
    gpio_pad_select_gpio(KPAD4);
    gpio_pad_select_gpio(ADC1_PIN);
    gpio_pad_select_gpio(ADC2_PIN);

    //Initialize or reinitialize TWDT
    CHECK_ERROR_CODE(esp_task_wdt_init(TWDT_TIMEOUT_S, true), ESP_OK);
    esp_task_wdt_add(NULL);
    //Subscribe Idle Tasks to TWDT if they were not subscribed at startup
    #ifndef CONFIG_ESP_TASK_WDT_CHECK_IDLE_TASK_CPU0
    esp_task_wdt_add(xTaskGetIdleTaskHandleForCPU(0));
    #endif
    #ifndef CONFIG_ESP_TASK_WDT_CHECK_IDLE_TASK_CPU1
    esp_task_wdt_add(xTaskGetIdleTaskHandleForCPU(1));
    #endif

    // Set log levels for various modules
    debug_log = 0;
    esp_log_level_set("wifi", ESP_LOG_WARN);
    esp_log_level_set("phy", ESP_LOG_WARN);
    esp_log_level_set("tcpip_adapter", ESP_LOG_WARN);
    esp_log_level_set("gpio", ESP_LOG_WARN);
    esp_log_level_set("system_api", ESP_LOG_WARN);

    // Create a queue to handle events from other tasks
    main_evt_queue = xQueueCreate(2, sizeof(uint32_t));

    // ==== Check and store reset reason ====
	reset_reason = rtc_get_reset_reason(0);
	reset_reason &= 0x1F;
    wake_reason = esp_sleep_get_wakeup_cause();
    if (reset_reason != DEEPSLEEP_RESET) {
        printf("* RESET Wake up (reason: %02X)\r\n", reset_reason);
        debug_log = 1;
        setStatus((uint32_t)(reset_reason << 20), SET_STATUS_OP_OR);
    }
    else {
        printf("* Deep sleep Wake up: sleep time = %d ms, reason: %d\r\n", sleep_time_ms, wake_reason);
        switch (wake_reason) {
            case ESP_SLEEP_WAKEUP_EXT0: {
                printf("* Wake up from EXT0 GPIO\r\n");
                debug_log = 1;
                reset_reason = ESP32_STATUS_WAKE_EXT0;
                break;
            }
            case ESP_SLEEP_WAKEUP_EXT1: {
                uint64_t wakeup_pin_mask = esp_sleep_get_ext1_wakeup_status();
                if (wakeup_pin_mask != 0) {
                    int pin = __builtin_ffsll(wakeup_pin_mask) - 1;
                    printf("* Wake up from EXT1 GPIO_%d\r\n", pin);
                } else {
                    printf("* Wake up from EXT1 GPIO\r\n");
                }
                debug_log = 1;
                reset_reason = ESP32_STATUS_WAKE_EXT1;
                break;
            }
            case ESP_SLEEP_WAKEUP_TIMER: {
                printf("* Wake up from Timer");
                reset_reason = ESP32_STATUS_WAKE_TIMR;
                break;
            }
            case ESP_SLEEP_WAKEUP_UNDEFINED:
            default: {
                printf("* Other wake up reason (%d)\r\n", wake_reason);
                debug_log = 1;
            }
        }
        setStatus((uint32_t)(reset_reason << 20), SET_STATUS_OP_OR);
    }

    if (debug_log >= 1) {
        const esp_partition_t *running_partition = esp_ota_get_running_partition();
        if (running_partition != NULL) {
            printf("* Running from partition '%s'\r\n", running_partition->label);
        }
        else {
            printf("* Running partition cannot be determined\r\n");
        }
    }

    time_t seconds = sleep_exit_time.tv_sec;
    //time(&seconds); // get the time from the RTC
    tm_info = gmtime(&seconds);
    strftime(str_time, 127, "%c", tm_info);
    printf("*  START time: %s (+%03lu ms)\r\n", str_time, sleep_exit_time.tv_usec/1000);

    seconds = sleep_enter_time.tv_sec;
    tm_info = gmtime(&seconds);
    strftime(str_time, 127, "%c", tm_info);
    printf("*  SLEEP time: %s (+%03lu ms)\r\n", str_time, sleep_enter_time.tv_usec/1000);

    seconds = wakeup_time.tv_sec;
    tm_info = gmtime(&seconds);
    strftime(str_time, 127, "%c", tm_info);
    printf("* WAKEUP time: %s\r\n", str_time);

    // Install gpio isr service
    gpio_install_isr_service(ESP_INTR_FLAG_LOWMED | ESP_INTR_FLAG_IRAM);

    // =============================
    // ==== Configure VCC_EN pin ===
    // =============================
    gpio_config_t pin_conf;
    pin_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    pin_conf.mode = GPIO_MODE_INPUT;
    pin_conf.pin_bit_mask = 1ULL<<VCC_EN_PIN;
    pin_conf.pull_down_en = 0;
    pin_conf.pull_up_en = 0;
    gpio_config(&pin_conf);
    if (gpio_get_level(VCC_EN_PIN) == 0) {
        gpio_set_direction(VCC_EN_PIN, GPIO_MODE_OUTPUT);
        use_vcc_en = true;
    }
    else {
        printf("* K210 already powered on.\r\n");
    }

    // ================================
    // ==== Configure WDT_RESET pin ===
    // ================================
    pin_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    pin_conf.mode = GPIO_MODE_OUTPUT;
    pin_conf.pin_bit_mask = 1ULL<<WDT_RESET_PIN;
    pin_conf.pull_down_en = 0;
    pin_conf.pull_up_en = 0;
    gpio_config(&pin_conf);
    gpio_set_level(WDT_RESET_PIN, false);

    // Turn off VCC/VDD for now
    vccEnable(false);
    // ========================================


    // =======================================
    // ==== Initialize NVS Flash =============
    // =======================================
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "Erasing NVS partition");
        ret = nvs_flash_erase();
        if (ret == ESP_OK) ret = nvs_flash_init();
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS initialization failed");
    }
    // =======================================

    // Initialize file system
    if (init_spiffs() == ESP_OK) setStatus(ESP32_STATUS_FS_OK, SET_STATUS_OP_OR);

    // Start the needed tasks

    #if USE_ADC
    // ==== Start ADC task ===============================================
    xTaskCreatePinnedToCore(ADC_task, "ADC task", 2048, NULL, 4, NULL, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    // ===================================================================
    #endif

    #if USE_KEYPAD
    // ==== Start Keypad task =================================================
    xTaskCreatePinnedToCore(KeypadTask, "Keypad task", 2048, NULL, 2, NULL, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    // ========================================================================
    #endif

    // ==== Start OTA task ===============================================
    xTaskCreatePinnedToCore(OTA_task, "OTA task", 2048, NULL, 2, NULL, 0);
    vTaskDelay(pdMS_TO_TICKS(10));

    // ==== Start SPI task ===========================================================
    xTaskCreatePinnedToCore(SPI_task, "SPI task", 4096, NULL, 7, &spi_task_handle, 1);
    vTaskDelay(pdMS_TO_TICKS(50));
    // ===============================================================================

    // === Turn ON VCC/VDD, power on K210 ===
    printf("* Turn on K210\r\n");
    vTaskDelay(pdMS_TO_TICKS(100));
    vccEnable(true);

    // Main loop
    // Wait for deep sleep request
    while (1) {
        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
        if (xQueueReceive(main_evt_queue, &sleep_time, pdMS_TO_TICKS(1000)) == pdTRUE) {
            // Sleep until 'sleep_time' (linux time stamp)
            gettimeofday(&sleep_enter_time, NULL);
            time_t sleep_period = sleep_time - sleep_enter_time.tv_sec;
            if (sleep_period >= 60) {
                esp_sleep_enable_timer_wakeup((uint64_t)sleep_period * 1000000);
                wakeup_time.tv_sec = sleep_time;
                wakeup_time.tv_usec = 0;
                // Turn OFF VCC/VDD, powers off K210
                vccEnable(false);

                prepare_pins_for_sleep();
                esp_wifi_stop();
                adc_power_off();;

                // === Enter deep sleep ===
                printf("* DEEP SLEEP for %lu seconds\r\n", sleep_period);
                vTaskDelay(pdMS_TO_TICKS(10));
                esp_deep_sleep_start();
            }
        }
    }

}

