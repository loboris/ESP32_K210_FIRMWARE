

#include "global.h"

#if USE_KEYPAD

#include "driver/gpio.h"
#include "driver/rtc_io.h"

uint8_t kpad_state = 0x0F;
static xQueueHandle keypad_evt_queue = NULL;

static const char *TAG = "[KEYPAD]";

//-----------------------------------------------
static void IRAM_ATTR gpio_isr_handler(void* arg)
{
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    uint32_t kpad = (uint32_t)arg;

    if (keypad_evt_queue) {
        gpio_intr_disable(KPAD1);
        gpio_intr_disable(KPAD2);
        gpio_intr_disable(KPAD3);
        gpio_intr_disable(KPAD4);

        xQueueSendFromISR(keypad_evt_queue, &kpad, &xHigherPriorityTaskWoken);
        if (xHigherPriorityTaskWoken) portYIELD_FROM_ISR();
    }
}

//----------------------
static void scanKeypad()
{
    uint32_t l1, l2, l3, l4;
    uint8_t n;
    bool f;
    // wait for unchanged levels on keypad pins
    n = 10;
    l1 = gpio_get_level(KPAD1);
    l2 = gpio_get_level(KPAD2);
    l3 = gpio_get_level(KPAD3);
    l4 = gpio_get_level(KPAD4);
    while (n) {
        f = true;
        vTaskDelay(pdMS_TO_TICKS(2));
        if (l1 != gpio_get_level(KPAD1)) f = false;
        else if (l2 != gpio_get_level(KPAD2)) f = false;
        else if (l3 != gpio_get_level(KPAD3)) f = false;
        else if (l4 != gpio_get_level(KPAD4)) f = false;
        if (f) n--;
        else {
            // start again
            l1 = gpio_get_level(KPAD1);
            l2 = gpio_get_level(KPAD2);
            l3 = gpio_get_level(KPAD3);
            l4 = gpio_get_level(KPAD4);
            n = 10;
        }
    }
    kpad_state = l1 | (l2 << 1) | (l3 << 2) | (l4 << 3);
}

//------------------------
void KeypadTask(void* arg)
{
    uint32_t kpad;
    uint8_t sent_state = 0x0F;

    // ==========================================
    // ==== Keypad configuration ================
    // ==========================================
    if (debug_log >= 2) ESP_LOGI(TAG, "Keypad task started");
    //Subscribe this task to TWDT, then check if it is subscribed
    CHECK_ERROR_CODE(esp_task_wdt_add(NULL), ESP_OK);
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_OK);

    gpio_config_t io_conf_tpk = {
        .intr_type=GPIO_INTR_ANYEDGE,
        .mode=GPIO_MODE_INPUT,
        .pull_up_en = 1,
        .pull_down_en = 0,
        .pin_bit_mask=(1ULL << KPAD1) | (1ULL << KPAD2) | (1ULL << KPAD3) | (1ULL << KPAD4)
    };
    gpio_config(&io_conf_tpk);
    // Configure KPAD1 for RTC
    /*rtc_gpio_init(KPAD1);
    rtc_gpio_set_direction(KPAD1, RTC_GPIO_MODE_INPUT_ONLY);
    rtc_gpio_pulldown_dis(KPAD1);
    rtc_gpio_pullup_en(KPAD1);
    rtc_gpio_hold_en(KPAD1);*/

    // Create a queue to handle gpio event from isr
    if (keypad_evt_queue == NULL) keypad_evt_queue = xQueueCreate(8, sizeof(uint32_t));
    if (keypad_evt_queue == NULL) {
        ESP_LOGE(TAG, "Keypad event queue not created!");
    }

    // Hook isr handler for specific gpio pin
    gpio_isr_handler_add(KPAD1, gpio_isr_handler, (void*)KPAD1);
    gpio_isr_handler_add(KPAD2, gpio_isr_handler, (void*)KPAD2);
    gpio_isr_handler_add(KPAD3, gpio_isr_handler, (void*)KPAD3);
    gpio_isr_handler_add(KPAD4, gpio_isr_handler, (void*)KPAD4);
    // ==========================================

    scanKeypad();
    if (debug_log >= 2) ESP_LOGI(TAG, "Waiting for key change...");

    while (1) {
        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
        if (xQueueReceive(keypad_evt_queue, &kpad, pdMS_TO_TICKS(1000)) == pdTRUE) {
            if (kpad == 0x5A0000) {
                // Terminate thread
                gpio_intr_disable(KPAD1);
                gpio_intr_disable(KPAD2);
                gpio_intr_disable(KPAD3);
                gpio_intr_disable(KPAD4);
                gpio_isr_handler_remove(KPAD1);
                gpio_isr_handler_remove(KPAD2);
                gpio_isr_handler_remove(KPAD3);
                gpio_isr_handler_remove(KPAD4);
                break;
            }
            // Key interrupt detected, scan the keypad
            scanKeypad();

            if (sent_state != kpad_state) {
                // Keypad state not yet sent to K210
                sent_state = kpad_state;
                // Save in global esp32 status
                setStatus((uint32_t)(kpad_state << 28) | ESP32_STATUS_KPAD_CHANGED, SET_STATUS_OP_OR);
                // Send to K210
                k210_status_send(ESP32_STATUS_CODE_KPD, kpad_state);
                if (debug_log >= 2) ESP_LOGI(TAG, "KBD changed (%u): [%02X->%02X]", kpad, sent_state, kpad_state);
            }
            // pins interrupts were disabled in ISR
            gpio_intr_enable(KPAD1);
            gpio_intr_enable(KPAD2);
            gpio_intr_enable(KPAD3);
            gpio_intr_enable(KPAD4);
        }
    }

    CHECK_ERROR_CODE(esp_task_wdt_delete(NULL), ESP_OK);             //Unsubscribe task from TWDT
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_ERR_NOT_FOUND);  //Confirm task is unsubscribed

    if (keypad_evt_queue) {
        vQueueDelete(keypad_evt_queue);
        keypad_evt_queue = NULL;
    }
    if (debug_log >= 2) ESP_LOGI(TAG, "Keypad task terminated");
    vTaskDelete(NULL);
}

/*
//----------------------------
static void inicTipku(int tpk)
{
    if (!rtc_gpio_is_valid_gpio(tpk)) {
        ESP_LOGW(TAG, "Tipka %d nije u RTC domeni", tpk);
    }
    else {
        rtc_gpio_init(tpk);
        rtc_gpio_set_direction(tpk, RTC_GPIO_MODE_INPUT_ONLY);
        rtc_gpio_pulldown_dis(tpk);
        rtc_gpio_pullup_en(tpk);
        rtc_gpio_hold_en(tpk);
    }
}

*/

#endif
