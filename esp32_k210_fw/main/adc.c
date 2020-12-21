
#include "global.h"

#if USE_ADC

#include "driver/adc.h"
#include "esp_adc_cal.h"


#define NO_OF_ADC_SAMPLES   32          // Multi sampling
#define DEFAULT_VREF        1100        // Use adc2_vref_to_gpio() to obtain a better estimate
#define SAMPLE_INTERVAL_MS  1000

#define ADC_OFFSET_MV       300
#define ADC_FACTOR          5700

static int adc1, adc2;
static esp_adc_cal_characteristics_t *adc_chars;
static const uint8_t adc1_gpios[ADC1_CHANNEL_MAX] = {36, 37, 38, 39, 32, 33, 34, 35};
static const char *TAG = "[MKM_ADC]";

uint32_t adc_voltage1 = 0;
uint32_t adc_voltage2 = 0;
QueueHandle_t adc_mutex = NULL;


//-----------------------------------------------------
static int get_adc_channel(adc_unit_t adc_num, int pin)
{
    int channel = -1;
    for (int i=0; i < ADC1_CHANNEL_MAX; i++) {
        if (adc1_gpios[i] == pin) {
            channel = i;
            break;
        }
    }
    return channel;
}

//-----------------------------------------------------------
static void print_char_val_type(esp_adc_cal_value_t val_type)
{
    if (val_type == ESP_ADC_CAL_VAL_EFUSE_TP) {
        if (debug_log >= 1) ESP_LOGI(TAG, "Characterized using Two Point Value [Vref=%u, Offset=%u, K=%u, Atten=%u]", adc_chars->vref, adc_chars->coeff_b, adc_chars->coeff_a, adc_chars->atten);
    } else if (val_type == ESP_ADC_CAL_VAL_EFUSE_VREF) {
        if (debug_log >= 1) ESP_LOGI(TAG, "Characterized using eFuse Vref [Vref=%u, Offset=%u, K=%u, Atten=%u]", adc_chars->vref, adc_chars->coeff_b, adc_chars->coeff_a, adc_chars->atten);
    } else {
        if (debug_log >= 1) ESP_LOGI(TAG, "Characterized using Default Vref [Vref=%u, Offset=%u, K=%u, Atten=%u]", adc_chars->vref, adc_chars->coeff_b, adc_chars->coeff_a, adc_chars->atten);
    }
}

//---------------------------
static void check_efuse(void)
{
    //Check TP is burned into eFuse
    if (esp_adc_cal_check_efuse(ESP_ADC_CAL_VAL_EFUSE_TP) == ESP_OK) {
        if (debug_log >= 1) ESP_LOGI(TAG, "eFuse Two Point: Supported");
    } else {
        if (debug_log >= 1) ESP_LOGI(TAG, "eFuse Two Point: NOT supported");
    }

    //Check Vref is burned into eFuse
    if (esp_adc_cal_check_efuse(ESP_ADC_CAL_VAL_EFUSE_VREF) == ESP_OK) {
        if (debug_log >= 1) ESP_LOGI(TAG, "eFuse Vref: Supported");
    } else {
        if (debug_log >= 1) ESP_LOGI(TAG, "eFuse Vref: NOT supported");
    }
}

//============
void adcInit()
{
    // Configure ADC
    if (debug_log >= 2) ESP_LOGI(TAG, "ADC Configuration");
    //Check if Two Point or Vref are burned into eFuse
    check_efuse();
    adc1 = get_adc_channel(ADC_UNIT_1, ADC1_PIN);
    adc1_config_width(ADC_WIDTH_BIT_12);
    adc1_config_channel_atten(adc1, ADC_ATTEN_DB_11);

    adc2 = get_adc_channel(ADC_UNIT_1, ADC2_PIN);
    adc1_config_width(ADC_WIDTH_BIT_12);
    adc1_config_channel_atten(adc2, ADC_ATTEN_DB_11);

    //Characterize ADC
    adc_chars = calloc(1, sizeof(esp_adc_cal_characteristics_t));
    esp_adc_cal_value_t val_type = esp_adc_cal_characterize(ADC_UNIT_1, ADC_ATTEN_DB_11, ADC_WIDTH_BIT_12, DEFAULT_VREF, adc_chars);
    print_char_val_type(val_type);
    //adc2_vref_to_gpio(27);
}

/*
 * @note When the power switch of SARADC1, SARADC2, HALL sensor and AMP sensor is turned on,
 *       the input of GPIO36 and GPIO39 will be pulled down for about 80ns.
 *       When enabling power for any of these peripherals, ignore input from GPIO36 and GPIO39.
 *       Please refer to section 3.11 of 'ECO_and_Workarounds_for_Bugs_in_ESP32' for the description of this issue.
 *
 */

//======================
void ADC_task(void* arg)
{
    bool f;
    uint32_t adc_reading1, adc_reading2, voltage1, voltage2;
    if (debug_log >= 2) ESP_LOGI(TAG, "ADC task started");
    //Subscribe this task to TWDT, then check if it is subscribed
    CHECK_ERROR_CODE(esp_task_wdt_add(NULL), ESP_OK);
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_OK);

    adcInit();
    if (adc_mutex == NULL) adc_mutex = xSemaphoreCreateMutex();

    while (1) {
        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
        if (vdd_enabled) {
            adc_reading1 = 0;
            adc_reading2 = 0;
            // Disable Interrupts on pins 36&39 during measurement
            gpio_intr_disable(GPIO_NUM_36);
            gpio_intr_disable(GPIO_NUM_39);

            // Sample the pins voltage using multiple samples
            for (int i = 0; i < NO_OF_ADC_SAMPLES; i++) {
                adc_reading1 += adc1_get_raw((adc1_channel_t)adc1);
            }
            adc_reading1 /= NO_OF_ADC_SAMPLES;
            for (int i = 0; i < NO_OF_ADC_SAMPLES; i++) {
                adc_reading2 += adc1_get_raw((adc1_channel_t)adc2);
            }
            adc_reading2 /= NO_OF_ADC_SAMPLES;

            // Re-enable Interrupts on pins 36&39 after measurement
            gpio_intr_enable(GPIO_NUM_36);
            gpio_intr_enable(GPIO_NUM_39);

            //Convert adc_reading to voltage in mV
            //voltage1 = ((esp_adc_cal_raw_to_voltage(adc_reading1, adc_chars) * ADC_FACTOR) / 1000) - ADC_OFFSET_MV;
            //voltage2 = ((esp_adc_cal_raw_to_voltage(adc_reading2, adc_chars) * ADC_FACTOR) / 1000) - ADC_OFFSET_MV;
            voltage1 = esp_adc_cal_raw_to_voltage(adc_reading1, adc_chars);
            voltage2 = esp_adc_cal_raw_to_voltage(adc_reading2, adc_chars);

            f = pdTRUE;
            if (adc_mutex) f = xSemaphoreTake(adc_mutex, 1000);
            adc_voltage1 = ((voltage1* ADC_FACTOR) / 1000) - ADC_OFFSET_MV;;
            adc_voltage2 = ((voltage2* ADC_FACTOR) / 1000) - ADC_OFFSET_MV;;
            //if (debug_log >= 3) printf("* ADC: [%u, %u, %u] [%u, %u, %u]\r\n", adc_reading1, voltage1, adc_voltage1, adc_reading2, voltage2, adc_voltage2);
            if ((adc_mutex) && (f)) xSemaphoreGive(adc_mutex);
            // ToDo: send voltage to K210
        }

        vTaskDelay(pdMS_TO_TICKS(SAMPLE_INTERVAL_MS));
    }

    if (adc_mutex != NULL) {
        vSemaphoreDelete(adc_mutex);
        adc_mutex = NULL;
    }

    CHECK_ERROR_CODE(esp_task_wdt_delete(NULL), ESP_OK);             //Unsubscribe task from TWDT
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_ERR_NOT_FOUND);  //Confirm task is unsubscribed

    if (debug_log >= 2) ESP_LOGI(TAG, "ADC task terminated");
    vTaskDelete(NULL);
}

#endif
