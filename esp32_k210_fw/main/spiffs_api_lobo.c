// Copyright 2015-2017 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_spiffs_lobo.h"
#include "esp_vfs.h"
#include "spiffs_api_lobo.h"
#include "esp_task_wdt.h" // LoBo

#define TASK_RESET_PERIOD_S     2

static const char* SPIFFS_API_TAG = "SPIFFS_API";

static uint64_t wdt_time = 0;

/*
void spiffs_api_lock(spiffs *fs)
{
    (void) xSemaphoreTake(((esp_spiffs_lobo_t *)(fs->user_data))->lock, portMAX_DELAY);
}

void spiffs_api_unlock(spiffs *fs)
{
    xSemaphoreGive(((esp_spiffs_lobo_t *)(fs->user_data))->lock);
}
*/

s32_t spiffs_api_read_lobo(spiffs *fs, uint32_t addr, uint32_t size, uint8_t *dst)
{
    esp_err_t err = esp_partition_read(((esp_spiffs_lobo_t *)(fs->user_data))->partition,
                                        addr, dst, size);
    if (err) {
        ESP_LOGE(SPIFFS_API_TAG, "failed to read addr %08x, size %08x, err %d", addr, size, err);
        return -1;
    }
    return 0;
}

s32_t spiffs_api_write_lobo(spiffs *fs, uint32_t addr, uint32_t size, uint8_t *src)
{
    esp_err_t err = esp_partition_write(((esp_spiffs_lobo_t *)(fs->user_data))->partition,
                                        addr, src, size);
    if (err) {
        ESP_LOGE(SPIFFS_API_TAG, "failed to write addr %08x, size %08x, err %d", addr, size, err);
        return -1;
    }
    return 0;
}

s32_t spiffs_api_erase_lobo(spiffs *fs, uint32_t addr, uint32_t size)
{
    // LoBo: Check if the sector is already erased
    uint8_t f = 1;
    esp_err_t err = 0;
    uint8_t *buff = heap_caps_malloc(size, MALLOC_CAP_DMA);
    if (buff) {
        err = esp_partition_read(((esp_spiffs_lobo_t *)(fs->user_data))->partition, addr, buff, size);
        if (err == ESP_OK) {
            f = 0;
            for (int i=0; i<size; i++) {
                if (buff[i] != 0xFF) {
                    f = 1;
                    break;
                }
            }
        }
        free(buff);
        err = 0;
    }
    if (f) {
        err = esp_partition_erase_range(((esp_spiffs_lobo_t *)(fs->user_data))->partition,
                                            addr, size);
        // LoBo: prevent WDT errors on long operations like format
        uint64_t t = esp_timer_get_time();
        if (t > wdt_time) {
            wdt_time = t + TASK_RESET_PERIOD_S;
            esp_task_wdt_reset();
            vTaskDelay(pdMS_TO_TICKS(1)+1);
        }
    }
    if (err) {
        ESP_LOGE(SPIFFS_API_TAG, "failed to erase addr %08x, size %08x, err %d", addr, size, err);
        return -1;
    }
    return 0;
}

void spiffs_api_check_lobo(spiffs *fs, spiffs_check_type type,
                            spiffs_check_report report, uint32_t arg1, uint32_t arg2)
{
    static const char * spiffs_check_type_str[3] = {
        "LOOKUP",
        "INDEX",
        "PAGE"
    };

    static const char * spiffs_check_report_str[7] = {
        "PROGRESS",
        "ERROR",
        "FIX INDEX",
        "FIX LOOKUP",
        "DELETE ORPHANED INDEX",
        "DELETE PAGE",
        "DELETE BAD FILE"
    };

    if (report != SPIFFS_CHECK_PROGRESS) {
        ESP_LOGE(SPIFFS_API_TAG, "CHECK: type:%s, report:%s, %x:%x", spiffs_check_type_str[type],
                              spiffs_check_report_str[report], arg1, arg2);
    } else {
        ESP_LOGV(SPIFFS_API_TAG, "CHECK PROGRESS: report:%s, %x:%x",
                              spiffs_check_report_str[report], arg1, arg2);
    }
}
