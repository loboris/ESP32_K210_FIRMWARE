
#include "global.h"
#include "esp_ota_ops.h"
#include "mbedtls/md5.h"

#define BUFFSIZE 8192

char ota_fname[65] = {0};
char ota_fmd5[33] = {0};

xQueueHandle ota_evt_queue = NULL;

const char *OTA_TAG = "[OTA_TASK]";

//------------------------
esp_err_t ota_fileupdate()
{
    char *ota_write_data = NULL; // ota data write buffer
    esp_err_t err = ESP_FAIL, errexit = ESP_FAIL;
    k210_fstat_t fstat;
    int fres = -1;
    int fdd = -1;
    char local_md5[33] = {0};

    // update handle : set by esp_ota_begin(), must be freed via esp_ota_end() !
    esp_ota_handle_t update_handle = 0 ;
    const esp_partition_t *update_partition = NULL;

    const esp_partition_t *running_partition = esp_ota_get_running_partition();
    if (running_partition == NULL) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Find running partition failed !");
        goto exit;
    }

    update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Find update partition failed !");
        goto exit;
    }

    ota_write_data = malloc(BUFFSIZE+16);
    if (ota_write_data == NULL) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Error allocating buffer !");
        goto exit;
    }

    if (debug_log >= 1)  ESP_LOGI(OTA_TAG, "Starting OTA update from '%s' to '%s' partition", running_partition->label, update_partition->label);

    CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);

    // Begin update
    err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
    if (err != ESP_OK) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "esp_ota_begin failed, error=%d", err);
        goto exit;
    }

    // Check if update file exists
    fres = k210_file_stat(ota_fname, &fstat);
    if (fres < 0) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Update file '%s' not found", ota_fname);
        goto exit;
    }

    int expect_len = fstat.size;
    if (expect_len > 100000) {
        if (debug_log >= 1)  ESP_LOGI(OTA_TAG, "Update image size: %d bytes", expect_len);
    }
    else {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "File size too small !");
        goto exit;
    }

    // Open the update file
    fdd = k210_file_open(ota_fname, ESP_FILE_MODE_RO);
    if (fdd < 0) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Error opening update file !");
        goto exit;
    }

    // Read 1st chunk from update file
    int rd_len = k210_file_read(fdd, (void *)ota_write_data, BUFFSIZE);
    if (rd_len != BUFFSIZE) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Error reading from update file !");
        goto exit;
    }

    if (ota_write_data[0] != 0xE9) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Error: OTA image has invalid magic byte!");
        goto exit;
    }

    // Start writing data
    if (debug_log >= 1)  ESP_LOGI(OTA_TAG, "Writing to '%s' partition at offset 0x%x", update_partition->label, update_partition->address);

    unsigned char md5_byte_array[16] = {0};
    mbedtls_md5_context ctx;
    mbedtls_md5_init( &ctx );
    mbedtls_md5_starts( &ctx );
    int binary_file_length = 0; // image total length
    int remaining = expect_len; // remaining to read
    int to_read;

    // ==== Read chunks of update file and write to the ota partition ====
    while (remaining > 0) {
        vTaskDelay(1);
        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);

        mbedtls_md5_update( &ctx, (const unsigned char *)ota_write_data, rd_len);

        err = esp_ota_write( update_handle, (const void *)ota_write_data, rd_len);
        if (err != ESP_OK) {
            //mp_hal_stdout_tx_newline();
            if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Error: esp_ota_write failed! err=0x%x", err);
            goto exit;
        }
        // Update sizes
        binary_file_length += rd_len;
        remaining -= rd_len;
        if (remaining <= 0) break;

        // read next chunk of data
        to_read = (remaining > BUFFSIZE) ? BUFFSIZE : remaining;
        rd_len = k210_file_read(fdd, (void *)ota_write_data, to_read);

        if (rd_len != to_read) {
            if (debug_log >= 1)  ESP_LOGW(OTA_TAG, "Error reading file chunk (%d <> %d), rem=%d", rd_len, to_read, remaining);
            goto exit;
        }
        if ((binary_file_length + rd_len) > expect_len) {
            if (debug_log >= 1)  ESP_LOGW(OTA_TAG, "More than expected bytes read %u > %u [%d]", binary_file_length+rd_len, expect_len, rd_len);
            goto exit;
        }
        if ((binary_file_length + rd_len) > update_partition->size) {
            if (debug_log >= 1)  ESP_LOGW(OTA_TAG, "Update file bigger than the partition size: %u > %u", binary_file_length+rd_len, update_partition->size);
            goto exit;
        }
    }

    CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
    // Finished, set local md5
    mbedtls_md5_finish( &ctx, md5_byte_array );
    mbedtls_md5_free( &ctx );
    for (int i = 0; i<16; i++){
        sprintf(local_md5+(i*2),"%02x", md5_byte_array[i]);
    }

    if (debug_log >= 1)  ESP_LOGI(OTA_TAG, "Image written, total length = %d bytes", binary_file_length);
    if (expect_len != binary_file_length) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Read size not equal to file size: %u <> %u", expect_len, binary_file_length);
        goto exit;
    }
    if (strlen(ota_fmd5) == 32) {
        if (strncmp(ota_fmd5, local_md5, 32) == 0) {
            if (debug_log >= 1)  ESP_LOGI(OTA_TAG, "MD5 Checksum check PASSED. (%s)", ota_fmd5);
        }
        else {
            if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "MD5 Checksum check FAILED! (%s <> %s)", ota_fmd5, local_md5);
            goto exit;
        }
    }

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "Image validation failed, image is corrupted! (err=0x%x)", err);
        goto exit;
    }

    // === Set boot partition ===
    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        if (debug_log >= 1)  ESP_LOGE(OTA_TAG, "OTA set_boot_partition failed! (err=0x%x)", err);
        goto exit;
    }
    if (debug_log >= 1)  ESP_LOGW(OTA_TAG, "On next reboot ESP32 will be started from '%s' partition\n", update_partition->label);
    errexit = ESP_OK;

exit:
    CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
    if (fdd >= 0) {
        k210_file_close(fdd);
    }
    if (ota_write_data) free(ota_write_data);

    return errexit;
}

//======================
void OTA_task(void* arg)
{
    if (debug_log >= 2) ESP_LOGI(OTA_TAG, "OTA task started");
    //Subscribe this task to TWDT, then check if it is subscribed
    CHECK_ERROR_CODE(esp_task_wdt_add(NULL), ESP_OK);
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_OK);

    ota_evt_queue = xQueueCreate(2, sizeof(uint32_t));
    uint32_t notify = 0;

    while (1) {
        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
        if (xQueueReceive(ota_evt_queue, &notify, pdMS_TO_TICKS(1000)) == pdTRUE) {
            if ((notify == OTA_REQUEST_UPDATE) && (strlen(ota_fname) > 5)) {
                setStatus(~(ESP32_STATUS_OTAFAILED | ESP32_STATUS_OTAUPDATED), SET_STATUS_OP_AND);
                // Send status to K210
                k210_status_send(ESP32_STATUS_CODE_STATUS, getStatus());

                vTaskDelay(pdMS_TO_TICKS(100));
                //--- Perform the update --------
                esp_err_t res = ota_fileupdate();
                //-------------------------------

                memset(ota_fname, 0, sizeof(ota_fname));
                if (res == ESP_OK) setStatus(ESP32_STATUS_OTAUPDATED, SET_STATUS_OP_OR);
                else setStatus(ESP32_STATUS_OTAFAILED, SET_STATUS_OP_OR);
                // Send status to K210
                k210_status_send(ESP32_STATUS_CODE_STATUS, getStatus());
            }
        }
    }

    CHECK_ERROR_CODE(esp_task_wdt_delete(NULL), ESP_OK);             //Unsubscribe task from TWDT
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_ERR_NOT_FOUND);  //Confirm task is unsubscribed

    if (debug_log >= 2) ESP_LOGI(OTA_TAG, "OTA task terminated");
    vTaskDelete(NULL);
}
