

#if 0

#include "global.h"
#include "driver/gpio.h"
#include "esp32/rom/crc.h"


WORD_ALIGNED_ATTR uint8_t spi_sendbuf[SPI_FRAME_SIZE]={'\0'};
WORD_ALIGNED_ATTR uint8_t spi_recvbuf[SPI_FRAME_SIZE]={'\0'};

const char *SPI_TAG = "[SPI_SLAVE]";

static spi_slave_transaction_t esp_spi_trans = {0};


// Called after a transaction is queued and ready for pickup by master.
// We use this to set the handshake line HIGH (ready).
//---------------------------------------------------
void post_setup_cb(spi_slave_transaction_t *trans)
{
    WRITE_PERI_REG(GPIO_OUT_W1TS_REG, (1<<GPIO_HANDSHAKE));
}

// Called after transaction is sent/received.
// We use this to set the handshake line LOW (busy).
//---------------------------------------------------
void post_trans_cb(spi_slave_transaction_t *trans)
{
    WRITE_PERI_REG(GPIO_OUT_W1TC_REG, (1<<GPIO_HANDSHAKE));
}

//===================================
esp_err_t spi_slave_transaction(void)
{
    uint32_t crc;
    memset(SPI_READ_BUF, 0x00, SPI_FRAME_SIZE);

    if (esp_cmdstat != 0) {
        // Command was received, prepare response
        *(uint16_t *)(SPI_WRITE_BUF) = esp_cmdstat;
        *(uint16_t *)(SPI_WRITE_BUF + 2) = esp_len;
        crc = crc32_le(0, SPI_WRITE_BUF, esp_len+4);
        memcpy(SPI_WRITE_BUF + esp_len + 4, (void *)&crc, 4);
    }

    esp_spi_trans.length = SPI_FRAME_SIZE * 8;
    esp_spi_trans.tx_buffer = SPI_WRITE_BUF;
    esp_spi_trans.rx_buffer = SPI_READ_BUF;

    // This call enables the SPI slave interface to send/receive to the SPI_WRITE_BUF and SPI_READ_BUF.
    // The transaction is initialized by the SPI master, however,
    // so it will not actually happen until the master starts a hardware transaction by pulling CS low and pulsing the clock etc.
    // In this case, we use the handshake line, set LOW by the .post_setup_cb callback that is called as soon as a transaction is ready,
    // to let the master know it is free to transfer data.

    if (mkm_debug) ESP_LOGI(SPI_TAG, "Transaction wait ...");
    esp_err_t ret=spi_slave_transmit(HSPI_HOST, &esp_spi_trans, portMAX_DELAY);
    if (mkm_debug) ESP_LOGI(SPI_TAG, "Transaction finished, length=%d.", esp_spi_trans.trans_len/8);
    spi_transaction_length = esp_spi_trans.trans_len/8;

    // spi_slave_transmit does not return until the master has done a transmission,
    // so by here we have sent our data and received data from the master.
    return ret;
}

//======================
void SPI_task(void* arg)
{
    // ========================================
    // ==== Configure SPI interface ===========
    // ========================================
    ESP_LOGI(SPI_TAG, "SPI Slave task started");

    //Configuration for the SPI bus
    spi_bus_config_t buscfg = {
        .mosi_io_num=GPIO_MOSI,
        .miso_io_num=GPIO_MISO,
        .sclk_io_num=GPIO_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = SPI_FRAME_SIZE,
    };

    //Configuration for the SPI slave interface
    spi_slave_interface_config_t slvcfg = {
        .mode=0,
        .spics_io_num=GPIO_CS,
        .queue_size=1,
        .flags=0,
        .post_setup_cb=post_setup_cb,
        .post_trans_cb=post_trans_cb
    };

    //Configuration for the handshake line
    gpio_config_t io_conf = {
        .intr_type=GPIO_INTR_DISABLE,
        .mode=GPIO_MODE_OUTPUT,
        .pin_bit_mask=(1<<GPIO_HANDSHAKE)
    };

    //Configure handshake line as output
    gpio_config(&io_conf);
    WRITE_PERI_REG(GPIO_OUT_W1TC_REG, (1<<GPIO_HANDSHAKE));

    //Enable pull-ups on SPI lines so we don'esp_spi_trans detect rogue pulses when no master is connected.
    gpio_set_pull_mode(GPIO_MOSI, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_SCLK, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_CS, GPIO_PULLUP_ONLY);

    //Initialize SPI slave interface
    if (spi_slave_initialize(HSPI_HOST, &buscfg, &slvcfg, DMA_CHAN) != ESP_OK) {
        ESP_LOGE(SPI_TAG, "Error initializing SPI Slave");
        goto exit;
    }

    ESP_LOGI(SPI_TAG, "SPI Slave configured");

    while (!vdd_enabled) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    // Start 1st transaction
    memset(SPI_WRITE_BUF, 0x00, SPI_FRAME_SIZE);
    esp_cmdstat = 0;
    spi_slave_transaction();

    while(1) {
        if (!vdd_enabled) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        // Transaction finished
        // Analyze received data
        if (spi_trans_check()) {
            spi_processCommand();
        }

        if (mkm_debug) ESP_LOGI(SPI_TAG, "Transaction processed\r\n");

        // Start new transaction
        spi_slave_transaction();
    }

exit:
    ESP_LOGI(SPI_TAG, "SPI Slave task terminated");
    vTaskDelete(NULL);
}

#endif

