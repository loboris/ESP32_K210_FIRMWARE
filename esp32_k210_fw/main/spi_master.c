

/* K210 SPI Slave Command (16 bytes) structure:
 * -------------------------------------------
 * For SPI_CMD_WRSTAT & SPI_CMD_WRSTAT_CONFIRM
 * -------------------------------------------
 * -------------------------------------------------------------
 *  0       user data command code
 *  1       user data command type (b0-b3) & dummy bytes (b4-b7)
 *  2 - 13  user data (12 bytes)
 * 14 - 15  16-bit crc
 * -------------------------------------------------------------
 *
 * ------------------
 * For other commands
 * ------------------
 * -------------------------------------
 *  0       command code & options
 *  1 -  3  20-bit address & dummy bytes
 *  4 -  5  16_bit length
 *  6 - 13  user data (8 bytes)
 * 14 - 15  16-bit crc
 * -------------------------------------
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>

#include "esp_system.h"
#include "driver/gpio.h"
#include "global.h"
#include "esp32/rom/crc.h"
#include "hal/spi_types.h"

#define POOLING_INTERVAL            2000

#define CMD_ERROR_SLAVE_NOTREADY    -101
#define CMD_ERROR_TIMEOUT           -102
#define CMD_ERROR_NOCONFIRM         -103
#define CMD_ERROR_BADCRC            -104
#define CMD_ERROR_SPI_ERROR         -105

#define CMD_BUFFER_SIZE             16
#define READ_BUFFER_SIZE            32
#define COMMAND_STATUS_LENGTH       12

uint8_t *spi_buffer = NULL;

static DMA_ATTR uint8_t cmd_buf[CMD_BUFFER_SIZE] = {0};
static DMA_ATTR uint8_t read_buf[READ_BUFFER_SIZE] = {0};
static spi_device_handle_t master_handle;

TaskHandle_t spi_task_handle = NULL;
TaskHandle_t socket_task_handle = NULL;
bool k210_slave_connected = false;
k210_info_t k210_info = {0};
uint32_t spi_master_buffer_size;
SemaphoreHandle_t func_semaphore;
QueueHandle_t sock_mutex = NULL;


const char *SPI_TAG = "[SPI_TASK]";

//-------------------------------------------
static const uint16_t Crc16LookupTable[256] =
{
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

//-----------------------------------------
static const uint8_t Crc8LookupTable[256] =
{
    0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
    157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
    35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
    190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
    70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
    219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
    101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
    248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
    140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
    17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
    175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
    50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
    202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
    87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
    233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
    116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53
};

//--------------------------------------------------------
static void IRAM_ATTR spi_handshake_isr_handler(void* arg)
{
    //High -> Low edge/level detected
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;

    //gpio_intr_disable(GPIO_HANDSHAKE);

    xTaskNotifyFromISR(spi_task_handle, SPI_NOTIFY_HANDSHAKE, eSetBits, &xHigherPriorityTaskWoken );
    if (xHigherPriorityTaskWoken) portYIELD_FROM_ISR();
}

//---------------------------------------------------------------------------------
static uint16_t calc_crc16(const void* data, size_t length, uint16_t previousCrc16)
{
    uint16_t crc = ~previousCrc16;
    const uint8_t *pbuf = (const uint8_t *)data;

    while (length--) {
        crc = (crc<<8) ^ Crc16LookupTable[((crc>>8) ^ *pbuf++) & 0x00FF];
    }
    return crc;
}

//---------------------------------------------------------------------
uint8_t calc_crc8(const void* data, size_t length, uint8_t previousCrc8)
{
    uint8_t crc = previousCrc8;
    const uint8_t *pbuf = (const uint8_t *)data;
    while (length--) {
        crc = Crc8LookupTable[crc ^ *pbuf++];
    }
    return crc;
}

//-----------------------------------
bool checkCRC(uint8_t *buff, int len)
{
    uint16_t crc16 = calc_crc16((const void*)buff, len, 0);
    if (crc16 == *((uint16_t *)(buff+len))) return true;
    else {
        if (debug_log >= 3) ESP_LOGI(SPI_TAG, "Crc16 error (%04X <> %04X)", crc16, *((uint16_t *)(buff+len)));
        return false;
    }
}

//---------------------------------
void setCRC(uint8_t *buff, int len)
{
    uint16_t crc16 = calc_crc16((const void*)buff, len, 0);
    *((uint16_t *)(buff+len)) = crc16;
}

//-------------------------------------
static bool k210WaitReady(int crc_time)
{
    // ==== Wait for K210 SPI Slave to enter READY state (handshake Low) ===
    int tmo = 100 + crc_time;
    uint64_t tend = esp_timer_get_time() + tmo + 100;
    while (tmo > 0) {
        if (gpio_get_level(GPIO_HANDSHAKE) == 0) break;
        if (esp_timer_get_time() > tend) return false;
    }
    return true;
}

//------------------------------------
static bool k210WaitIdle(int crc_time)
{
    // ==== Wait for K210 SPI Slave to return to IDLE state ===
    int tmo = 300 + crc_time;
    uint64_t tend = esp_timer_get_time() + tmo;
    while (tmo > 0) {
        if (gpio_get_level(GPIO_HANDSHAKE)) break;
        if (esp_timer_get_time() > tend) return false;
    }
    return true;
}

//--------------------------------
static uint32_t k210LongWaitIdle()
{
    // ==== Wait for K210 SPI Slave to return to IDLE state (without timeout) ===
    // Watchdog timeout will occur if running for very long time!
    uint64_t tstart, tend;
    tstart = esp_timer_get_time();
    while (1) {
        if (gpio_get_level(GPIO_HANDSHAKE)) {
            tend = esp_timer_get_time();
            break;
        }
        taskYIELD();
    }
    return (tend - tstart);
}

//-----------------------
int k210_wait_handshake()
{
    CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
    uint32_t notify_value = 0;
    gpio_intr_enable(GPIO_HANDSHAKE);
    BaseType_t res = xTaskNotifyWait(0, ULONG_MAX, &notify_value, pdMS_TO_TICKS(2000));
    gpio_intr_disable(GPIO_HANDSHAKE);
    if ((res == pdPASS) && (notify_value & SPI_NOTIFY_HANDSHAKE)) {
        // handshake detected
        // wait for high handshake level
        uint64_t tmo = esp_timer_get_time() + 300;
        while (1) {
            if (gpio_get_level(GPIO_HANDSHAKE) == 1) break;
            if (esp_timer_get_time() > tmo) return 2;
        }
        return ESP_OK;
    }
    else return 1;
}

//---------------------------------------
int IRAM_ATTR readTrans(uint8_t cmd_code)
{
    if (gpio_get_level(GPIO_HANDSHAKE) == 0) {
        if ((k210_slave_connected) && (debug_log >= 1)) ESP_LOGE(SPI_TAG, "readTrans: K210 not Idle");
        return CMD_ERROR_SLAVE_NOTREADY;
    }

    // Format the K210 SPI slave request
    memset(read_buf, 0xdd, READ_BUFFER_SIZE);

    esp_err_t ret;
    uint8_t cmd = cmd_code;
    spi_transaction_t t;

    memset(&t, 0, sizeof(t)); //Zero out the transaction
    t.length = 8;
    t.tx_buffer = &cmd;

    // Execute command transaction
    #if SPI_MASTER_3WIRE
    ret = spi_device_nodma_transmit(master_handle, &t, 0);
    #else
    ret = spi_device_polling_transmit(master_handle, &t);
    #endif

    memset(&t, 0, sizeof(t)); //Zero out the transaction
    t.length = ((cmd_code == SLAVE_CMD_READ_TRANS) ? READ_BUFFER_SIZE : COMMAND_STATUS_LENGTH) * 8;
    t.rx_buffer = read_buf;

    #if SPI_MASTER_3WIRE
    ret = spi_device_nodma_transmit(master_handle, &t, 0);
    #else
    ret = spi_device_polling_transmit(master_handle, &t);
    #endif
    if (ret == ESP_OK) {
        if (!checkCRC(read_buf, ((cmd_code == SLAVE_CMD_READ_TRANS) ? READ_BUFFER_SIZE-2 : COMMAND_STATUS_LENGTH-2))) return CMD_ERROR_BADCRC;
    }

    return ret;
}

//------------------------------------------------------------------------
int transferData(uint8_t cmd, uint32_t addr, uint32_t dsize, uint8_t *data)
{
    /*
     * Small transactions ( <= 32 bytes ) are handled in polling mode for higher speed.
     * The overhead of interrupt transactions is more than just waiting for the transaction to complete.
     */

    uint8_t ntry = MAX_TRANSFER_RETRIES;
    uint32_t size;

start:
    size = dsize;
    if (gpio_get_level(GPIO_HANDSHAKE) == 0) {
        if ((k210_slave_connected) && (debug_log >= 1)) ESP_LOGE(SPI_TAG, "transferData: K210 not Idle");
        return CMD_ERROR_SLAVE_NOTREADY;
    }

    esp_err_t ret;
    uint64_t t1, t2, t3, t4, t5;
    t1 = esp_timer_get_time();
    int crc_time = 0;

    // Format the K210 SPI slave request
    /* Command structure:
     * ------------------
     *  0       command code & options
     *  1 -  3  20-bit address & dummy bytes
     *  4 -  5  16_bit length
     *  6 - 13  user data (8 bytes)
     * 14 - 15  16-bit crc
     * -------------------
     *
     * Different format for: SPI_CMD_WRSTAT & SPI_CMD_WRSTAT_CONFIRM
     * -------------------------------------------------------------
     *  0       user data command code
     *  1       user data command type (b0-b3) & dummy bytes (b4-b7)
     *  2 - 13  user data (12 bytes)
     * 14 - 15  16-bit crc
     * -------------------------------------------------------------
     */
    memset(cmd_buf, 0, CMD_BUFFER_SIZE);
    if ((cmd == SLAVE_CMD_WRSTAT) || (cmd == SLAVE_CMD_WRSTAT_CONFIRM)) {
        cmd_buf[0] = cmd;
        cmd_buf[1] = (addr & 0x0F) | (DUMMY_BYTES << 4);
        if (data) memcpy(cmd_buf+2, data, (size > 12) ? 12 : size);
        size = 9;
        crc_time = 200;
    }
    else {
        cmd_buf[0] = cmd;
        cmd_buf[1] = addr & 0xff;
        cmd_buf[2] = (addr >> 8) & 0xff;
        cmd_buf[3] = ((addr >> 16) & 0x0f) | (((cmd & 0x0f) != SLAVE_CMD_WRITE) ? (DUMMY_BYTES << 4) : 0);
        cmd_buf[4] = (size-1) & 0xff;
        cmd_buf[5] = ((size-1) >> 8) & 0xff;
        if (data) memcpy(cmd_buf+6, data, 8);
    }
    setCRC(cmd_buf, 14);
    if (debug_log >= 3) ESP_LOGI(SPI_TAG, "Command crc: %04X", calc_crc16((const void*)cmd_buf, 14, 0));

    // ===== Transaction phase 1: Send command block ====================
    spi_transaction_t t;
    memset(&t, 0, sizeof(t)); //Zero out the transaction
    t.length = CMD_BUFFER_SIZE * 8;
    t.tx_buffer = cmd_buf;

    // Send command to K210 slave
    #if SPI_MASTER_3WIRE
    ret = spi_device_nodma_transmit(master_handle, &t, 0);
    #else
    ret = spi_device_polling_transmit(master_handle, &t);
    #endif
    // ============================================================

    t2 = esp_timer_get_time();
    if (ret != ESP_OK) {
        if (debug_log >= 1) ESP_LOGE(SPI_TAG, "Trans #1 error (%d): %llu", ret, t2-t1);
        return ret;
    }

    if ((cmd & 0x0F) == SLAVE_CMD_WRSTAT) {
        // For status write command(s) this is all we have to do
        return ESP_OK;
    }

    // -----------------------------------------------------------------------------------------
    // --- Wait for K210 to process the command and become ready for data block transfer
    // --- After receiving the command K210 slave must respond by pulling the handshake line low
    // --- This should be less than 50 us
    if (!k210WaitReady(crc_time)) {
        if ((k210_slave_connected) && (ntry > 0)) {
            ntry--;
            vTaskDelay(pdMS_TO_TICKS(20));
            // slave nor ready, try again
            goto start;
        }
        t3 = esp_timer_get_time();
        if ((k210_slave_connected) && (debug_log >= 1)) ESP_LOGE(SPI_TAG, "K210 slave not ready: %llu, %llu (%u, %u) %u", t2-t1, t3-t2, cmd&0xFF, size, MAX_TRANSFER_RETRIES-ntry);
        return CMD_ERROR_TIMEOUT;
    }
    // -----------------------------------------------------------------------------------------

    t3 = esp_timer_get_time();

    if ((cmd & 0x0f) != SLAVE_CMD_WRITE) crc_time = ((size * k210_info.crc_speed) / 1000000);
    if ((cmd & 0x0F) != SLAVE_CMD_WRSTAT_CONFIRM) {
        // add 2-byte crc16 to transfer size for commands with crc16
        if (cmd & SLAVE_CMD_OPT_CRC) size += 2;
    }

    // ===== Transaction phase 2: Write or Read data block ===============================================================
    uint8_t *trans_buff = spi_buffer;
    if ((cmd & 0x0f) != SLAVE_CMD_WRITE) {
        size += DUMMY_BYTES;
    }
    else {
        trans_buff = SPI_RW_BUFFER;
    }

    memset(&t, 0, sizeof(t)); //Zero out the transaction
    t.length = size * 8;
    if ((cmd & 0x0f) == SLAVE_CMD_WRITE) {
        t.tx_buffer = trans_buff;
    }
    else {
        t.rx_buffer = trans_buff;
        t.rxlength = size * 8;
    }
    // Send or receive data block to/from K210 slave
    #if SPI_MASTER_3WIRE
    ret = spi_device_nodma_transmit(master_handle, &t, 0);
    #else
    if (size > 32) ret = spi_device_transmit(master_handle, &t);
    else {
        // if the data transaction is small, it is handled in polling mode for higher speed.
        // The overhead of interrupt transactions is more than just waiting for the transaction to complete.
        ret = spi_device_polling_transmit(master_handle, &t);
    }
    #endif
    // =============================================================================================================

    t4 = esp_timer_get_time();
    if (ret != ESP_OK) {
        if (debug_log >= 1) ESP_LOGE(SPI_TAG, "Trans #2 error (%d): %llu, %llu, %llu", ret, t2-t1, t3-t2, t4-t3);
        return ret;
    }

    // === Wait for the Write Command confirmation if requested ===============
    // === This should be less than 300 us + crc16 calculation time (if used)
    if ((cmd & SLAVE_CMD_OPT_CRC)) crc_time = (size * k210_info.crc_speed) / 500000;
    else crc_time = 0;

    if ( ((cmd & 0x0f) == SLAVE_CMD_WRITE) && (cmd & SLAVE_CMD_OPT_CONFIRM) ) {
        // read the confirmation block (transaction state) from slave
        k210WaitIdle(crc_time);

        ret = readTrans(SLAVE_CMD_STATUS_TRANS);
        t5 = esp_timer_get_time();

        if (ret != ESP_OK) return ret;
    }
    else {
        /* Wait for K210 slave to accept the data block
           and return to IDLE state (indicated by high state of the handshake line)
           this may take a long time (up to 100 ms) when the slave has to process
           some time consuming commands, like in case of file commands
           First we wait for 1 ms in which time most commands should be finished
           If not, we wait for an indefinite time until K210 slave returns to IDLE state
           (this should not take more than 100 ms)
        */
        if (!k210WaitIdle(700)) {
            uint32_t twait = k210LongWaitIdle();
            if (debug_log >= 1) {
                ESP_LOGW(SPI_TAG, "transferData done: K210 processing time %u us", twait+1000);
            }
            //return CMD_ERROR_SLAVE_NOTREADY;
        }
        t5 = esp_timer_get_time();
    }

    if ((ntry < MAX_TRANSFER_RETRIES) && (debug_log >= 1)) {
        ESP_LOGW(SPI_TAG, "OK; cmd=%u, retries=%u", cmd&0xFF, MAX_TRANSFER_RETRIES-ntry);
    }
    if (debug_log >= 2) {
        ESP_LOGI(SPI_TAG, "OK; Times (us): command=%llu, ready=%llu, data=%llu, process=%llu", t2-t1, t3-t2, t4-t3, t5-t4);
    }
    return ret;
}

//-------------------------------------
void getStatsInfo(bool stats, bool prn)
{
    memset(SPI_RW_BUFFER, 0, spi_master_buffer_size);
    char *pbuff = (char *)(SPI_RW_BUFFER+4);
    int pbufidx = 0;

    if (stats) {
        #if (defined(CONFIG_FREERTOS_USE_TRACE_FACILITY) && defined(CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS))
        bool has_stats = false;
        TaskStatus_t *pxTaskStatusArray = NULL;
        volatile UBaseType_t uxArraySize, x;
        uint32_t ulTotalRunTime;
        float ulStatsAsPercentage;
        uxArraySize = uxTaskGetNumberOfTasks();
        uint32_t tasks[uxArraySize];
        for ( x = 0; x < uxArraySize; x++ ) {
            tasks[x] = 0;
        }
        // Get Run time statistics
        // Take a snapshot of the number of tasks in case it changes while this function is executing.
        // Allocate a TaskStatus_t structure for each task.  An array could be allocated statically at compile time.
        pxTaskStatusArray = malloc(uxArraySize * sizeof(TaskStatus_t));
        if ( pxTaskStatusArray != NULL ) {
            // Generate raw status information about each task.
            uxArraySize = uxTaskGetSystemState( pxTaskStatusArray, uxArraySize, &ulTotalRunTime );
            // Avoid divide by zero errors.
            if ((ulTotalRunTime / 100) > 0) has_stats = true;
        }
        //vTaskList
        if (has_stats) {
            char tid[5];
            bool handled = false;
            sprintf(pbuff+pbufidx, "FreeRTOS tasks running:\n");
            pbufidx = strlen(pbuff);
            sprintf(pbuff+pbufidx, "-----------------------------------------------------------\n");
            pbufidx = strlen(pbuff);
            sprintf(pbuff+pbufidx, " Core             Name MinStack Priority Run time (s)   (%%)\n");
            pbufidx = strlen(pbuff);
            sprintf(pbuff+pbufidx, "-----------------------------------------------------------\n");
            pbufidx = strlen(pbuff);
            for ( x = 0; x < uxArraySize; x++ ) {
                handled = false;
                for ( int i = 0; i < uxArraySize; i++ ) {
                    if (pxTaskStatusArray[x].xHandle == (TaskHandle_t)tasks[i]) {
                        handled = true;
                        break;
                    }
                }
                if (!handled) {
                    ulStatsAsPercentage = (float)pxTaskStatusArray[x].ulRunTimeCounter / (float)ulTotalRunTime;
                    if (pxTaskStatusArray[x].xCoreID == 0) sprintf(tid, "0");
                    else if (pxTaskStatusArray[x].xCoreID == 1) sprintf(tid, "1");
                    else sprintf(tid, "---");
                    sprintf(pbuff+pbufidx, "%5s%17s%9u%9d%13.3f%6.2f\n",
                            tid, pxTaskStatusArray[x].pcTaskName,
                            pxTaskStatusArray[x].usStackHighWaterMark,
                            pxTaskStatusArray[x].uxCurrentPriority, (double)pxTaskStatusArray[x].ulRunTimeCounter / 1000000.0, ulStatsAsPercentage);
                    pbufidx = strlen(pbuff);
                }

            }
            sprintf(pbuff+pbufidx, "-----------------------------------------------------------\n\n");
            pbufidx = strlen(pbuff);

            if ( pxTaskStatusArray != NULL ) free(pxTaskStatusArray);
        }
        #endif
    }

    multi_heap_info_t info;
    heap_caps_get_info(&info, MALLOC_CAP_INTERNAL | MALLOC_CAP_32BIT | MALLOC_CAP_8BIT | MALLOC_CAP_DMA);
    sprintf(pbuff+pbufidx, "Heap info:\n----------\n");
    pbufidx = strlen(pbuff);
    sprintf(pbuff+pbufidx, "              Free: %u\n", info.total_free_bytes);
    pbufidx = strlen(pbuff);
    sprintf(pbuff+pbufidx, "         Allocated: %u\n", info.total_allocated_bytes);
    pbufidx = strlen(pbuff);
    sprintf(pbuff+pbufidx, "      Minimum free: %u\n", info.minimum_free_bytes);
    pbufidx = strlen(pbuff);
    sprintf(pbuff+pbufidx, "      Total blocks: %u\n", info.total_blocks);
    pbufidx = strlen(pbuff);
    sprintf(pbuff+pbufidx, "Largest free block: %u\n", info.largest_free_block);
    pbufidx = strlen(pbuff);
    sprintf(pbuff+pbufidx, "  Allocated blocks: %u\n", info.allocated_blocks);
    pbufidx = strlen(pbuff);
    sprintf(pbuff+pbufidx, "       Free blocks: %u\n\n", info.free_blocks);
    pbufidx = strlen(pbuff);

    if (prn) printf(pbuff);
}

//----------------------
static bool detectK210()
{
    esp_err_t ret;
    bool crcok;
    struct timeval start_wait_time;
    struct timeval current_time;
    int seconds;

    spi_buffer = read_buf;
    spi_master_buffer_size = READ_BUFFER_SIZE;

    // Detect K210 Slave
    if (debug_log >= 1) printf("* Waiting for K210 to become ready...\r\n");

    gettimeofday(&start_wait_time, NULL);

    while (1) {
        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
        memset(read_buf, 0, READ_BUFFER_SIZE);

        ret = transferData(SLAVE_CMD_INFO | SLAVE_CMD_OPT_CRC, SLAVE_BUFFER_CMD_ADDRESS, SLAVE_INFO_LENGTH, NULL);
        if (ret != ESP_OK) {
            gettimeofday(&current_time, NULL);
            seconds = current_time.tv_sec - start_wait_time.tv_sec;
            if ((seconds > 0) & ((seconds % 10) == 0)) {
                ESP_LOGW(SPI_TAG, "No response from K210 in %d seconds (%d)", seconds, ret);
            }
        }
        else {
            crcok = checkCRC(SPI_RW_BUFFER, SLAVE_INFO_LENGTH);
            if (crcok) {
                k210_info.databuff_size = SPI_RW_BUFFER[12] | (SPI_RW_BUFFER[13] << 8) | (SPI_RW_BUFFER[14] << 16);
                k210_info.databuff_ro_size = SPI_RW_BUFFER[15] | (SPI_RW_BUFFER[16] << 8) | (SPI_RW_BUFFER[17] << 16);
                k210_info.crc_speed = SPI_RW_BUFFER[18] | (SPI_RW_BUFFER[19] << 8) | (SPI_RW_BUFFER[20] << 16);
                k210_info.crc32_speed = SPI_RW_BUFFER[21] | (SPI_RW_BUFFER[22] << 8) | (SPI_RW_BUFFER[23] << 16);
                bool handshake = (bool)SPI_RW_BUFFER[24];
                memcpy(k210_info.info, (char *)SPI_RW_BUFFER, 11);
                k210_info.info[11] = '\0';
                if (!handshake) {
                    ESP_LOGE(SPI_TAG, "FATAL: K210 does not use handshake!");
                    return false;
                }

                // Allocate spi buffer
                spi_buffer = NULL;
                spi_master_buffer_size = k210_info.databuff_size - k210_info.databuff_ro_size;
                spi_buffer = (uint8_t *)heap_caps_malloc(spi_master_buffer_size+64, MALLOC_CAP_DMA);
                while (spi_buffer == NULL) {
                    if (spi_master_buffer_size < 1024) {
                        ESP_LOGE(SPI_TAG, "FATAL: cannot allocate SPI buffer");
                        return false;
                    }
                    spi_master_buffer_size -= 1024;
                    spi_buffer = heap_caps_malloc(spi_master_buffer_size+64, MALLOC_CAP_DMA);
                }

                // Test ESP32 crc calculation speeds
                for (int i=0; i<1000; i++) {
                    spi_buffer[i] = (uint8_t)i;
                }
                uint32_t crc16_speed, crc32_speed;
                uint64_t tstart;

                tstart = esp_timer_get_time();
                uint16_t crc16 = calc_crc16(spi_buffer, 1000, 0);
                crc16_speed = (uint32_t)(esp_timer_get_time() - tstart);
                tstart = esp_timer_get_time();
                uint32_t crc32 = crc32_le(0, spi_buffer, 1000);
                crc32_speed = (uint32_t)(esp_timer_get_time() - tstart);
                if (debug_log >= 3) ESP_LOGI(SPI_TAG, "CRC: %04X (%u), %08X (%u)", crc16, crc16_speed, crc32, crc32_speed);

                // Print info
                printf("\r\n-----------------------------\r\n");
                printf("K210 SPI Slave info received:\r\n");
                printf("-----------------------------\r\n");
                printf("    Version: %s\r\n", k210_info.info);
                printf("Buffer size: %u bytes (Read Only: %u bytes) [ESP32: %u bytes]\r\n", k210_info.databuff_size, k210_info.databuff_ro_size, spi_master_buffer_size);
                printf("CRC16 speed: %u ns [ESP32: %u us] per 1000 bytes\r\n", k210_info.crc_speed, crc16_speed);
                printf("CRC32 speed: %u ns [ESP32: %u us] per 1000 bytes\r\n\r\n", k210_info.crc32_speed, crc32_speed);

                if (debug_log >= 1) getStatsInfo(true, true);

                k210_slave_connected = true;
                setStatus(ESP32_STATUS_K210_DETECTED, SET_STATUS_OP_OR);
                vTaskDelay(pdMS_TO_TICKS(50));
                k210_status_send(ESP32_STATUS_CODE_STATUS, getStatus());

                vTaskDelay(pdMS_TO_TICKS(50));
                time_t seconds;
                time(&seconds); // get the time from the RTC
                k210_status_send(ESP32_STATUS_CODE_TIME, seconds);
                vTaskDelay(pdMS_TO_TICKS(10));

                break;
            }
            else {
                if (debug_log >= 2) ESP_LOGW(SPI_TAG, "CRC Error");
                //ESP_LOG_BUFFER_HEX(SPI_TAG, SPI_RW_BUFFER, SLAVE_INFO_LENGTH+2);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(POOLING_INTERVAL));

        gettimeofday(&current_time, NULL);
        if ((current_time.tv_sec - start_wait_time.tv_sec) > K210_RESPONSE_TIMEOUT) {
            ESP_LOGW(SPI_TAG, "No response from K210 in %d seconds, go to sleep!", K210_RESPONSE_TIMEOUT);
            time_t sleep_time = ((current_time.tv_sec / 3600) * 3600) + 3600;
            xQueueSend(main_evt_queue, (void *)&sleep_time, pdMS_TO_TICKS(500));
            vTaskDelay(pdMS_TO_TICKS(POOLING_INTERVAL));
        }
        continue;
    }
    return true;
}

//--------------------------------
uint16_t getCommand(uint16_t type)
{
    esp_err_t ret;
    bool crcok;
    uint16_t res = ESP_ERROR_OK;

    if (debug_log >= 2) ESP_LOGI(SPI_TAG, "Check command");

    ret = transferData(SLAVE_CMD_RDSTAT | SLAVE_CMD_OPT_CRC, SLAVE_BUFFER_CMD_ADDRESS, 4, NULL);
    crcok = checkCRC(SPI_RW_BUFFER, 4);
    if ((ret != ESP_OK) || (!crcok) || (SPI_RW_BUFFER[1] != (type>>8))) {
        if (ret != ESP_OK) res = ESP_ERROR_READ;
        else if (!crcok) res = ESP_ERROR_CRC;
        else res = ESP_ERROR_NOCMD;
        if (debug_log >= 1) {
            if (ret != ESP_OK) ESP_LOGW(SPI_TAG, "Get command: com error %d\n", ret);
            else if (!crcok) ESP_LOGW(SPI_TAG, "Get command: crc error\n");
            else ESP_LOGW(SPI_TAG, "Get command: bad command %d, expected %d\n", SPI_RW_BUFFER[1], ESP_STATUS_MREQUEST>>8);
        }
    }
    else if (debug_log >= 2) ESP_LOGI(SPI_TAG, "OK.");
    return res;
}

//----------------------------------
esp_err_t send_response(uint8_t opt)
{
    uint8_t *wrbuf = SPI_RW_BUFFER;
    wrbuf[0] = esp_cmdstat & 0xFF;
    wrbuf[1] = esp_cmdstat >> 8;
    wrbuf[2] = esp_len & 0xFF;
    wrbuf[3] = esp_len >> 8;
    uint32_t crc = crc32_le(0, wrbuf, esp_len+4);
    memcpy(wrbuf + esp_len + 4, (void *)&crc, 4);
    setCRC(SPI_RW_BUFFER, esp_len+8);

    return transferData(SLAVE_CMD_WRITE | opt, SLAVE_BUFFER_CMD_ADDRESS, esp_len+8, NULL);
}

//------------------------------
static bool spi_interface_init()
{
    // ========================================
    // ==== Configure SPI interface ===========
    // ========================================

    func_semaphore = xSemaphoreCreateBinary();
    if (func_semaphore == NULL) {
        ESP_LOGE(SPI_TAG, "Error creating function semaphore");
        return false;
    }
    sock_mutex = xSemaphoreCreateMutex();
    if (sock_mutex == NULL) {
        ESP_LOGE(SPI_TAG, "Error creating socket mutex");
        return false;
    }

    // Configuration for the SPI bus
    spi_bus_config_t buscfg = {
        .mosi_io_num     = GPIO_MOSI,
        #if SPI_MASTER_3WIRE
        .miso_io_num     = -1,
        #else
        .miso_io_num     = GPIO_MISO,
        #endif
        .sclk_io_num     = GPIO_SCLK,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = SPI_BUFFER_SIZE_MAX,
        .intr_flags      = ESP_INTR_FLAG_IRAM,
    };

    // Configuration for the SPI master interface
    spi_device_interface_config_t devcfg = {
        .clock_speed_hz   = SPI_MASTER_CLOCK,
        .mode             = 0,
        .queue_size       = 1,
        #if SPI_MASTER_3WIRE
        .spics_io_num     = -GPIO_CS,
        .flags            = SPI_DEVICE_3WIRE | SPI_DEVICE_HALFDUPLEX, // | SPI_DEVICE_NO_DUMMY,
        #else
        .spics_io_num     = GPIO_CS,
        .flags            = 0,
        #endif
        .duty_cycle_pos   = 128,
    };

    #if SPI_MASTER_3WIRE
    gpio_pad_select_gpio(GPIO_CS);
    if (gpio_set_direction(GPIO_CS, GPIO_MODE_OUTPUT) != ESP_OK) {
        ESP_LOGE(SPI_TAG, "Error initializing CS pin");
        return false;
    }
    if (gpio_set_level(GPIO_CS, 1) != ESP_OK) {
        ESP_LOGE(SPI_TAG, "Error initializing CS pin");
        return false;
    }
    #endif

    // Configure pin for the handshake line
    gpio_config_t io_conf = {
        .intr_type    = GPIO_INTR_NEGEDGE, //GPIO_INTR_LOW_LEVEL
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = 1,
        .pull_down_en = 0,
        .pin_bit_mask = (1<<GPIO_HANDSHAKE)
    };

    // Configure handshake line as input
    if (gpio_config(&io_conf) != ESP_OK) {
        ESP_LOGE(SPI_TAG, "Error initializing handshake pin");

        return false;
    }
    if (gpio_intr_disable(GPIO_HANDSHAKE) != ESP_OK) {
        ESP_LOGE(SPI_TAG, "Error initializing handshake pin");
        return false;
    }
    // Hook isr handler for handshake pin
    //ret = gpio_isr_register(spi_handshake_isr_handler, NULL, ESP_INTR_FLAG_LOWMED | ESP_INTR_FLAG_EDGE | ESP_INTR_FLAG_IRAM, NULL);
    //if (ret != ESP_OK) {
    if (gpio_isr_handler_add(GPIO_HANDSHAKE, spi_handshake_isr_handler, NULL) != ESP_OK) {
        ESP_LOGE(SPI_TAG, "Error initializing handshake pin interrupt");
        return false;
    }

    #if !SPI_MASTER_3WIRE
    gpio_set_pull_mode(GPIO_MISO, GPIO_PULLUP_ONLY);
    #endif

    // Initialize SPI bus
    #if SPI_MASTER_3WIRE
    if (spi_bus_initialize(HSPI_HOST, &buscfg, 0) != ESP_OK) {
    #else
        if (spi_bus_initialize(HSPI_HOST, &buscfg, DMA_CHAN) != ESP_OK) {
    #endif
        ESP_LOGE(SPI_TAG, "Error initializing SPI Master bus");
        return false;
    }
    // Attach the SPI device to the SPI bus
    if (spi_bus_add_device(HSPI_HOST, &devcfg, &master_handle) != ESP_OK) {
        ESP_LOGE(SPI_TAG, "Error initializing SPI Master device");
        return false;
    }

    if (debug_log) printf("* SPI Master configured (native pins: %s, speed = %d Hz)\r\n",
            spi_device_uses_native_pins(master_handle) ? "true" : "false", spi_device_get_speed(master_handle));

    return true;
}

//--------------------------------
static bool spi_interface_deinit()
{
    spi_bus_remove_device(master_handle);
    spi_bus_free(HSPI_HOST);
    return true;
}

/*
 * ESP32 master <-> K210 slave command procedure:
 *   0. K210 sends the handshake
 *   1. esp32 checks the command, 1st 4 bytes of the command buffer (SPI_CMD_RDSTAT)
 *   2. esp32 reads the full command (SPI_CMD_READ_DATA_BLOCK)
 *   3. esp32 processes the command
 *   4. esp32 sends the result to K210 slave (SPI_CMD_WRITE_DATA_BLOCK)
 */
//-------------------------------
static int process_K210_request()
{
    esp_err_t ret;
    uint16_t res;
    int32_t do_exit = 0;

    // (1.) Check the command
    res = getCommand(ESP_STATUS_MREQUEST);

    if (res == ESP_ERROR_OK) {
        // ===============================================
        // ==== Command execution requested from K210 ====
        // ===============================================

        // Command execution requested, first 4 bytes of the command are in 'SPI_RW_BUFFER'
        esp_len = *((uint16_t *)(SPI_RW_BUFFER+2));
        if (esp_len <= (spi_master_buffer_size-32)) {
            // Short delay between transactions
            ets_delay_us(10);
            // (2.) we have the command length, read the full command frame
            spi_transaction_length = esp_len+8;
            ret = transferData(SLAVE_CMD_READ, SLAVE_BUFFER_CMD_ADDRESS, spi_transaction_length, NULL);
            if (ret == ESP_OK) {
                // Command frame read, check it
                if (command_frame_check()) {
                    if (debug_log >= 2) ESP_LOGI(SPI_TAG, "Command: %d (0x%02X)", esp_cmdstat&0xff, esp_cmdstat&0xff);

                    // (3.) Process the command
                    do_exit = processCommand();

                    if ((esp_cmdstat == 0) && (debug_log >= 1)) ESP_LOGW(SPI_TAG, "Command (%04X) does not require response\r\n", *((uint16_t *)(SPI_RW_BUFFER)));
                }
                else ets_delay_us(500);
                if (debug_log >= 2) ESP_LOGI(SPI_TAG, "Command processed\r\n");
            }
            else {
                if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Command: Read Error!\r\n");
                esp_cmdstat |= ESP_ERROR_READ;
                esp_len = 0;
                ets_delay_us(500);
            }
        }
        else {
            if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Command: Length to large (%u)\r\n", esp_len);
            esp_cmdstat |= ESP_ERROR_LENGTH;
            esp_len = 0;
            ets_delay_us(500);
        }
    }
    else {
        esp_cmdstat |= res;
        esp_len = 0;
        ets_delay_us(500);
    }

    // ---------------------------------------------
    // (4.) Command was processed, send the response
    // ---------------------------------------------
    ret = send_response(SLAVE_CMD_OPT_CRC);
    if (ret == ESP_OK) {
        if (debug_log >= 2) {
            ESP_LOGI(SPI_TAG, "Command: Response sent (cmd=%04X, len=%u)\r\n", *((uint16_t *)(SPI_RW_BUFFER)), *((uint16_t *)(SPI_RW_BUFFER + 2)));
            //ESP_LOG_BUFFER_HEX(SPI_TAG, SPI_RW_BUFFER, 64);
        }
    }
    else if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Command: Error sending response\r\n");

    // Clean the receive buffer
    memset(spi_buffer, 0, spi_master_buffer_size);
    return do_exit;
}

//==========================================================
// SPI communication task
// All communication with K210 is performed from this task !
//==========================================================

//================================
void IRAM_ATTR SPI_task(void* arg)
{
    uint32_t notify_value = 0;
    int32_t do_exit = 0;
    struct timeval start_wait_time;
    struct timeval current_time;

    if (debug_log >= 1) ESP_LOGW(SPI_TAG, "SPI Master task started");
    //Subscribe this task to TWDT, then check if it is subscribed
    CHECK_ERROR_CODE(esp_task_wdt_add(NULL), ESP_OK);
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_OK);

    if (!spi_interface_init()) goto exit;

    for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
        opened_sockets[i].fd = -1;
        opened_sockets[i].parrent = -1;
        opened_sockets[i].connected = false;
        opened_sockets[i].rdset = false;
        opened_sockets[i].listening = false;
        opened_sockets[i].ssl = false;
    }

    // create the socket task
    if (xTaskCreatePinnedToCore(SOCKET_task, "SOCK task", 3072, NULL, 6, &socket_task_handle, 1) != pdPASS) {
        ESP_LOGE(SPI_TAG, "Error creating socket task");
        goto exit;
    }

    // wait for power to K210 to be switched on
    while (!vdd_enabled) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // === Wait until K210 is detected ===
    if (!detectK210()) goto exit;
    // ===================================

    vTaskDelay(pdMS_TO_TICKS(50));
    // request from K210 to close all open files
    k210_file_closeall();
    vTaskDelay(pdMS_TO_TICKS(20));

    if (debug_log >= 1) printf("* Waiting command...\r\n\r\n");

    gettimeofday(&start_wait_time, NULL);

    while(1) {
        // Watchdog reset
        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);

        // === Check if there is a command to process ===

        // --- Wait for request (low pulse on handshake line) ---
        notify_value = 0;
        gpio_intr_enable(GPIO_HANDSHAKE);
        BaseType_t res = xTaskNotifyWait(0, ULONG_MAX, &notify_value, pdMS_TO_TICKS(1000));
        gpio_intr_disable(GPIO_HANDSHAKE);
        if (res == pdPASS) {
            // Watchdog reset
            CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);

            if (notify_value & SPI_NOTIFY_EXIT) {
                // exit request
                spi_interface_deinit();
                break;
            }

            if (notify_value & SPI_NOTIFY_HANDSHAKE) {
                // handshake detected, possible K210's request
                // wait for high handshake level
                uint64_t tmo = esp_timer_get_time() + 300;
                bool f = false;
                while (esp_timer_get_time() < tmo) {
                    if (gpio_get_level(GPIO_HANDSHAKE) == 1) {
                        f = true;
                        break;
                    }
                }
                if (!f) {
                    if (debug_log >= 2) ESP_LOGI(SPI_TAG, "Handshake, but no high edge");
                    continue;
                }
                // ===============================================
                // ==== Command execution requested from K210 ====
                // ===============================================
                //ets_delay_us(100); // delay after handshake high
                gpio_set_level(WDT_RESET_PIN, true);
                //-------------------------------
                do_exit = process_K210_request();
                //-------------------------------
                gpio_set_level(WDT_RESET_PIN, false);
                // reset request timeout
                gettimeofday(&start_wait_time, NULL);
                if (do_exit != 0) {
                    // exit request
                    break;
                }
            }

            if (notify_value & SPI_NOTIFY_FUNC_MASK) {
                // internal request
                process_internal_request((uint8_t)(notify_value & SPI_NOTIFY_FUNC_MASK));
            }
        }
        #if K210_INACTIVITY_CHECK
        // Check for how long K210 did not sent a request
        gettimeofday(&current_time, NULL);
        int time_to_sleep = (int)(current_time.tv_sec - start_wait_time.tv_sec);
        if (time_to_sleep > K210_REQUEST_TIMEOUT) {
            ESP_LOGW(SPI_TAG, "No request from K210 in %ld seconds, go to sleep!", current_time.tv_sec - start_wait_time.tv_sec);
            time_t sleep_time = ((current_time.tv_sec / wakeup_interval) * wakeup_interval) + wakeup_interval;
            if ((sleep_time - current_time.tv_sec) <= 60) sleep_time += wakeup_interval;
            xQueueSend(main_evt_queue, (void *)&sleep_time, pdMS_TO_TICKS(500));
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
        else if (time_to_sleep > (K210_REQUEST_TIMEOUT-30)) {
            ESP_LOGW(SPI_TAG, "No request from K210 in %d seconds, deepsleep pending!", time_to_sleep);
            vTaskDelay(pdMS_TO_TICKS(1000));
            // Send warning to K210
            k210_status_send(ESP32_STATUS_CODE_SLEEP, K210_REQUEST_TIMEOUT-time_to_sleep);
        }
        #endif
    }

exit:
    spi_interface_deinit();

    if (socket_task_handle) {
        xTaskNotify(socket_task_handle, 0xA55A0000 , eSetBits);
        vTaskDelay(2);
    }
    spi_task_handle = NULL;

    if (sock_mutex != NULL) vSemaphoreDelete(sock_mutex);
    if (func_semaphore != NULL) vSemaphoreDelete(func_semaphore);

    if (spi_buffer) {
        free(spi_buffer);
        spi_buffer = NULL;
    }
    if (debug_log >= 1) ESP_LOGW(SPI_TAG, "SPI Master task terminated");

    CHECK_ERROR_CODE(esp_task_wdt_delete(NULL), ESP_OK);             //Unsubscribe task from TWDT
    CHECK_ERROR_CODE(esp_task_wdt_status(NULL), ESP_ERR_NOT_FOUND);  //Confirm task is unsubscribed

    if (do_exit != 0) {
        xQueueSend(main_evt_queue, (void *)&do_exit, pdMS_TO_TICKS(500));
        vTaskDelay(200);
    }
    vTaskDelete(NULL);
}
