

#ifndef _MKM_GLOBAL_H_
#define _MKM_GLOBAL_H_

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_INFO

#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "driver/spi_master.h"
#include "esp_wifi.h"

typedef enum {
    SLAVE_CMD_NONE,
    SLAVE_CMD_READ,
    SLAVE_CMD_WRITE,
    SLAVE_CMD_INFO,
    SLAVE_CMD_WRSTAT,
    SLAVE_CMD_WRSTAT_CONFIRM,
    SLAVE_CMD_RDSTAT,
    SLAVE_CMD_READ_TRANS,
    SLAVE_CMD_STATUS_TRANS,
    SLAVE_CMD_MAX,
} slave_command_t;

typedef struct _k210_info_t
{
    uint32_t databuff_size;
    uint32_t databuff_ro_size;
    uint32_t crc_speed;
    uint32_t crc32_speed;
    char     info[12];
} k210_info_t;

typedef struct _k210_fstat_t
{
    uint32_t mode;
    int32_t  size;
    uint32_t time;
} k210_fstat_t;

typedef struct _k210_direntry_t
{
    k210_fstat_t stat;
    char *       name;
} k210_direntry_t;

typedef struct _file_params_t
{
    int          par1;
    int          par2;
    size_t       size;
    void         *spar;
    int          result;
    k210_fstat_t *st;
    void         **listres;
} file_params_t;

typedef struct _socketcfg_t
{
    int  fd;
    int  parrent;
    bool connected;
    bool rdset;
    bool listening;
    bool ssl;
} socketcfg_t;

#define VERSION_STR                 "1.06"
#define VERSION_NUM                 0x106

#define MAX_TRANSFER_RETRIES        8

// Declare used ESP32 pins
#define VCC_EN_PIN                  4
#define WDT_RESET_PIN               17

#define ADC1_PIN                    35
#define ADC2_PIN                    34

#define GPIO_HANDSHAKE              2
#define GPIO_MOSI                   13
#define GPIO_MISO                   12
#define GPIO_SCLK                   14
#define GPIO_CS                     15

#define KPAD2                       27
#define KPAD1                       39
#define KPAD4                       36
#define KPAD3                       21

#define USE_RTC_XTAL                1

#define OTA_REQUEST_UPDATE          0x0CD5A407

#define RTCRAM_BUFF_SIZE            2048+16

// K210 status constants
#define ESP32_STATUS_K210_DETECTED  0x00000001UL
#define ESP32_STATUS_TIME_BAD       0x00000002UL
#define ESP32_STATUS_FS_OK          0x00000004UL
#define ESP32_STATUS_WIFI_INIT      0x00000008UL
#define ESP32_STATUS_WIFI_MODEAP    0x00000010UL
#define ESP32_STATUS_WIFI_CONNECTED 0x00000020UL
#define ESP32_STATUS_WEBSERVER_OK   0x00000040UL
#define ESP32_STATUS_OTAUPDATED     0x00000080UL
#define ESP32_STATUS_OTAFAILED      0x00000100UL
#define ESP32_STATUS_KPAD_CHANGED   0x00010000UL
#define ESP32_STATUS_KPAD_MASK      0xF0000000UL
#define ESP32_STATUS_RST_MASK       0x0FF00000UL
#define ESP32_STATUS_WAKE_EXT0      0x00000011UL
#define ESP32_STATUS_WAKE_EXT1      0x00000012UL
#define ESP32_STATUS_WAKE_TIMR      0x00000013UL

// System watchdog timeout in seconds
#define TWDT_TIMEOUT_S              5
// K210 initial response timeout in seconds
#define K210_RESPONSE_TIMEOUT       300     // 5 min
// K210 inactivity timeout in seconds
#define K210_REQUEST_TIMEOUT        900     // 15 min

#define K210_INACTIVITY_CHECK       1

#define USE_SPI_MASTER              1   // Do not change !!
#define USE_ADC                     1
#define USE_KEYPAD                  1
#define USE_UART                    0

// SPI related constants
#define SLAVE_CMD_OPT_CRC           0x10
#define SLAVE_CMD_OPT_CONFIRM       0x20
#define SLAVE_INFO_LENGTH           25
#define SLAVE_BUFFER_CMD_ADDRESS    0

#define DMA_CHAN                    1

#define SPI_MASTER_3WIRE            1

#if SPI_MASTER_3WIRE
#define SPI_MASTER_CLOCK            SPI_MASTER_FREQ_16M
#else
#define SPI_MASTER_CLOCK            SPI_MASTER_FREQ_16M
#endif

// ------------------------------------------------
// Those defines must be the same in K210 firmware!
// ------------------------------------------------
#define DUMMY_BYTES                 0
#define SPI_BUFFER_SIZE_MAX         (32768+32)
#define SPI_RW_BUFFER               (spi_buffer+DUMMY_BYTES)
#define REQUESTS_URL_MAX_SIZE       256

#define ESP32_STATUS_CODE_KPD       1
#define ESP32_STATUS_CODE_VOLTAGE   2
#define ESP32_STATUS_CODE_STATUS    3
#define ESP32_STATUS_CODE_FILE      4
#define ESP32_STATUS_CODE_SOCKETRD  5
#define ESP32_STATUS_CODE_TIME      6
#define ESP32_STATUS_CODE_SLEEP     7

// -------------------------------------
// ESP32 <-> K210 communication commands
#define ESP_COMMAND_NONE             0
#define ESP_COMMAND_ECHO             1
#define ESP_COMMAND_GETTIME          2
#define ESP_COMMAND_SETTIME          3
#define ESP_COMMAND_GETVOLTAGE       4
#define ESP_COMMAND_GETKEYS          5
#define ESP_COMMAND_DEEPSLEEP        6
#define ESP_COMMAND_LOGENABLE        7
#define ESP_COMMAND_INFO             8
#define ESP_COMMAND_GETSTATUS        9
#define ESP_COMMAND_GETRTCRAM       10
#define ESP_COMMAND_SETRTCRAM       11
#define ESP_COMMAND_SETWKUPINTER    12
#define ESP_COMMAND_GETVER          13

#define ESP_COMMAND_SCK_START       20
#define ESP_COMMAND_SCK_ADDRINFO    21
#define ESP_COMMAND_SCK_OPEN        22
#define ESP_COMMAND_SCK_CLOSE       23
#define ESP_COMMAND_SCK_RECV        24
#define ESP_COMMAND_SCK_SEND        25
#define ESP_COMMAND_SCK_POLL        26
#define ESP_COMMAND_SCK_CONNECT     27
#define ESP_COMMAND_SCK_SETTIMEOUT  28
#define ESP_COMMAND_SCK_RDLINE      29
#define ESP_COMMAND_SCK_BIND        30
#define ESP_COMMAND_SCK_LISTEN      31
#define ESP_COMMAND_SCK_ACCEPT      32
#define ESP_COMMAND_SCK_SETOPTS     33
#define ESP_COMMAND_SCK_MAX         39

#define ESP_COMMAND_RQGET           90
#define ESP_COMMAND_RQNEXT          91

#define ESP_COMMAND_FILE_FUNCSTART  100
#define ESP_COMMAND_FOPEN           101
#define ESP_COMMAND_FREAD           102
#define ESP_COMMAND_FWRITE          103
#define ESP_COMMAND_FCLOSE          104
#define ESP_COMMAND_FSTAT           105
#define ESP_COMMAND_FFSTAT          106
#define ESP_COMMAND_FRESPONSE       107
#define ESP_COMMAND_FSEEK           108
#define ESP_COMMAND_FLISTDIR        109
#define ESP_COMMAND_FREMOVE         110
#define ESP_COMMAND_FRMDIR          111
#define ESP_COMMAND_FILE_FUNCMAX    112

#define ESP_COMMAND_STAT_SEND       180
#define ESP_COMMAND_OTAUPDATE       190

#define ESP_COMMAND_WIFIINIT        200
#define ESP_COMMAND_WIFISTATUS      201
#define ESP_COMMAND_WEBSERVER_START 202
#define ESP_COMMAND_WIFIDEINIT      203

#define ESP_COMMAND_MAX             255
// -------------------------------------

#define ESP_FILE_MODE_RO            0
#define ESP_FILE_MODE_RW            1
#define ESP_FILE_MODE_WR            2
#define ESP_FILE_MODE_APPEND        4

#define ESP_FILEERR_NOTCONNECTED    -11
#define ESP_FILEERR_RQSEND          -12
#define ESP_FILEERR_HANDSHAKE       -13
#define ESP_FILEERR_HANDSHAKE1      -14
#define ESP_FILEERR_RESPONSE        -15
#define ESP_FILEERR_FRAME           -16
#define ESP_FILEERR_CMDRESP         -17
#define ESP_FILEERR_SIZE            -18
#define ESP_FILEERR_RESPONSE1       -19
#define ESP_FILEERR_FRAME1          -20
#define ESP_FILEERR_CMDRESP1        -21
#define ESP_FILEERR_SIZE1           -22
#define ESP_FILEERR_UNKNOWNCMD      -23

#define ESP_ERROR_OK                0x0000
#define ESP_ERROR_COMMAND_UNKNOWN   0x0100
#define ESP_ERROR_CRC               0x0200
#define ESP_ERROR_LENGTH            0x0300
#define ESP_ERROR_NOCMD             0x0400
#define ESP_ERROR_FRAME             0x0500
#define ESP_ERROR_PROCESS           0x0600
#define ESP_ERROR_TIMEOUT           0x0700
#define ESP_ERROR_NOTCONNECTED      0x0800
#define ESP_ERROR_SPISLAVE          0x0900
#define ESP_ERROR_HANDSHAKE         0x0A00
#define ESP_ERROR_NOFS              0x0B00
#define ESP_ERROR_READ              0x0C00

#define ESP_STATUS_RQFINISH         0x6000
#define ESP_STATUS_MREQUEST         0x6100
#define ESP_STATUS_MULTIBLOCK       0x6200
// ------------------------------------------------

#define SPI_NOTIFY_HANDSHAKE        0x00010000
#define SPI_NOTIFY_FUNC_MASK        0x000000FF
#define SPI_NOTIFY_EXIT             0x00100000

#define STREAM_POLL_RD              (0x0001)
#define STREAM_POLL_WR              (0x0004)
#define STREAM_POLL_ERR             (0x0008)
#define STREAM_POLL_HUP             (0x0010)
#define STREAM_POLL_NVAL            (0x0020)

#define SET_STATUS_OP_SET           1
#define SET_STATUS_OP_AND           2
#define SET_STATUS_OP_OR            3

/*
 * Macro to check the outputs of TWDT functions and trigger an abort if an
 * incorrect code is returned.
 */
#define CHECK_ERROR_CODE(returned, expected) ({                        \
            if(returned != expected){                                  \
                printf("TWDT ERROR\n");                                \
                abort();                                               \
            }                                                          \
})

extern TaskHandle_t spi_task_handle;
extern TaskHandle_t socket_task_handle;
extern bool k210_slave_connected;
extern k210_info_t k210_info;
extern uint32_t spi_master_buffer_size;
extern SemaphoreHandle_t func_semaphore;
extern file_params_t file_func_params;
extern QueueHandle_t sock_mutex;
extern socketcfg_t opened_sockets[CONFIG_LWIP_MAX_SOCKETS];
const uint32_t wakeup_intervals[6];
extern RTC_NOINIT_ATTR uint32_t wakeup_interval;
extern RTC_NOINIT_ATTR uint8_t rtc_ram[RTCRAM_BUFF_SIZE];

void setStatus(uint32_t status, uint8_t op);
uint32_t getStatus();

int transferData(uint8_t cmd, uint32_t addr, uint32_t dsize, uint8_t *data);

#if USE_KEYPAD

extern uint8_t kpad_state;

void KeypadTask(void* arg);
#endif

// Global variables
extern uint8_t debug_log;
extern bool vdd_enabled;

#if USE_ADC
extern uint32_t adc_voltage1;
extern uint32_t adc_voltage2;
extern QueueHandle_t adc_mutex;

void ADC_task(void* arg);
#endif

#if USE_UART
void uartInit();
char *uartRead(int timeout, char *lnend, char *lnstart);
int uartAny();
void uartFlush();
int uartWrite_break(int len);
int uartWrite(const char* buf, size_t size);
#endif

void SOCKET_task(void* arg);

extern uint8_t *spi_buffer;
extern int16_t esp_cmdstat;
extern uint16_t esp_len;

extern bool wifi_is_init;
extern bool wifi_is_connected;
extern bool wifi_connect_failed;
extern char wifi_ip_address[16];
extern char wifi_netmask[16];
extern char wifi_gateway[16];
extern uint8_t sta_ssid[32];
extern uint8_t sta_password[64];
extern uint8_t ap_ssid[32];
extern uint8_t ap_password[64];

extern char ota_fname[65];
extern char ota_fmd5[33];
extern xQueueHandle ota_evt_queue;

extern xQueueHandle main_evt_queue;

extern const char *SPI_TAG;
extern size_t spi_transaction_length;

// Global functions
void getStatsInfo(bool stats, bool prn);

void SPI_task(void* arg);
esp_err_t spi_slave_transaction(void);
bool command_frame_check(void);
int32_t processCommand();
void setCRC(uint8_t *buff, int len);
bool checkCRC(uint8_t *buff, int len);
int k210_wait_handshake();
esp_err_t send_response(uint8_t opt);
uint16_t getCommand(uint16_t type);

esp_err_t start_file_server(const char *base_path);
esp_err_t stop_file_server(void);

// WiFi
int wifi_init_sta_ap(wifi_mode_t mode);
void wifi_deinit_sta_ap(void);
esp_err_t start_web_server(const char *base_path);

void requests_GET(char *url);

// K210 file system

int k210_file_open(const char *path, int flags);
int k210_file_write(int fd, const void *data, size_t size);
int k210_file_read(int fd, void *dst, size_t size);
int k210_file_close(int fd);
int k210_file_closeall();
int k210_file_fstat(int fd, k210_fstat_t *st);
int k210_file_stat(const char *path, k210_fstat_t *st);
int k210_file_listdir(const char *path, void **list);
int k210_file_remove(const char *path);
int k210_file_rmdir(const char *path);
int k210_status_send(int type, int val);

void process_internal_request(uint8_t command);

void OTA_task(void* arg);


#endif
