

#include "global.h"

#if USE_UART

#include "driver/uart.h"

#define UART_BUFF_SIZE      256
#define UART_NUM            UART_NUM_1

typedef struct _uart_ringbuf_t {
    uint8_t *buf;
    uint16_t size;
    uint16_t iget;
    uint16_t iput;
} uart_ringbuf_t;



static const char *TAG = "[UART]";

static QueueHandle_t uart_mutex = NULL;
static uart_ringbuf_t uart_buffer;
static uart_ringbuf_t *uart_buf = NULL;
static QueueHandle_t UART_QUEUE = NULL;
static bool uart_endtask = false;
static bool uart_data_cb = false;
static bool uart_pattern_cb = false;
static int uart_data_cb_size = 0;
static uint8_t uart_pattern[8] = "\n";
static int uart_pattern_len = 1;
static TaskHandle_t uart_task_id = NULL;

//-----------------------------------------
static void uart_ringbuf_alloc(uint16_t sz)
{
    uart_buffer.buf = malloc(sz);
    uart_buffer.size = sz;
    uart_buffer.iget = 0;
    uart_buffer.iput = 0;
    uart_buf = &uart_buffer;
}

//---------------------------------------------------------------------
static int uart_buf_get(uart_ringbuf_t *r, uint8_t *dest, uint16_t len)
{
    if (r->iget == r->iput) return -1; // input buffer empty

    int res = 0;
    for (int i=0; i<len; i++) {
        dest[i] = r->buf[r->iget++];
        res++;
        if (r->iget == r->iput) break;
    }
    // move the buffer and adjust the pointers
    memmove(r->buf, r->buf+res, r->iput - res);
    r->iget -= res;
    r->iput -= res;

    return res;
}

//-----------------------------------------------------------------------
static int uart_buf_put(uart_ringbuf_t *r, uint8_t *source, uint16_t len)
{
    int res = 0;
    for (int i=0; i<len; i++) {
        if (r->iput >= r->size) return 1; // overflow
        r->buf[r->iput++] = source[i];
    }
    return res;
}

//--------------------------------------------------------------------------------------------
static int match_pattern(uint8_t *text, int text_length, uint8_t *pattern, int pattern_length)
{
    int c, d, e, position = -1;

    if (pattern_length > text_length) return -1;

    for (c = 0; c <= (text_length - pattern_length); c++) {
        position = e = c;
        // check pattern
        for (d = 0; d < pattern_length; d++) {
            if (pattern[d] == text[e]) e++;
            else break;
        }
        if (d == pattern_length) return position;
    }

    return -1;
}

//---------------------------------------------
static void uart_event_task(void *pvParameters)
{
    uart_event_t event;
    size_t datasize;
    int res;
    uint8_t* dtmp = (uint8_t*) malloc(UART_BUFF_SIZE);

    for(;;) {
        if (uart_mutex) xSemaphoreTake(uart_mutex, 200 / portTICK_PERIOD_MS);
        if (uart_endtask) {
            if (uart_mutex) xSemaphoreGive(uart_mutex);
            break;
        }
        if (uart_mutex) xSemaphoreGive(uart_mutex);

        if (UART_QUEUE == NULL) {
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        //Waiting for UART event.
        if (xQueueReceive(UART_QUEUE, (void *)&event, 1000 / portTICK_PERIOD_MS)) {
            if (uart_mutex) xSemaphoreTake(uart_mutex, 200 / portTICK_PERIOD_MS);
            bzero(dtmp, UART_BUFF_SIZE);
            switch(event.type) {
                //Event of UART receiving data
                case UART_DATA:
                    // move UART data to buffer
                    uart_get_buffered_data_len(UART_NUM, &datasize);
                    if (datasize > 0) {
                        // read data from UART buffer
                        if (uart_read_bytes(UART_NUM, dtmp, datasize, 0) > 0) {
                            res = uart_buf_put(uart_buf, dtmp, datasize);
                            if (res) {
                                // buffer full
                            }
                            else {
                                if (uart_data_cb && (uart_data_cb_size > 0) && (uart_buf->iput >= uart_data_cb_size)) {
                                    // ** callback on data length received
                                    uart_buf_get(uart_buf, dtmp, uart_data_cb_size);
                                }
                                else if (uart_pattern_cb) {
                                    // ** callback on pattern received
                                    res = match_pattern(uart_buf->buf, uart_buf->iput,uart_pattern, uart_pattern_len);
                                    if (res >= 0) {
                                        // found, pull data, including pattern from buffer
                                        uart_buf_get(uart_buf, dtmp, res+uart_pattern_len);
                                    }
                                }
                            }
                        }
                    }
                    break;
                //Event of HW FIFO overflow detected
                case UART_FIFO_OVF:
                    // If fifo overflow happened, you should consider adding flow control for your application.
                    // The ISR has already reset the rx FIFO,
                    // As an example, we directly flush the rx buffer here in order to read more data.
                    uart_flush_input(UART_NUM);
                    xQueueReset(UART_QUEUE);
                    ESP_LOGW(TAG, "UART FIFO Overflow");
                    break;
                //Event of UART ring buffer full
                case UART_BUFFER_FULL:
                    // If buffer full happened, you should consider increasing your buffer size
                    // As an example, we directly flush the rx buffer here in order to read more data.
                    uart_flush_input(UART_NUM);
                    xQueueReset(UART_QUEUE);
                    ESP_LOGW(TAG, "UART Buffer full");
                    break;
                //Event of UART RX break detected
                case UART_BREAK:
                    ESP_LOGW(TAG, "UART Break detected");
                    break;
                //Event of UART parity check error
                case UART_PARITY_ERR:
                    ESP_LOGW(TAG, "UART Parity Error");
                    break;
                //Event of UART frame error
                case UART_FRAME_ERR:
                    ESP_LOGW(TAG, "UART Frame Error");
                    break;
                //Others
                default:
                    ESP_LOGI(TAG, "uart event type: %d", event.type);
                    break;
            }

            if (uart_mutex) xSemaphoreGive(uart_mutex);
        }
    }
    free(dtmp);
    dtmp = NULL;
    vTaskDelete(NULL);
}

//=============
void uartInit()
{
    // Set defaults parameters
   uart_config_t uartcfg = {
       .baud_rate = 115200,
       .data_bits = UART_DATA_8_BITS,
       .parity = UART_PARITY_DISABLE,
       .stop_bits = UART_STOP_BITS_1,
       .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
       .rx_flow_ctrl_thresh = 0,
       #ifdef CONFIG_PM_ENABLE
       .use_ref_tick = true
       #endif
   };
    if (uart_mutex == NULL) {
       uart_mutex = xSemaphoreCreateMutex();
    }

    ESP_LOGI(TAG, "Iniciranje");
    if (uart_buf == NULL) {
        // First time, create ring buffer
        uart_ringbuf_alloc(4096);
        if (uart_buf == NULL) {
            ESP_LOGE(TAG, "Error allocating ring buffer");
        }
    }

    // Remove any existing configuration
    ESP_LOGI(TAG, "Remove driver");
    uart_driver_delete(UART_NUM);
    // Initialize the peripheral with default parameters
    ESP_LOGI(TAG, "Config");
    uart_param_config(UART_NUM, &uartcfg);
    ESP_LOGI(TAG, "Driver install");
    esp_err_t res = uart_driver_install(UART_NUM, UART_BUFF_SIZE, 0, 20, &UART_QUEUE, 0);
    if (res != ESP_OK) {
        ESP_LOGE(TAG, "Error installing driver");
    }

    // Make sure pins are connected.
    ESP_LOGI(TAG, "Init Pins");
    uart_set_pin(UART_NUM, 26, 25, -1, -1);

    //Disable uart pattern detect function
    uart_disable_pattern_det_intr(UART_NUM);

    //Create a task to handle UART event from ISR
    ESP_LOGI(TAG, "Create task");
    xTaskCreate(uart_event_task, "uart_event_task", 8192, NULL, 10, uart_task_id);
}

//-----------------------------------------------------
char *uartRead(int timeout, char *lnend, char *lnstart)
{
    char *rdstr = NULL;
    int rdlen = -1;
    int minlen = strlen(lnend);
    if (lnstart) minlen += strlen(lnstart);

    if (timeout == 0) {
        if (uart_mutex) {
            if (xSemaphoreTake(uart_mutex, 200 / portTICK_PERIOD_MS) != pdTRUE) {
                return NULL;
            }
        }
        // check for minimal length
        if (uart_buf->iput < minlen) {
            if (uart_mutex) xSemaphoreGive(uart_mutex);
            return NULL;
        }
        while (1) {
            rdlen = match_pattern(uart_buf->buf, uart_buf->iput, (uint8_t *)lnend, strlen(lnend));
            if (rdlen >= 0) {
                // found, pull data, including pattern from buffer
                rdlen += 2;
                rdstr = calloc(rdlen+1, 1);
                if (rdstr) {
                    uart_buf_get(uart_buf, (uint8_t *)rdstr, rdlen);
                    rdstr[rdlen] = 0;
                    if (lnstart) {
                        // Match beginning string
                        char *start_ptr = strstr(rdstr, lnstart);
                        if (start_ptr) {
                            if (start_ptr != rdstr) {
                                char *new_rdstr = strdup(start_ptr);
                                free(rdstr);
                                rdstr = new_rdstr;
                            }
                            break;
                        }
                        else {
                            free(rdstr);
                            rdstr = NULL;
                            rdlen = -1;
                            break;
                        }
                    }
                    else break;
                }
                else {
                    rdlen = -1;
                    break;
                }
            }
            else break;
        }
        if (uart_mutex) xSemaphoreGive(uart_mutex);
        if (rdlen < 0) return NULL;
    }
    else {
        // wait until lnend received or timeout
        int wait = timeout;
        int buflen = 0;
        //mp_hal_set_wdt_tmo();
        while (wait > 0) {
            if (uart_mutex) {
                if (xSemaphoreTake(uart_mutex, 200 / portTICK_PERIOD_MS) != pdTRUE) {
                    vTaskDelay(10 / portTICK_PERIOD_MS);
                    wait -= 10;
                    //mp_hal_reset_wdt();
                    continue;
                }
            }
            if (buflen < uart_buf->iput) {
                // ** new data received, reset timeout
                buflen = uart_buf->iput;
                wait = timeout;
            }
            if (uart_buf->iput < minlen) {
                // ** too few characters received
                if (uart_mutex) xSemaphoreGive(uart_mutex);
                vTaskDelay(10 / portTICK_PERIOD_MS);
                wait -= 10;
                //mp_hal_reset_wdt();
                continue;
            }

            while (1) {
                // * Check if lineend pattern is received
                rdlen = match_pattern(uart_buf->buf, uart_buf->iput, (uint8_t *)lnend, strlen(lnend));
                if (rdlen >= 0) {
                    rdlen += 2;
                    // * found, pull data, including pattern from buffer
                    rdstr = calloc(rdlen+1, 1);
                    if (rdstr) {
                        uart_buf_get(uart_buf, (uint8_t *)rdstr, rdlen);
                        rdstr[rdlen] = 0;
                        if (lnstart) {
                            // * Find beginning of the sentence
                            char *start_ptr = strstr(rdstr, lnstart);
                            if (start_ptr) {
                                // === received string ending with lnend and starting with lnstart
                                if (start_ptr != rdstr) {
                                    char *new_rdstr = strdup(start_ptr);
                                    free(rdstr);
                                    rdstr = new_rdstr;
                                }
                                break;
                            }
                            else {
                                free(rdstr);
                                rdstr = NULL;
                                break;
                            }
                        }
                        else break; // === received string ending with lineend
                    }
                    else {
                        // error allocating buffer, finish
                        wait = 0;
                        break;
                    }
                }
                else break;
            }
            if (uart_mutex) xSemaphoreGive(uart_mutex);

            if (rdstr) break;
            if (wait > 0) {
                vTaskDelay(10 / portTICK_PERIOD_MS);
                wait -= 10;
                //mp_hal_reset_wdt();
            }
        }
    }
    return rdstr;
}

//-----------
int uartAny()
{
   if (uart_mutex) xSemaphoreTake(uart_mutex, 200 / portTICK_PERIOD_MS);
    int res = uart_buf->iput;
    if (uart_mutex) xSemaphoreGive(uart_mutex);

    return res;
}

//--------------
void uartFlush()
{
    if (uart_mutex) xSemaphoreTake(uart_mutex, 200 / portTICK_PERIOD_MS);
    uart_flush_input(UART_NUM);
    uart_buf->iput = 0;
    uart_buf->iget = 0;
    if (uart_mutex) xSemaphoreGive(uart_mutex);
}

//--------------------------
int uartWrite_break(int len)
{
    char b = 0;
    return uart_write_bytes_with_break(UART_NUM, &b, 1, len);
}

//_----------------------------------------
int uartWrite(const char* buf, size_t size)
{
    return uart_write_bytes(UART_NUM, buf, size);
}

#endif
