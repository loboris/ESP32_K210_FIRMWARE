
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/errno.h>

#include "esp32/rom/crc.h"

#include "tcpip_adapter.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/ip4.h"
#include "lwip/igmp.h"
#include "lwip/errno.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "global.h"

typedef struct _ssl_socket_t
{
    int                      fd;
    void                     *cert_pem_data;
    int                      cert_pem_len;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context      ssl;
    mbedtls_x509_crt         cacert;
    mbedtls_x509_crt         client_cert;
    mbedtls_pk_context       client_key;
    mbedtls_ssl_config       conf;
    mbedtls_net_context      client_fd;
    mbedtls_net_context      remote_fd;
    void                     *client_cert_pem_data;
    int                      client_cert_pem_len;
    void                     *client_key_pem_data;
    int                      client_key_pem_len;
    bool                     mutual_authentication;
    bool                     ssl_initialized;
    bool                     verify_server;
} ssl_socket_t;

#define SSL_SOCKET_FD_OFFSET    31000
#define SOCKET_CONNECT_TIMEOUT  3000
#define SOCKET_CHECK_INTERVAL   20


size_t spi_transaction_length = 0;
int16_t esp_cmdstat = 0;
uint16_t esp_len = 0;
socketcfg_t opened_sockets[CONFIG_LWIP_MAX_SOCKETS];

static char rqurl[REQUESTS_URL_MAX_SIZE];
static ssl_socket_t *ssl_sockets[CONFIG_LWIP_MAX_SOCKETS] = {NULL};

static const char *SOCK_TAG = "[SPI_TASK_SOCK]";
static const char *SOCK_TAG_SSL = "[SPI_TASK_SOCK_SSL]";

//============================
bool command_frame_check(void)
{
    uint32_t crc, calc_crc;
    bool res = false;

    // Analyze received data (in 'SPI_RW_BUFFER')
    esp_len = *((uint16_t *)(SPI_RW_BUFFER+2));
    spi_transaction_length = esp_len+8;
    if (spi_transaction_length >= 8) {
        // Transaction length OK
        esp_cmdstat = (*(uint16_t *)(SPI_RW_BUFFER)) & 0x00FF;
        if ((esp_cmdstat > ESP_COMMAND_NONE) && (esp_cmdstat < ESP_COMMAND_MAX)) {
            // Valid command received
            if (esp_len <= (spi_master_buffer_size-64)) {
                // Length ok
                memcpy((void *)&crc, SPI_RW_BUFFER + esp_len + 4, 4);
                calc_crc = crc32_le(0, SPI_RW_BUFFER, esp_len + 4);
                if (crc == calc_crc) {
                    // CRC32 check passed, command accepted
                    res = true;
                }
                else {
                    if (debug_log >= 1) {
                        ESP_LOGW(SPI_TAG, "Transaction: len=%u, CRC Error (%08X <> %08X)", esp_len, crc, calc_crc);
                        //ESP_LOG_BUFFER_HEX(SPI_TAG, SPI_RW_BUFFER, ((esp_len+8) > 128) ? 128 : (esp_len+8));
                    }
                    esp_cmdstat |= ESP_ERROR_CRC;
                    esp_len = 0;
                }
            }
            else {
                if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Transaction: Length error (%u)", esp_len);
                esp_cmdstat |= ESP_ERROR_LENGTH;
                esp_len = 0;
            }
        }
        else {
            // Not a valid command
            if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Transaction: No valid command");
            esp_cmdstat |= ESP_ERROR_NOCMD;
            esp_len = 0;
        }
    }
    else {
        // Valid transaction length must be at least 8 bytes
        if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Transaction: Frame length error (%d)", spi_transaction_length);
        esp_cmdstat = ESP_ERROR_FRAME;
        esp_len = 0;
    }
    return res;
}

//--------------------------------------------------
static void close_mbedtls_socket(ssl_socket_t *sock)
{
    if (sock->ssl_initialized) {
        if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Cleanup mbedtls");
        mbedtls_ssl_close_notify(&sock->ssl);
        mbedtls_ssl_session_reset(&sock->ssl);
        mbedtls_net_free(&sock->client_fd);
        mbedtls_ssl_config_free(&sock->conf);
        if (sock->verify_server) {
            mbedtls_x509_crt_free(&sock->cacert);
        }
        if (sock->mutual_authentication) {
            mbedtls_x509_crt_free(&sock->client_cert);
            mbedtls_pk_free(&sock->client_key);
        }
        mbedtls_ctr_drbg_free(&sock->ctr_drbg);
        mbedtls_entropy_free(&sock->entropy);
        mbedtls_ssl_free(&sock->ssl);
        sock->mutual_authentication = false;
        sock->ssl_initialized = false;
        sock->verify_server = false;
    }
}

//-----------------------------------------------------
static int _mbed_socket_init_cacert(ssl_socket_t *sock)
{
    if (sock->verify_server) {
        mbedtls_x509_crt_free(&sock->cacert);
    }
    mbedtls_x509_crt_init(&sock->cacert);

    if (sock->cert_pem_data) {
        if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Loading the CA root certificate...");
        int ret = mbedtls_x509_crt_parse(&sock->cacert, sock->cert_pem_data, sock->cert_pem_len + 1);

        if (ret < 0) {
            if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_x509_crt_parse returned -0x%x", -ret);
            return -1;
        }
        mbedtls_ssl_conf_ca_chain(&sock->conf, &sock->cacert, NULL);
        mbedtls_ssl_conf_authmode(&sock->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

        sock->verify_server = true;
    }
    else {
        if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "No CA root certificate used.");
        mbedtls_ssl_conf_authmode(&sock->conf, MBEDTLS_SSL_VERIFY_NONE);
        sock->verify_server = false;
    }
    return 0;
}

//----------------------------------------------------------
static int _mbed_socket_init_client_cert(ssl_socket_t *sock)
{
    int ret;
    if (sock->mutual_authentication) {
        mbedtls_x509_crt_free(&sock->client_cert);
        mbedtls_pk_free(&sock->client_key);
    }

    sock->mutual_authentication = false;
    mbedtls_x509_crt_init(&sock->client_cert);
    mbedtls_pk_init(&sock->client_key);

    if (sock->client_cert_pem_data && sock->client_key_pem_data) {
        sock->mutual_authentication = true;
        if ((ret = mbedtls_x509_crt_parse(&sock->client_cert, sock->client_cert_pem_data, sock->client_cert_pem_len + 1)) < 0) {
            if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_x509_crt_parse returned -0x%x\nDATA=%s,len=%d", -ret, (char*)sock->client_cert_pem_data, sock->client_cert_pem_len);
            return -1;
        }
        if ((ret = mbedtls_pk_parse_key(&sock->client_key, sock->client_key_pem_data, sock->client_key_pem_len + 1, NULL, 0)) < 0) {
            if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_pk_parse_keyfile returned -0x%x\nDATA=%s,len=%d", -ret, (char*)sock->client_key_pem_data, sock->client_key_pem_len);
            return -1;
        }

        if ((ret = mbedtls_ssl_conf_own_cert(&sock->conf, &sock->client_cert, &sock->client_key)) < 0) {
            if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_ssl_conf_own_cert returned -0x%x", -ret);
            return -1;
        }
    }
    else if (sock->client_cert_pem_data || sock->client_key_pem_data) {
        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "You have to provide both client_cert_pem and client_key_pem for mutual authentication");
        return -1;
    }
    return 0;
}

//------------------------------------------------------------------------
static int _mbed_socket_set_hostname(ssl_socket_t *sock, const char *host)
{
    if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Setting host name ('%s') for TLS session...", (host) ? host : "_None_");
    // Host name set here should match CN in server certificate
    int ret = mbedtls_ssl_set_hostname(&sock->ssl, host);
    if (ret != 0) {
       if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
       return -1;
    }
    return 0;
}

//------------------------------------------------
static int init_mbedtls_socket(ssl_socket_t *sock)
{
    int ret;

    mbedtls_ssl_init(&sock->ssl);
    mbedtls_ctr_drbg_init(&sock->ctr_drbg);

    mbedtls_ssl_config_init(&sock->conf);

    mbedtls_entropy_init(&sock->entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&sock->ctr_drbg, mbedtls_entropy_func, &sock->entropy, NULL, 0)) != 0) {
        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_ctr_drbg_seed returned %d", ret);
        return -1;
    }

    if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&sock->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_ssl_config_defaults returned %d", ret);
        return -1;
    }

    if (_mbed_socket_init_cacert(sock) < 0) return -1;
    if (_mbed_socket_init_client_cert(sock) < 0) return -1;
    if (_mbed_socket_set_hostname(sock, NULL) < 0) return -1;

    mbedtls_ssl_conf_rng(&sock->conf, mbedtls_ctr_drbg_random, &sock->ctr_drbg);
    #ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&sock->conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
    #endif

    if ((ret = mbedtls_ssl_setup(&sock->ssl, &sock->conf)) != 0) {
        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_ssl_setup returned -0x%x", -ret);
        return -1;
    }

    sock->ssl_initialized = true;
    return 0;
}

//----------------------------------------------------------------------------------------------------
static int connect_mbedtls_socket(const char *host, int port, ssl_socket_t *sock, uint32_t timeout_ms)
{
    if (!sock->ssl_initialized) return -1;
    if (_mbed_socket_set_hostname(sock, host) != 0) return -1;

    char buf[512];
    char port_str[16] = {'\0'};
    int ret, flags;
    struct timeval tv;

    sprintf(port_str, "%d", port);

    mbedtls_net_init(&sock->client_fd);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms - (tv.tv_sec * 1000)) * 1000;
    lwip_setsockopt(sock->client_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Connecting to %s:%s...", host, port_str);

    if ((ret = mbedtls_net_connect(&sock->client_fd, host, port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_net_connect returned -%x", -ret);
        return -1;
    }
    if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Connected.");

    mbedtls_ssl_set_bio(&sock->ssl, &sock->client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Performing the SSL/TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&sock->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_ssl_handshake returned -0x%x", -ret);
            return -1;
        }
    }

    if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Verifying peer X.509 certificate...");
    if ((flags = mbedtls_ssl_get_verify_result(&sock->ssl)) != 0) {
        // In real life, we probably want to close connection if ret != 0
        if (debug_log >= 1) ESP_LOGW(SOCK_TAG_SSL, "Failed to verify peer certificate!");
        bzero(buf, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        if (debug_log >= 1) ESP_LOGW(SOCK_TAG_SSL, "verification info: %s", buf);
    }
    else {
        if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Certificate verified.");
    }

    if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&sock->ssl));
    return 0;
}

//----------------------------------------------------------------------------
static int bind_mbedtls_socket(const char *host, int port, ssl_socket_t *sock)
{
    if (!sock->ssl_initialized) return -1;

    char port_str[16] = {'\0'};

    sprintf(port_str, "%d", port);

    mbedtls_net_init(&sock->client_fd);

    // Create a receiving socket port, make the socket listening
    int ret = mbedtls_net_bind(&sock->client_fd, NULL, port_str, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0 ) {
        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_net_bind returned -%x", -ret);
        return -1;
    }

    //mbedtls_ssl_set_bio(&sock->ssl, &sock->client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    return 0;
}

//--------------------------------------------------------------------------------------------------------------
static int accept_mbedtls_socket(ssl_socket_t *sock, unsigned char *client_ip, size_t sizeip, size_t *cliip_len)
{
    int ret;
    mbedtls_net_context client_fd;
    mbedtls_net_init(&client_fd);

    ret = mbedtls_net_accept(&sock->client_fd, &client_fd, client_ip, sizeip, cliip_len);
    if (ret != 0) {
        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_net_accept returned -%x", -ret);
        return -1;
    }

    if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "Connection accepted");
    // Create new mbedtls socket
    int fd = -1;
    for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
        if (ssl_sockets[i] == NULL) {
            ssl_socket_t *skt = pvPortMalloc(sizeof(ssl_socket_t));
            if (skt) {
                memcpy(skt, sock, sizeof(ssl_socket_t));
                // Initialize mbedtls socket
                mbedtls_net_free(&skt->client_fd);
                mbedtls_ssl_session_reset(&skt->ssl);
                memcpy(&skt->client_fd, &client_fd, sizeof(mbedtls_net_context));

                mbedtls_ssl_set_bio(&skt->ssl, &skt->client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

                if (debug_log >= 1) ESP_LOGI(SOCK_TAG_SSL, "Performing client SSL/TLS handshake...");
                while ((ret = mbedtls_ssl_handshake(&skt->ssl)) != 0) {
                    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        if (debug_log >= 1) ESP_LOGE(SOCK_TAG_SSL, "mbedtls_ssl_handshake for client returned -0x%x", -ret);
                    }
                    else {
                        ssl_sockets[i] = skt;
                        ssl_sockets[i]->fd = i+SSL_SOCKET_FD_OFFSET;
                        fd = i+SSL_SOCKET_FD_OFFSET;
                    }
                }
            }
            break;
        }
    }

    return fd;
}

//-------------------------------------------------------------------------------------------
static int get_ipaddr(const char *host_str, int port, struct sockaddr_in *addr, int *errcode)
{
    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *resp;
    struct addrinfo *resi = NULL;

    *errcode = 0;
    int ret = -1;
    char port_str[16] = {0};
    sprintf(port_str, "%d", port);
    if (host_str[0] == '\0') {
        // a host of "" is equivalent to the default/all-local IP address
        host_str = "0.0.0.0";
    }
    ret = lwip_getaddrinfo(host_str, port_str, &hints, &resp);
    *errcode = errno;
    if ((ret >= 0) && (resp)) {
        for (resi = resp; resi; resi = resi->ai_next) {
            if (resi->ai_family == AF_INET) break;
        }
        if ((resi) && (resi->ai_family == AF_INET)) {
            memcpy(addr, (struct sockaddr_in *)resi->ai_addr, sizeof(struct sockaddr_in));
            ret = 0;
        }
        else *errcode = ENETRESET;
    }
    else ret = -1;
    if (resp) lwip_freeaddrinfo(resp);
    return ret;
}

//=========================
void SOCKET_task(void* arg)
{
    if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Socket task started");

    uint32_t notify_value;
    int i, ret;
    int fd;
    fd_set rfds;
    struct timeval tmout;
    tmout.tv_sec = 0;
    tmout.tv_usec = 0;

    while (1) {
        BaseType_t res = xTaskNotifyWait(0, ULONG_MAX, &notify_value, pdMS_TO_TICKS(SOCKET_CHECK_INTERVAL));
        xSemaphoreTake(sock_mutex, 100000);
        if ((res == pdPASS) && (notify_value == 0xA55A0000)) {
            // terminate task
            xSemaphoreGive(sock_mutex);
            break;
        }

        for (i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
            if ((opened_sockets[i].fd >= 0) && (opened_sockets[i].connected) && (!opened_sockets[i].rdset)) {
                fd = opened_sockets[i].fd;
                // Check if this is SSL socket
                if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                    int n = fd - SSL_SOCKET_FD_OFFSET;
                    fd = -1;
                    if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                        if (ssl_sockets[n]->fd == fd) {
                            fd = ssl_sockets[n]->client_fd.fd;
                        }
                    }
                }
                if (fd >= 0) {
                    FD_ZERO(&rfds);
                    FD_SET(fd, &rfds);

                    ret = lwip_select(fd+1, &rfds, NULL, NULL, &tmout);
                    if (ret >= 0) {
                        if (FD_ISSET(fd, &rfds)) {
                            // Socket has data received
                            if (k210_status_send(ESP32_STATUS_CODE_SOCKETRD, fd) == ESP_OK) opened_sockets[i].rdset = true;
                            vTaskDelay(pdMS_TO_TICKS(5));
                        }
                    }
                }
            }
        }
        xSemaphoreGive(sock_mutex);
    }

    if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Socket task terminated");
    socket_task_handle = NULL;
    vTaskDelete(NULL);
}

//--------------------------------------
static int32_t process_socket_commands()
{
    if (!wifi_is_connected) {
        if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Cmd %d, Not Connected", esp_cmdstat);
        esp_cmdstat |= ESP_ERROR_NOTCONNECTED;
        esp_len = 0;
        return 0;
    }
    xSemaphoreTake(sock_mutex, 100000);
    switch (esp_cmdstat) {
        case ESP_COMMAND_SCK_ADDRINFO: {
            // get parameters
            int port = *((int32_t *)(SPI_RW_BUFFER+4));             // port number
            const char *host_str = (const char *)(SPI_RW_BUFFER+8); // host string (domain), null terminated string
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Address Info %s:%d", host_str, port);

            char buf[16] = {'\0'};
            ip4_addr_t ip4_addr;
            struct sockaddr_in addr;
            int errcode = 0;

            int ret = get_ipaddr(host_str, port, &addr, &errcode);
            if (ret == 0) {
                // This looks odd, but it's really just a u32_t
                ip4_addr.addr = addr.sin_addr.s_addr;
                ip4addr_ntoa_r(&ip4_addr, buf, sizeof(buf));
                memcpy(SPI_RW_BUFFER+4, buf, strlen(buf)+1);
                esp_len = strlen(buf)+1;
            }
            else {
                esp_cmdstat |= ESP_ERROR_PROCESS;
                esp_len = 0;
            }
            break;
        }
        case ESP_COMMAND_SCK_OPEN: {
            // get parameters
            int domain = *((int32_t *)(SPI_RW_BUFFER+4));   // open domain
            int type = *((int32_t *)(SPI_RW_BUFFER+8));     // open type
            int proto = *((int32_t *)(SPI_RW_BUFFER+12));   // open proto
            int ssl = SPI_RW_BUFFER[16];                    // opening SSL socket (1) or not (0)
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Open (domain=%d, type=%d, proto=%d, ssl=%d)", domain, type, proto, ssl);

            int fd = -1;
            if (ssl) {
                // Find free SSL socket
                for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                    if (ssl_sockets[i] == NULL) {
                        ssl_socket_t *skt = pvPortMalloc(sizeof(ssl_socket_t));
                        if (skt) {
                            memset(skt, 0, sizeof(ssl_socket_t));
                            ssl_sockets[i] = skt;
                            ssl_sockets[i]->fd = i+SSL_SOCKET_FD_OFFSET;
                            // Initialize mbedtls socket
                            if (init_mbedtls_socket(ssl_sockets[i]) == 0) fd = i+SSL_SOCKET_FD_OFFSET;
                        }
                        break;
                    }
                }
            }
            else {
                fd = lwip_socket(domain, type, proto);
                if (fd >= 0) {
                    // set the socket as non blocking
                    int res = lwip_fcntl(fd, F_GETFL, 0);
                    res |= O_NONBLOCK;
                    lwip_fcntl(fd, F_SETFL, res);
                }
            }
            if (fd >= 0) {
                // Add to opened sockets list
                for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                    if (opened_sockets[i].fd < 0) {
                        opened_sockets[i].fd = fd;
                        opened_sockets[i].parrent = -1;
                        opened_sockets[i].ssl = (fd >= SSL_SOCKET_FD_OFFSET);
                        opened_sockets[i].rdset = false;
                        opened_sockets[i].listening = false;
                        opened_sockets[i].connected = false;
                        break;
                    }
                }
            }

            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Opened socket %d", fd);
            *((int32_t *)(SPI_RW_BUFFER+4)) = fd;
            esp_len = 4;
            break;
        }
        case ESP_COMMAND_SCK_CLOSE: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));   // socket's fd
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Close (fd=%d)", fd);

            int ret = -1;
            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        // close SSL socket
                        close_mbedtls_socket(ssl_sockets[n]);
                        free(ssl_sockets[n]);
                        ssl_sockets[n] = NULL;
                        ret = 0;
                    }
                }
            }
            else ret = lwip_close(fd);
            // Remove from opened sockets list
            for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                if (opened_sockets[i].fd == fd) {
                    opened_sockets[i].fd = -1;
                    opened_sockets[i].parrent = -1;
                    opened_sockets[i].ssl = false;
                    opened_sockets[i].rdset = false;
                    opened_sockets[i].listening = false;
                    opened_sockets[i].connected = false;
                    break;
                }
            }

            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Closed socket %d", fd);
            *((int32_t *)(SPI_RW_BUFFER+4)) = ret;
            esp_len = 4;
            break;
        }
        case ESP_COMMAND_SCK_POLL: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));       // socket's fd
            int arg = *((int32_t *)(SPI_RW_BUFFER+8));      // arguments
            int timeout = *((int32_t *)(SPI_RW_BUFFER+12)); // timeout in ms

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                fd = -1;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        fd = ssl_sockets[n]->client_fd.fd;
                    }
                }
            }

            int ret = 0;
            if (fd >= 0) {
                fd_set rfds; FD_ZERO(&rfds);
                fd_set wfds; FD_ZERO(&wfds);
                fd_set efds; FD_ZERO(&efds);
                struct timeval tmout;
                tmout.tv_sec = timeout / 1000;
                tmout.tv_usec = (timeout % 1000) * 1000;
                if (arg & STREAM_POLL_RD) FD_SET(fd, &rfds);
                if (arg & STREAM_POLL_WR) FD_SET(fd, &wfds);
                if (arg & STREAM_POLL_HUP) FD_SET(fd, &efds);

                ret = lwip_select(fd+1, &rfds, &wfds, &efds, &tmout);
                if (ret >= 0) {
                    ret = 0;
                    if (FD_ISSET(fd, &rfds)) ret |= STREAM_POLL_RD;
                    if (FD_ISSET(fd, &wfds)) ret |= STREAM_POLL_WR;
                    if (FD_ISSET(fd, &efds)) ret |= STREAM_POLL_HUP;
                }
                else ret = -1;
            }

            if ((debug_log >= 1) && (ret > 0)) ESP_LOGI(SOCK_TAG, "Poll (fd=%d, arg=%d, tmo=%d) res=%d", fd, arg, timeout, ret);
            *((int32_t *)(SPI_RW_BUFFER+4)) = ret;
            esp_len = 4;
            break;
        }
        case ESP_COMMAND_SCK_CONNECT: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));                   // socket's fd
            int port = *((int32_t *)(SPI_RW_BUFFER+8));                 // remote port
            const char *host_str = (const char *)(SPI_RW_BUFFER+12);    // remote domain
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Connect (fd=%d, port=%d, host='%s')", fd, port, host_str);

            int errcode = 0;
            int ret = -1;
            CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        // Connect SSL socket
                        ret = connect_mbedtls_socket(host_str, port, ssl_sockets[n], SOCKET_CONNECT_TIMEOUT);
                        if (ret != 0) {
                            // close SSL socket
                            close_mbedtls_socket(ssl_sockets[n]);
                            free(ssl_sockets[n]);
                            ssl_sockets[n] = NULL;
                        }
                    }
                }
            }
            else {
                struct sockaddr_in addr;
                ret = get_ipaddr(host_str, port, &addr, &errcode);
                if (ret == 0) {
                    // Non blocking socket is used, wait for connection
                    fd_set readset;
                    fd_set writeset;
                    fd_set errset;
                    struct timeval tv;
                    FD_ZERO(&readset);
                    FD_SET(fd, &readset);
                    FD_ZERO(&writeset);
                    FD_SET(fd, &writeset);
                    FD_ZERO(&errset);
                    FD_SET(fd, &errset);
                    tv.tv_sec = SOCKET_CONNECT_TIMEOUT / 1000;
                    tv.tv_usec = (SOCKET_CONNECT_TIMEOUT - (tv.tv_sec * 1000)) * 1000;

                    ret = lwip_connect(fd, (struct sockaddr *)&addr, sizeof(addr));
                    // should have an error: "inprogress"
                    ret = lwip_select(fd + 1, &readset, &writeset, &errset, &tv);
                    if (ret < 1) ret = -1;
                    else if (FD_ISSET(fd, &errset)) ret = -1;
                    else {
                        ret = 0;
                        if (FD_ISSET(fd, &readset)) ret |= STREAM_POLL_RD;
                        if (FD_ISSET(fd, &writeset)) ret |= STREAM_POLL_WR;
                    }
                }
                else ret = -1;
            }
            errcode = errno;
            if (ret >= 0) {
                // Mark as connected in opened sockets list
                for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                    if (opened_sockets[i].fd == fd) {
                        opened_sockets[i].connected = true;
                        break;
                    }
                }
            }
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Connect (res=%d, err=%d)", ret, errcode);

            *((int32_t *)(SPI_RW_BUFFER+4)) = ret;
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            esp_len = 8;
            break;
        }
        case ESP_COMMAND_SCK_BIND: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));                   // socket's fd
            int port = *((int32_t *)(SPI_RW_BUFFER+8));                 // remote port
            const char *host_str = (const char *)(SPI_RW_BUFFER+12);    // remote domain
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Bind (fd=%d, port=%d, host='%s')", fd, port, host_str);

            int errcode = 0;
            int ret = -1;

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        // Bind SSL socket
                        ret = bind_mbedtls_socket(host_str, port, ssl_sockets[n]);
                        if (ret != 0) {
                            // close SSL socket
                            close_mbedtls_socket(ssl_sockets[n]);
                            free(ssl_sockets[n]);
                            ssl_sockets[n] = NULL;
                        }
                    }
                }
            }
            else {
                struct sockaddr_in addr;
                ret = get_ipaddr(host_str, port, &addr, &errcode);
                if (ret == 0) {
                    ret = lwip_bind(fd, (struct sockaddr *)&addr, sizeof(addr));
                    if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Bind res=%d (%d)", ret, errno);
                }
                else {
                    if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Bind, get ip error %d", errcode);
                    ret = -1;
                }
            }
            errcode = errno;
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Bind (res=%d, err=%d)", ret, errcode);

            *((int32_t *)(SPI_RW_BUFFER+4)) = ret;
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            esp_len = 8;
            break;
        }
        case ESP_COMMAND_SCK_LISTEN: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));                   // socket's fd
            int backlog = *((int32_t *)(SPI_RW_BUFFER+8));              // backlog
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Listen (fd=%d, backlog=%d)", fd, backlog);

            int errcode = 0;
            int ret = -1;

            // Check if this is SSL socket
            if ((fd < SSL_SOCKET_FD_OFFSET)) {
                ret = lwip_listen(fd, backlog);
                errcode = errno;
            }
            else ret = 0;
            if (ret >= 0) {
                // Mark as listening in opened sockets list
                for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                    if (opened_sockets[i].fd == fd) {
                        opened_sockets[i].listening = true;
                        break;
                    }
                }
            }
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Listen (res=%d, err=%d)", ret, errcode);

            *((int32_t *)(SPI_RW_BUFFER+4)) = ret;
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            esp_len = 8;
            break;
        }
        case ESP_COMMAND_SCK_ACCEPT: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));                   // socket's fd
            int timeout = *((int32_t *)(SPI_RW_BUFFER+8));              // timeout in ms
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Accept (fd=%d, tmo=%d)", fd, timeout);

            ssl_socket_t *sock = NULL;
            struct sockaddr addr;
            socklen_t addr_len = sizeof(addr);
            int new_fd = -1;
            int errcode = 0;
            int remote_port = -1;
            int n = 0;
            int ret = 0;
            char remote_ip[16] = {'\0'};
            size_t cliip_len;
            uint64_t wait_start = esp_timer_get_time();
            uint64_t wait_end = wait_start + (timeout*1000);

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                ret = -1;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        sock = ssl_sockets[n];
                        mbedtls_net_set_nonblock(&sock->client_fd);
                        ret = 0;
                    }
                }
            }

            if (ret == 0) {
                while (esp_timer_get_time() < wait_end) {
                    // Check if this is SSL socket
                    if (sock) {
                        // Accept on SSL socket
                        int ret = accept_mbedtls_socket(ssl_sockets[n], (unsigned char *)remote_ip, 16, &cliip_len);
                        if (ret > 0) {
                            new_fd = ret;
                            break;
                        }
                        else if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
                            errcode = errno;
                            new_fd = -1;
                            break;
                        }
                    }
                    else {
                        // Accept on LWIP socket
                        new_fd = lwip_accept(fd, &addr, &addr_len);
                        if (new_fd >= 0) {
                            // make the return value
                            uint8_t *ip = (uint8_t*)&((struct sockaddr_in*)&addr)->sin_addr;
                            remote_port = lwip_ntohs(((struct sockaddr_in*)&addr)->sin_port);
                            snprintf(remote_ip, 16, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                            // set the new socket as non blocking
                            int res = lwip_fcntl(new_fd, F_GETFL, 0);
                            res |= O_NONBLOCK;
                            lwip_fcntl(new_fd, F_SETFL, res);
                            break;
                        }
                        else if (errno != EAGAIN) {
                            errcode = errno;
                            new_fd = -1;
                            break;
                        }
                    }
                    vTaskDelay(pdMS_TO_TICKS(1));
                    n++;
                    if ((n % 1000) == 0) {
                        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
                    }
                }
            }
            if (new_fd >= 0) {
                // Add to opened sockets list
                for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                    if (opened_sockets[i].fd < 0) {
                        opened_sockets[i].fd = new_fd;
                        opened_sockets[i].parrent = fd;
                        opened_sockets[i].ssl = (new_fd >= SSL_SOCKET_FD_OFFSET);
                        opened_sockets[i].rdset = false;
                        opened_sockets[i].listening = false;
                        opened_sockets[i].connected = true;
                        break;
                    }
                }
            }

            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Accept: (new_fd=%d, %s:%d)", new_fd, remote_ip, remote_port);
            *((int32_t *)(SPI_RW_BUFFER+4)) = new_fd;
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            *((int32_t *)(SPI_RW_BUFFER+12)) = remote_port;
            memcpy(SPI_RW_BUFFER+16, remote_ip, 16);
            esp_len = 28;
            break;
        }
        case ESP_COMMAND_SCK_SEND: {

            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));                       // socket's fd
            uint32_t timeout = *((uint32_t *)(SPI_RW_BUFFER+8));            // timeout in ms
            uint32_t datalen = *((uint32_t *)(SPI_RW_BUFFER+12));           // send data length
            uint32_t port = *((uint32_t *)(SPI_RW_BUFFER+16));              // remote port (use sendto if > 0)
            const char *data = (const char *)(SPI_RW_BUFFER+20);            // send data buffer
            const char *addr = (const char *)(SPI_RW_BUFFER+20+datalen);    // remote host, if sendto is used
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Send (fd=%d, tmo=%u, size=%u, port=%u)", fd, timeout, datalen, port);

            ssl_socket_t *sock = NULL;
            uint64_t wait_start = esp_timer_get_time();
            uint64_t wait_end = wait_start + (timeout*1000);
            int errcode = 0;
            int sentlen = 0;
            struct sockaddr_in addr_to;
            int ret = 0;
            int r;
            int n = 0;

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                ret = -1;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        sock = ssl_sockets[n];
                        mbedtls_net_set_nonblock(&sock->client_fd);
                        ret = 0;
                    }
                }
            }

            if ((port > 0) && (sock == NULL)) {
                ret = get_ipaddr(addr, port, &addr_to, &errcode);
            }

            if (ret == 0) {
                while ((esp_timer_get_time() < wait_end) && (sentlen < datalen)) {
                    if (port) {
                        // sendto
                        r = lwip_sendto(fd, data+sentlen, datalen-sentlen, 0, (struct sockaddr*)&addr_to, sizeof(addr_to));
                    }
                    else {
                        if (sock) {
                            // ssl send
                            r = mbedtls_ssl_write(&sock->ssl, (const unsigned char *)(data+sentlen), datalen-sentlen);
                            if (r == MBEDTLS_ERR_NET_CONN_RESET ) {
                                if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Send (ERROR: peer closed the connection)" );
                                errcode = errno;
                                break;
                            }
                            if ((r < 0) && ((r != MBEDTLS_ERR_SSL_WANT_READ) && (r != MBEDTLS_ERR_SSL_WANT_WRITE))) {
                                if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Send (ERROR: -0x%x", r );
                                errcode = errno;
                                break;
                            }
                        }
                        else {
                            // socket send
                            r = lwip_write(fd, data+sentlen, datalen-sentlen);
                            if ((r < 0) && (errno != EWOULDBLOCK)) {
                                errcode = errno;
                                break;
                            }
                        }
                    }
                    if (r > 0) sentlen += r;
                    vTaskDelay(pdMS_TO_TICKS(1));
                    n++;
                    if ((n % 1000) == 0) {
                        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
                    }
                }
                if (sentlen == 0) errcode = ETIMEDOUT;
            }

            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Sent %d (err=%d, n=%d, time=%llu)", sentlen, errcode, n, esp_timer_get_time() - wait_start);
            *((int32_t *)(SPI_RW_BUFFER+4)) = sentlen;
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            esp_len = 8;
            break;
        }
        case ESP_COMMAND_SCK_RECV: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));               // socket's fd
            int size = *((int32_t *)(SPI_RW_BUFFER+8));             // max size to receive
            uint32_t timeout = *((uint32_t *)(SPI_RW_BUFFER+12));   // timeout in ms
            uint8_t rcvfrom = SPI_RW_BUFFER[16];                    // recvfrom flag

            ssl_socket_t *sock = NULL;
            uint64_t wait_start = esp_timer_get_time();
            uint64_t wait_end = wait_start + (timeout*1000);
            struct sockaddr from;
            socklen_t from_len = sizeof(from);
            int ret = 0;
            int recv_len = 0;
            uint8_t peer_closed = 0;
            int n = 0;
            int errcode = 0;

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                ret = -1;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        sock = ssl_sockets[n];
                        mbedtls_net_set_nonblock(&sock->client_fd);
                        ret = 0;
                    }
                }
            }
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Receive (fd=%d, tmo=%u, size=%d, mode=%s)", fd, timeout, size, (sock) ? "SSL" : "LWIP");

            if (ret == 0) {
                void *buf = (void *)(SPI_RW_BUFFER+13); // received data buffer
                while (esp_timer_get_time() < wait_end) {
                    if (sock) {
                        // SSL receive
                        recv_len = mbedtls_ssl_read(&sock->ssl, (unsigned char *)buf, size);

                        if ((recv_len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) || (recv_len == MBEDTLS_ERR_NET_CONN_RESET)) {
                            if (debug_log >= 1) {
                                if (recv_len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) ESP_LOGI(SOCK_TAG, "Receive (connection was closed gracefully)");
                                if (recv_len == MBEDTLS_ERR_NET_CONN_RESET) ESP_LOGI(SOCK_TAG, "Receive (connection was reset by peer)");
                            }
                            peer_closed = 1;
                            break;
                        }
                        if (recv_len > 0) {
                            ret = recv_len;
                            break;
                        }
                        if (!((recv_len == MBEDTLS_ERR_SSL_WANT_READ || recv_len == MBEDTLS_ERR_SSL_WANT_WRITE))) {
                            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Receive (error -0x%x)", -recv_len);
                            ret = -1;
                            break;
                        }

                    }
                    else {
                        // lwip socket receive
                        if (rcvfrom) recv_len = lwip_recvfrom(fd, buf, size, 0, &from, &from_len);
                        else recv_len = lwip_recv(fd, buf, size, 0);

                        if (recv_len > 0) {
                            ret = recv_len;
                            break;
                        }
                        if (recv_len == 0) {
                            peer_closed = 1;
                        }
                        if (errno != EWOULDBLOCK) {
                            ret = -1;
                            errcode = errno;
                            break;
                        }
                    }
                    vTaskDelay(pdMS_TO_TICKS(1));
                    n++;
                    if ((n % 1000) == 0) {
                        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
                    }
                }
            }
            else errcode = ENOTSOCK;

            if (ret >= 0) {
                // Mark for data available check in opened sockets list
                for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                    if (opened_sockets[i].fd == fd) {
                        opened_sockets[i].rdset = false;
                        break;
                    }
                }
            }

            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "RECEIVED %d [%d] (err=%d, closed=%d, n=%d, time=%llu)",
                    ret, recv_len, errcode, peer_closed, n, esp_timer_get_time() - wait_start);

            *((int32_t *)(SPI_RW_BUFFER+4)) = ret; // received data length (> 0) or error (<= 0)
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            SPI_RW_BUFFER[12] = peer_closed;
            esp_len = 9 + recv_len;
            if (rcvfrom) {
                memcpy(SPI_RW_BUFFER+13+recv_len, (void *)&from, sizeof(from));
                esp_len += sizeof(from);
            }
            break;
        }
        case ESP_COMMAND_SCK_RDLINE: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));               // socket's fd
            uint32_t timeout = *((uint32_t *)(SPI_RW_BUFFER+8));    // timeout in ms
            uint8_t rcvfrom = SPI_RW_BUFFER[12];                    // recvfrom flag
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Read line (fd=%d, tmo=%u)", fd, timeout);

            ssl_socket_t *sock = NULL;
            uint64_t wait_start = esp_timer_get_time();
            uint64_t wait_end = wait_start + (timeout*1000);
            struct sockaddr from;
            socklen_t from_len = sizeof(from);
            int ret = 0;
            int errcode = 0;
            int recv_len = 0;
            int recv_ptr = 0;
            uint8_t peer_closed = 0;
            int n = 0;

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                ret = -1;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        sock = ssl_sockets[n];
                        ret = 0;
                    }
                }
            }

            if (ret == 0) {
                void *buf = (void *)(SPI_RW_BUFFER+13); // received data buffer
                while (esp_timer_get_time() < wait_end) {
                    if (sock) {
                        // SSL receive
                        recv_len = mbedtls_ssl_read(&sock->ssl, (unsigned char *)(buf+recv_ptr), 1);

                        if (recv_len == 1) {
                            if (*((uint8_t *)(buf+recv_ptr)) == '\n') {
                                recv_ptr++;
                                ret = recv_ptr;
                                break;
                            }
                            if (recv_ptr >= (spi_master_buffer_size-64)) {
                                recv_ptr++;
                                ret = recv_ptr;
                                break;
                            }
                            recv_ptr++;
                            continue;
                        }
                        else {
                            if ((recv_len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) || (recv_len == MBEDTLS_ERR_NET_CONN_RESET)) {
                                if (debug_log >= 1) {
                                    if (recv_len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) ESP_LOGI(SOCK_TAG, "Read line (connection was closed gracefully)");
                                    if (recv_len == MBEDTLS_ERR_NET_CONN_RESET) ESP_LOGI(SOCK_TAG, "Read line (connection was reset by peer)");
                                }
                                peer_closed = 1;
                                break;
                            }
                            if (!((recv_len == MBEDTLS_ERR_SSL_WANT_READ || recv_len == MBEDTLS_ERR_SSL_WANT_WRITE))) {
                                if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Read line (error -0x%x)", -recv_len);
                                errcode = errno;
                                ret = -1;
                                break;
                            }
                        }
                    }
                    else {
                        // lwip socket receive
                        if (rcvfrom) recv_len = lwip_recvfrom(fd, buf+recv_ptr, 1, 0, &from, &from_len);
                        else recv_len = lwip_recv(fd, buf+recv_ptr, 1, 0);

                        if (recv_len == 1) {
                            if (*((uint8_t *)(buf+recv_ptr)) == '\n') {
                                recv_ptr++;
                                ret = recv_ptr;
                                break;
                            }
                            if (recv_ptr >= (spi_master_buffer_size-64)) {
                                recv_ptr++;
                                ret = recv_ptr;
                                break;
                            }
                            recv_ptr++;
                            continue;
                        }
                        if (recv_len == 0) {
                            peer_closed = 1;
                        }
                        else {
                            if (errno != EWOULDBLOCK) {
                                errcode = errno;
                                ret = -1;
                                break;
                            }
                        }
                    }
                    vTaskDelay(pdMS_TO_TICKS(1));
                    n++;
                    if ((n % 1000) == 0) {
                        CHECK_ERROR_CODE(esp_task_wdt_reset(), ESP_OK);
                    }
                }
                if ((ret == 0) && (esp_timer_get_time() > wait_end)) errcode = ETIMEDOUT;
            }

            if (ret >= 0) {
                // Mark for data available check in opened sockets list
                for (int i=0; i<CONFIG_LWIP_MAX_SOCKETS; i++) {
                    if (opened_sockets[i].fd == fd) {
                        opened_sockets[i].rdset = false;
                        break;
                    }
                }
            }

            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Received %d (err=%d, closed=%d, n=%d, time=%llu)",
                    ret, errcode, peer_closed, n, esp_timer_get_time() - wait_start);
            *((int32_t *)(SPI_RW_BUFFER+4)) = ret; // received data length (>= 0) or error (< 0)
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            SPI_RW_BUFFER[12] = peer_closed;
            esp_len = 9 + recv_ptr;
            if (rcvfrom) {
                memcpy(SPI_RW_BUFFER+13+recv_ptr, (void *)&from, sizeof(from));
                esp_len += sizeof(from);
            }
            break;
        }
        case ESP_COMMAND_SCK_SETTIMEOUT: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));                       // socket's fd
            uint32_t timeout = *((uint32_t *)(SPI_RW_BUFFER+8));            // timeout
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Set timeout (fd=%d, tmo=%u)", fd, timeout);

            struct timeval tmout;
            tmout.tv_sec = timeout / 1000;
            tmout.tv_usec = (timeout % 1000) * 1000;

            // Check if this is SSL socket
            if ((fd >= SSL_SOCKET_FD_OFFSET)) {
                int n = fd - SSL_SOCKET_FD_OFFSET;
                fd = -1;
                if ((n < CONFIG_LWIP_MAX_SOCKETS) && (ssl_sockets[n])) {
                    if (ssl_sockets[n]->fd == fd) {
                        fd = ssl_sockets[n]->client_fd.fd;
                    }
                }
            }

            int res = 0;
            if (fd >= 0) {
                res = lwip_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const void *)&tmout, sizeof(tmout));
                if (res >= 0) res = lwip_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tmout, sizeof(tmout));
                if (res >= 0) res = lwip_fcntl(fd, F_GETFL, 0);
                if (res >= 0) {
                    res |= O_NONBLOCK;
                    res = lwip_fcntl(fd, F_SETFL, res);
                }
            }

            *((int32_t *)(SPI_RW_BUFFER+4)) = res;
            esp_len = 4;
            break;
        }
        case ESP_COMMAND_SCK_SETOPTS: {
            // get parameters
            int fd = *((int32_t *)(SPI_RW_BUFFER+4));   // socket's fd
            int opt = *((int32_t *)(SPI_RW_BUFFER+8));  // option code
            int val = *((int32_t *)(SPI_RW_BUFFER+12));  // option value
            const ip4_addr_t *buf = (const ip4_addr_t *)(SPI_RW_BUFFER+12);
            if (debug_log >= 1) ESP_LOGI(SOCK_TAG, "Set option (fd=%d, opt=%d, val=%d)", fd, opt, val);

            int ret = 0;
            int errcode = 0;

            switch (opt) {
                // level: SOL_SOCKET
                case SO_REUSEADDR: {
                    ret = lwip_setsockopt(fd, SOL_SOCKET, opt, &val, sizeof(int));
                    if (ret != 0) errcode = errno;
                    break;
                }
                // level: IPPROTO_IP
                case IP_ADD_MEMBERSHIP: {
                    // POSIX setsockopt has order: group addr, if addr, lwIP has it vice-versa
                    ret = igmp_joingroup(buf + sizeof(ip4_addr_t), buf);
                    if (ret != 0) errcode = -ret;
                    break;
                }
                default:
                    ret = -1;
            }

            *((int32_t *)(SPI_RW_BUFFER+4)) = ret;
            *((int32_t *)(SPI_RW_BUFFER+8)) = errcode;
            esp_len = 8;
            break;
        }
        default: {
            if (debug_log >= 1) ESP_LOGW(SOCK_TAG, "Unknown cmd (%d)", esp_cmdstat);
            esp_cmdstat = ESP_ERROR_COMMAND_UNKNOWN;
            esp_len = 0;
        }
    }
    xSemaphoreGive(sock_mutex);
    ets_delay_us(50);
    return 0;
}

//======================
int32_t processCommand()
{
    // === Process command ===
    esp_cmdstat &= 0x00FF;

    if ((esp_cmdstat > ESP_COMMAND_SCK_START) && (esp_cmdstat < ESP_COMMAND_SCK_MAX)) {
        return process_socket_commands();
    }

    switch (esp_cmdstat) {
        case ESP_COMMAND_ECHO: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: ECHO, len=%u", esp_len);
            break;
        }
        case ESP_COMMAND_GETTIME: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: GET TIME");
            time_t seconds;
            time(&seconds); // get the time from the RTC
            memcpy(SPI_RW_BUFFER+4, (void *)&seconds, sizeof(time_t));
            esp_len = sizeof(time_t);
            break;
        }
        case ESP_COMMAND_GETVER: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: GET VERSION");
            uint32_t ver = VERSION_NUM;
            memcpy(SPI_RW_BUFFER+4, (void *)&ver, sizeof(uint32_t));
            esp_len = sizeof(uint32_t);
            break;
        }
        case ESP_COMMAND_SETTIME: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: SET TIME");
            struct timeval current_time;
            memcpy(&current_time.tv_sec, SPI_RW_BUFFER+4, 4);
            current_time.tv_usec = 0;
            settimeofday(&current_time, NULL);
            setStatus(~ESP32_STATUS_TIME_BAD, SET_STATUS_OP_AND);

            time_t seconds;
            time(&seconds); // get the time from the RTC
            memcpy(SPI_RW_BUFFER+4, (void *)&seconds, sizeof(time_t));
            esp_len = sizeof(time_t);
            break;
        }
        case ESP_COMMAND_SETWKUPINTER: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: SET WAKEUP INTERVAL");
            uint32_t wkup_inter = 300;
            memcpy(&wkup_inter, SPI_RW_BUFFER+4, sizeof(uint32_t));
            int wkupint = 6;
            for (wkupint=0; wkupint<6; wkupint++) {
                if (wkup_inter == wakeup_intervals[wkupint]) break;
            }
            if (wkupint < 6) wakeup_interval = wkup_inter;
            else wkup_inter = 0;
            memcpy(SPI_RW_BUFFER+4, (void *)&wkup_inter, sizeof(uint32_t));
            esp_len = sizeof(uint32_t);
            break;
        }
        case ESP_COMMAND_GETVOLTAGE: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: GET VOLTAGE");
            uint32_t voltage1, voltage2;
            if (adc_mutex) xSemaphoreTake(adc_mutex, 1000);
            voltage1 = adc_voltage1;
            voltage2 = adc_voltage2;
            if (adc_mutex) xSemaphoreGive(adc_mutex);

            memcpy(SPI_RW_BUFFER+4, (void *)&voltage1, 4);
            memcpy(SPI_RW_BUFFER+8, (void *)&voltage2, 4);
            esp_len = 8;
            break;
        }
        case ESP_COMMAND_SETRTCRAM: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: SET RTC RAM");
            uint16_t size = 0;
            memcpy(&size, SPI_RW_BUFFER+4, 2);
            if (size > RTCRAM_BUFF_SIZE) esp_cmdstat |= ESP_ERROR_PROCESS;
            else memcpy(rtc_ram, SPI_RW_BUFFER+6, size);
            esp_len = 0;
            break;
        }
        case ESP_COMMAND_GETRTCRAM: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: GET RTC RAM");
            uint16_t size = 0;
            memcpy(&size, SPI_RW_BUFFER+4, 2);
            if (size > RTCRAM_BUFF_SIZE) {
                esp_cmdstat |= ESP_ERROR_PROCESS;
                esp_len = 0;
            }
            else {
                memcpy(SPI_RW_BUFFER+4, rtc_ram, size);
                esp_len = size;
            }
            break;
        }
        case ESP_COMMAND_GETKEYS: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: GET KEYS");
            uint32_t keys;
            keys = kpad_state;
            memcpy(SPI_RW_BUFFER+4, (void *)&keys, 4);
            esp_len = 4;
            break;
        }
        case ESP_COMMAND_GETSTATUS: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: GET STATUS");
            uint32_t status = getStatus();
            memcpy(SPI_RW_BUFFER+4, (void *)&status, sizeof(uint32_t));
            esp_len = sizeof(uint32_t);
            break;
        }
        case ESP_COMMAND_DEEPSLEEP: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: DEEPSLEEP");
            struct timeval current_time;
            time_t sleep_time;
            gettimeofday(&current_time, NULL);
            memcpy(&sleep_time, SPI_RW_BUFFER+4, 4);
            if (sleep_time == 0) {
                sleep_time = ((current_time.tv_sec / wakeup_interval) * wakeup_interval) + wakeup_interval;
                if ((sleep_time - current_time.tv_sec) <= 60) sleep_time += wakeup_interval;
            }

            if (sleep_time > current_time.tv_sec) {
                esp_cmdstat = 0;
                esp_len = 0;
                return sleep_time;
            }
            else {
                esp_cmdstat |= ESP_ERROR_PROCESS;
            }
            esp_len = 0;
            break;
        }
        case ESP_COMMAND_LOGENABLE: {
            uint8_t old_debug = debug_log;
            uint32_t logen;
            memcpy(&logen, SPI_RW_BUFFER+4, 4);
            if ((logen & 0xFFFFFF00) == 0x12325600) debug_log = logen & 0x07;
            ESP_LOGI(SPI_TAG, "Command: DEBUG LEVEL (%u -> %u)", old_debug, debug_log);
            esp_len = 0;
            esp_cmdstat = 0;
            break;
        }
        case ESP_COMMAND_RQGET: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: Requests GET");
            if (esp_len < REQUESTS_URL_MAX_SIZE) {
                memcpy(rqurl, SPI_RW_BUFFER+4, esp_len);
                rqurl[esp_len] = '\0';
                if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: GET [%s]", rqurl);

                requests_GET(rqurl);
            }
            else {
                esp_cmdstat |= ESP_ERROR_LENGTH;
                esp_len = 0;
            }
            break;
        }
        case ESP_COMMAND_WIFISTATUS: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: Get WiFi status");
            if (!wifi_is_connected) {
                esp_cmdstat |= ESP_ERROR_NOTCONNECTED;
                esp_len = 0;
            }
            else {
                tcpip_adapter_ip_info_t info;
                tcpip_adapter_dns_info_t dns_info;
                wifi_mode_t mode = (getStatus() & ESP32_STATUS_WIFI_MODEAP) ? TCPIP_ADAPTER_IF_STA : TCPIP_ADAPTER_IF_AP;

                tcpip_adapter_get_ip_info(mode, &info);
                tcpip_adapter_get_dns_info(mode, TCPIP_ADAPTER_DNS_MAIN, &dns_info);

                memcpy(SPI_RW_BUFFER+4, &info, sizeof(info));
                memcpy(SPI_RW_BUFFER+4+sizeof(info), &dns_info, sizeof(dns_info));

                esp_len = sizeof(info) + sizeof(dns_info);
            }
            break;
        }
        case ESP_COMMAND_INFO: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: Get ESP32 info");
            getStatsInfo(true, false);
            char *pbuff = (char *)(SPI_RW_BUFFER+4);
            esp_len = strlen(pbuff);
            break;
        }
        case ESP_COMMAND_WIFIINIT: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: WiFi init");
            if (!wifi_is_init) {
                uint8_t mode = SPI_RW_BUFFER[4];
                int ssidlen = strlen((char *)(SPI_RW_BUFFER+5));
                int passlen = strlen((char *)(SPI_RW_BUFFER+6+ssidlen));
                if ((ssidlen + passlen + 3) == (esp_len)) {
                    memset(sta_ssid, 0, 32);
                    memset(sta_password, 0, 64);
                    memset(ap_ssid, 0, 32);
                    memset(ap_password, 0, 64);
                    if (mode == WIFI_MODE_STA) {
                        strncpy((char *)sta_ssid, (char *)(SPI_RW_BUFFER+5), 31);
                        strncpy((char *)sta_password, (char *)(SPI_RW_BUFFER+6+ssidlen), 63);
                    }
                    else if (mode == WIFI_MODE_AP) {
                        strncpy((char *)ap_ssid, (char *)(SPI_RW_BUFFER+5), 31);
                        strncpy((char *)ap_password, (char *)(SPI_RW_BUFFER+6+ssidlen), 63);
                    }
                    int res = wifi_init_sta_ap(mode);
                    if (res != ESP_OK) {
                        if (debug_log >= 1) ESP_LOGW(SPI_TAG, "WiFi init error (%d)", res);
                        esp_cmdstat |= ESP_ERROR_PROCESS;
                    }
                }
                else {
                    if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Wrong ssid and/or pass length (%d+%d+2 <> %d)", ssidlen, passlen, esp_len);
                    esp_cmdstat |= ESP_ERROR_LENGTH;
                }
            }
            esp_len = 0;
            break;
        }
        case ESP_COMMAND_WIFIDEINIT: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: WiFi deinit");
            if (wifi_is_init) {
                wifi_deinit_sta_ap();
            }
            esp_len = 0;
            break;
        }
        case ESP_COMMAND_WEBSERVER_START: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: Start Web Server");
            if (!wifi_is_connected) {
                esp_cmdstat |= ESP_ERROR_NOTCONNECTED;
                esp_len = 0;
            }
            else {
                esp_cmdstat = ESP_ERROR_OK ;
                char path[32] = {'\0'};
                if (esp_len == 0) {
                    sprintf(path, "/flash");
                }
                else {
                    int pathlen = strlen((char *)SPI_RW_BUFFER);
                    if (((pathlen > 0) && (pathlen < 32)) && (pathlen == (esp_len-1))) {
                        strcpy(path, (char *)SPI_RW_BUFFER);
                    }
                    else {
                        if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Wrong path length (%d <> %d)", pathlen, esp_len-1);
                        esp_cmdstat |= ESP_ERROR_LENGTH;
                    }
                }
                if (esp_cmdstat == ESP_ERROR_OK ) {
                    if (start_web_server((const char *)path) != ESP_OK) {
                        esp_cmdstat |= ESP_ERROR_PROCESS;
                    }
                }
                esp_len = 0;
            }
            break;
        }
        case ESP_COMMAND_OTAUPDATE: {
            if (debug_log >= 1) ESP_LOGI(SPI_TAG, "Command: OTA Update");
            int md5len = strlen((char *)(SPI_RW_BUFFER+4));
            int fnamelen = strlen((char *)(SPI_RW_BUFFER+5+md5len));
            if ((md5len + fnamelen + 2) == (esp_len)) {
                memset(ota_fname, 0, sizeof(ota_fname));
                memset(ota_fmd5, 0, sizeof(ota_fmd5));
                strncpy((char *)ota_fmd5, (char *)(SPI_RW_BUFFER+4), sizeof(ota_fmd5)-1);
                strncpy((char *)ota_fname, (char *)(SPI_RW_BUFFER+5+md5len), sizeof(ota_fname)-1);
                uint32_t otareq = OTA_REQUEST_UPDATE;
                xQueueSend(ota_evt_queue, (void *)&otareq, pdMS_TO_TICKS(500));
            }
            else {
                if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Wrong md5 and/or file name length (%d+%d+2 <> %d)", md5len, fnamelen, esp_len);
                esp_cmdstat |= ESP_ERROR_LENGTH;
            }
            esp_len = 0;
            break;
        }
        default: {
            if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Command: Unknown (%d)", esp_cmdstat);
            esp_cmdstat = ESP_ERROR_COMMAND_UNKNOWN;
            esp_len = 0;
        }
    }
    return 0;
}

// ==== File functions ==================================================================

/*
 * ESP32 acts as master, requesting some file operation from K210
 * --------------------------------------------------------------
 * 1. ESP32 sends normal spi transaction with file request
 * 2. K210  responds with 50 us pulse on handshake line to confirm the response data are ready
 * 3. ESP32 reads the response data
 * --------------------------------------------------------------
 */

file_params_t file_func_params;

//----------------------------------------------
static bool _filecmd_send_get(int size, bool eq)
{
    uint8_t dbglog = debug_log;
    debug_log = 0; // disable logging during file requests
    uint8_t ntry = 3;
    int ret = ESP_FILEERR_RQSEND;

    // ===> Send file request to K210
start:
    ret = send_response(SLAVE_CMD_OPT_CRC);
    if (ret == ESP_OK) {
        // <== wait for handshake pulse (request result ready) from K210
        ret = k210_wait_handshake();
        if (ret == ESP_OK) {
            // <=== Get file request response data
            ret = transferData(SLAVE_CMD_READ, SLAVE_BUFFER_CMD_ADDRESS, size+8, NULL);
            if (ret == ESP_OK) {
                if (command_frame_check()) {
                    // received frame (length & crc) ok
                    bool f = false;
                    if (eq) f = (esp_len == size);
                    else f = (esp_len <= size);
                    if ((esp_cmdstat == ESP_COMMAND_FRESPONSE) && (f)) ret = 0;
                    else ret = ESP_FILEERR_CMDRESP;
                }
                else {
                    if (debug_log >= 1) ESP_LOGW(SPI_TAG, "File: frame error (%u)", esp_len);
                    ret = ESP_FILEERR_FRAME;
                }
            }
            else ret = ESP_FILEERR_RESPONSE;
        }
        else ret = ((ret == 1) ? ESP_FILEERR_HANDSHAKE : ESP_FILEERR_HANDSHAKE1);
    }
    else {
        if (ntry > 0) {
            ntry--;
            vTaskDelay(pdMS_TO_TICKS(50));
            goto start;
        }
        ret = ESP_FILEERR_RQSEND;
    }

    file_func_params.result = ret;
    debug_log = dbglog;
    return (ret == 0);
}

//---------------------------
static void _k210_file_open()
{
    const char *path = (const char *)file_func_params.spar;
    int flags = file_func_params.par1;
    int fd;
    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, (uint8_t *)&flags, 4);
    memcpy(SPI_RW_BUFFER+8, path, strlen(path));
    esp_len = strlen(path) + 4;
    esp_cmdstat = ESP_COMMAND_FOPEN;

    if (_filecmd_send_get(4, true)) {
        memcpy(&fd, SPI_RW_BUFFER+4, 4);
        file_func_params.result = fd;
    }
}

//---------------------------
static void _k210_file_read()
{
    int fd = file_func_params.par1;
    size_t size = file_func_params.size;
    void *dst = file_func_params.spar;

    if (size > spi_master_buffer_size) size = spi_master_buffer_size;
    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, (uint8_t *)&fd, 4);
    memcpy(SPI_RW_BUFFER+8, (uint8_t *)&size, 4);
    esp_len = 8;
    esp_cmdstat = ESP_COMMAND_FREAD;

    if (_filecmd_send_get(size, false)) {
        if (esp_len > 0) memcpy(dst, SPI_RW_BUFFER+4, esp_len);
        file_func_params.result = esp_len;
    }
}

//----------------------------
static void _k210_file_write()
{
    int fd = file_func_params.par1;
    size_t size = file_func_params.size;
    const void *data = (const void *)file_func_params.spar;

    int wrlen = -1;
    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, (uint8_t *)&fd, 4);
    memcpy(SPI_RW_BUFFER+8, (uint8_t *)data, size);
    esp_len = size + 4;
    esp_cmdstat = ESP_COMMAND_FWRITE;

    if (_filecmd_send_get(4, true)) {
        memcpy(&wrlen, SPI_RW_BUFFER+4, 4);
        file_func_params.result = wrlen;
    }
}

//----------------------------
static void _k210_file_close()
{
    int fd = file_func_params.par1;
    int res = -1;
    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, (uint8_t *)&fd, 4);
    esp_len = 4;
    esp_cmdstat = ESP_COMMAND_FCLOSE;

    if (_filecmd_send_get(4, true)) {
        memcpy(&res, SPI_RW_BUFFER+4, 4);
        file_func_params.result = res;
    }
}

//----------------------------
static void _k210_file_fstat()
{
    int fd = file_func_params.par1;
    k210_fstat_t *st = file_func_params.st;

    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, (uint8_t *)fd, 4);
    esp_len = 4;
    esp_cmdstat = ESP_COMMAND_FSTAT;

    if (_filecmd_send_get(12, true)) {
        int32_t fsize = *((int32_t *)(SPI_RW_BUFFER+8));
        if (fsize >= 0) {
            st->mode = (*((uint32_t *)(SPI_RW_BUFFER+4)) == 0x4000) ? S_IFDIR : S_IFREG;
            st->size = fsize;
            st->time = *((uint32_t *)(SPI_RW_BUFFER+12));
        }
        else file_func_params.result = -1;
    }
}

//---------------------------
static void _k210_file_stat()
{
    const char *path = (const char *)file_func_params.spar;
    k210_fstat_t *st = file_func_params.st;

    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, path, strlen(path));
    esp_len = strlen(path);
    esp_cmdstat = ESP_COMMAND_FFSTAT;

    if (_filecmd_send_get(12, true)) {
        int32_t fsize = *((int32_t *)(SPI_RW_BUFFER+8));
        if (fsize >= 0) {
            st->mode = (*((uint32_t *)(SPI_RW_BUFFER+4)) == 0x4000) ? S_IFDIR : S_IFREG;
            st->size = fsize;
            st->time = *((uint32_t *)(SPI_RW_BUFFER+12));
        }
        else file_func_params.result = -1;
    }
}

/*
   Directory list in buffer is represented as:
   | int16_t |           |     |
   | result  | dir_entry | ... |

   each dir_entry is in the format:
   | uint8_t   | uint32_t  | uint32_t  | null terminated string |
   | file_mode | file_size | file_time | file_name_string       |

   'result' is -1 on error or number of dir_entries otherwise
*/
//------------------------------
static void _k210_file_listdir()
{
    const char *path = (const char *)file_func_params.spar;
    void **listres = file_func_params.listres;

    *listres = NULL;
    int ret, res = -1;
    // ===> Send dir list request to K210
    memcpy(SPI_RW_BUFFER+4, path, strlen(path));
    esp_len = strlen(path);
    esp_cmdstat = ESP_COMMAND_FLISTDIR;
    ret = send_response(SLAVE_CMD_OPT_CRC);
    if (ret == ESP_OK) {
        // <=== wait for handshake from K210
        ret = k210_wait_handshake();
        if (ret == ESP_OK) {
            // Get result size descriptor
            if (getCommand(0) == ESP_ERROR_OK) {
                esp_len = *((uint16_t *)(SPI_RW_BUFFER+2));
                if ((esp_len >= 2) && (esp_len <= (spi_master_buffer_size-32))) {
                    // <=== read dir list data from K210
                    ets_delay_us(250);
                    ret = transferData(SLAVE_CMD_READ | SLAVE_CMD_OPT_CRC, SLAVE_BUFFER_CMD_ADDRESS, esp_len+8, NULL);
                    if (ret == ESP_OK) {
                        if (command_frame_check()) {
                            if ((esp_cmdstat == ESP_COMMAND_FRESPONSE) && (esp_len >= 2)) {
                                int16_t n_entries = *((int16_t *)(SPI_RW_BUFFER+4));
                                if (n_entries > 0) {
                                    void *list = malloc(esp_len-2);
                                    if (list) {
                                        memcpy(list, SPI_RW_BUFFER+6, esp_len-2);
                                        res = n_entries;
                                        *listres = list;
                                    }
                                    else res = 0;
                                }
                                else res = 0;
                            }
                            else res = ESP_FILEERR_CMDRESP1;
                        }
                        else res = ESP_FILEERR_FRAME1;
                    }
                    else res = ESP_FILEERR_RESPONSE1;
                }
                else res = ESP_FILEERR_SIZE;
            }
            else res = ESP_FILEERR_RESPONSE;
        }
        else res = ESP_FILEERR_HANDSHAKE;
    }
    else res = ESP_FILEERR_RQSEND;

    file_func_params.result = res;
}

//-----------------------------
static void _k210_file_remove()
{
    const char *path = (const char *)file_func_params.spar;
    int res;
    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, path, strlen(path));
    esp_len = strlen(path);
    esp_cmdstat = ESP_COMMAND_FREMOVE;

    if (_filecmd_send_get(4, true)) {
        memcpy(&res, SPI_RW_BUFFER+4, 4);
        file_func_params.result = res;
    }
}

//----------------------------
static void _k210_file_rmdir()
{
    const char *path = (const char *)file_func_params.spar;
    int res;
    // Send request to K210
    memcpy(SPI_RW_BUFFER+4, path, strlen(path));
    esp_len = strlen(path);
    esp_cmdstat = ESP_COMMAND_FRMDIR;

    if (_filecmd_send_get(4, true)) {
        memcpy(&res, SPI_RW_BUFFER+4, 4);
        file_func_params.result = res;
    }
}


// =====================
// Global file functions
// =====================

//---------------------------------------------
int k210_file_open(const char *path, int flags)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.par1 = flags;
    file_func_params.spar = (void *)path;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_open();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FOPEN, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//------------------------------------------------
int k210_file_read(int fd, void *dst, size_t size)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.par1 = fd;
    file_func_params.size = size;
    file_func_params.spar = dst;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_read();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FREAD, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//--------------------------------------------------------
int k210_file_write(int fd, const void *data, size_t size)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;
    if (size > spi_master_buffer_size) return ESP_FILEERR_SIZE;

    file_func_params.par1 = fd;
    file_func_params.size = size;
    file_func_params.spar = (void *)data;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_write();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FWRITE, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//-------------------------
int k210_file_close(int fd)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.par1 = fd;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_close();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FCLOSE, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//----------------------
int k210_file_closeall()
{
    return k210_file_close(99);
}

//-------------------------------------------
int k210_file_fstat(int fd, k210_fstat_t *st)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.par1 = fd;
    file_func_params.st = st;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_fstat();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FSTAT, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//----------------------------------------------------
int k210_file_stat(const char *path, k210_fstat_t *st)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.spar = (void *)path;
    file_func_params.st = st;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_stat();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FFSTAT, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//------------------------------------
int k210_file_remove(const char *path)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.spar = (void *)path;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_remove();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FREMOVE, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//-----------------------------------
int k210_file_rmdir(const char *path)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.spar = (void *)path;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_rmdir();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FRMDIR, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//-----------------------------------------------------
int k210_file_listdir(const char *path, void **listres)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.spar = (void *)path;
    file_func_params.listres = listres;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_file_listdir();
    else {
        xTaskNotify(spi_task_handle, ESP_COMMAND_FLISTDIR, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//-----------------------------
static void _k210_status_send()
{
    int type = file_func_params.par1;
    int val = file_func_params.par2;
    uint8_t ntry = 3;
    int ret = -1;

    // Send status to K210
start:
    ret = transferData(SLAVE_CMD_WRSTAT_CONFIRM, type, 4, (uint8_t *)&val);
    if (ret == ESP_OK) {
        uint16_t crcok = checkCRC(SPI_RW_BUFFER, 7);
        if (!crcok) {
            if (ntry > 0) {
                ntry--;
                vTaskDelay(pdMS_TO_TICKS(20));
                goto start;
            }
            if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Send status: crc error");
            ret = -2;
        }
        else if (SPI_RW_BUFFER[6] != ESP_ERROR_OK) {
            if (ntry > 0) {
                ntry--;
                vTaskDelay(pdMS_TO_TICKS(20));
                goto start;
            }
            if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Send status: Error %d\n", SPI_RW_BUFFER[6]);
            ret = -3;
        }
    }
    else {
        if (ntry > 0) {
            ntry--;
            vTaskDelay(pdMS_TO_TICKS(20));
            goto start;
        }
        if (debug_log >= 1) ESP_LOGW(SPI_TAG, "Error sending STATUS");
    }
    if ((ret == ESP_OK) && (ntry != 3) && (debug_log >= 1)) ESP_LOGD(SPI_TAG, "Status sent after retry (%d)", 3-ntry);

    file_func_params.result = ret;
    if (debug_log >= 2) ESP_LOGI(SPI_TAG, "Send status: t=%d, v=%d, res=%d, n=%d", type, val, ret, 3+ntry);
}

//-----------------------------------
int k210_status_send(int type, int val)
{
    if ((spi_task_handle == NULL) || (!k210_slave_connected)) return ESP_FILEERR_NOTCONNECTED;

    file_func_params.par1 = type;
    file_func_params.par2 = val;

    if (xTaskGetCurrentTaskHandle() == spi_task_handle) _k210_status_send();
    else {
        if (debug_log >= 2) ESP_LOGI(SPI_TAG, "Send status scheduled...");
        xTaskNotify(spi_task_handle, ESP_COMMAND_STAT_SEND, eSetBits);
        // Wait until the command is processed
        xSemaphoreTake(func_semaphore, portMAX_DELAY);
    }
    return file_func_params.result;
}

//--------------------------------------------
void process_internal_request(uint8_t command)
{
    // Execute requested command
    switch (command) {
        case ESP_COMMAND_FOPEN:
            _k210_file_open();
            break;
        case ESP_COMMAND_FREAD:
            _k210_file_read();
            break;
        case ESP_COMMAND_FWRITE:
            _k210_file_write();
            break;
        case ESP_COMMAND_FCLOSE:
            _k210_file_close();
            break;
        case ESP_COMMAND_FSTAT:
            _k210_file_fstat();
            break;
        case ESP_COMMAND_FFSTAT:
            _k210_file_stat();
            break;
        case ESP_COMMAND_FLISTDIR:
            _k210_file_listdir();
            break;
        case ESP_COMMAND_FREMOVE:
            _k210_file_remove();
            break;
        case ESP_COMMAND_FRMDIR:
            _k210_file_rmdir();
            break;
        case ESP_COMMAND_STAT_SEND:
            _k210_status_send();
            break;
        default:
            file_func_params.result = ESP_FILEERR_UNKNOWNCMD;
    }

    // inform the calling function execution finished
    xSemaphoreGive(func_semaphore);
}
