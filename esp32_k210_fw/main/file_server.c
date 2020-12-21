/* HTTP File Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/errno.h>
#include <libgen.h>

#include "esp_err.h"
#include "esp_log.h"

#include "esp_vfs.h"
#include "esp_spiffs.h"
#include "esp_http_server.h"

#include "global.h"

/* Max length a file path can have on storage */
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)

/* Max size of an individual file. Make sure this
 * value is same as that set in upload_script.html */
#define MAX_FILE_SIZE   (500*1024) // 200 KB
#define MAX_FILE_SIZE_STR "500KB"

/* Scratch buffer size */
#define SCRATCH_BUFSIZE  8192

struct file_server_data {
    /* Base path of file storage */
    char base_path[ESP_VFS_PATH_MAX + 1];

    /* Scratch buffer for temporary storage during file transfer */
    char scratch[SCRATCH_BUFSIZE];
};

static const char *TAG = "[File_server]";
static httpd_handle_t server = NULL;

/* Handler to redirect incoming GET request for /index.html to /
 * This can be overridden by uploading file with same name */
//-------------------------------------------------------
static esp_err_t index_html_get_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "307 Temporary Redirect");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);  // Response body can be empty
    return ESP_OK;
}

/* Handler to respond with an icon file embedded in flash.
 * Browsers expect to GET website icon at URI /favicon.ico.
 * This can be overridden by uploading file with same name */
//----------------------------------------------------
static esp_err_t favicon_get_handler(httpd_req_t *req)
{
    extern const unsigned char favicon_ico_start[] asm("_binary_favicon_ico_start");
    extern const unsigned char favicon_ico_end[]   asm("_binary_favicon_ico_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);
    httpd_resp_set_type(req, "image/x-icon");
    httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_size);
    return ESP_OK;
}

//-------------------------------------------------
static esp_err_t logo_get_handler(httpd_req_t *req)
{
    extern const unsigned char logo_start[] asm("_binary_logo_png_start");
    extern const unsigned char logo_end[]   asm("_binary_logo_png_end");
    const size_t logo_size = (logo_end - logo_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_send(req, (const char *)logo_start, logo_size);
    return ESP_OK;
}

/* Send HTTP response with a run-time generated html consisting of
 * a list of all files and folders under the requested path.
*/
//------------------------------------------------------------------------
static esp_err_t http_resp_dir_html(httpd_req_t *req, const char *dirpath)
{
    char entrypath[FILE_PATH_MAX];
    char entrysize[16];
    char entrytime[24];
    struct tm *tm_info;
    const char *entrytype;
    char dirpath_loc[strlen(dirpath)+1];

    struct dirent *entry = NULL;
    struct stat entry_stat;

    struct dirent k210_entry;
    void *dirlist = NULL;
    int n_entries = 0;
    int curr_entry = 0;
    int list_ptr = 0;

    strcpy(dirpath_loc, dirpath);

    if ((strlen(dirpath_loc) > 1) && (dirpath_loc[strlen(dirpath_loc)] == '/')) {
        dirpath_loc[strlen(dirpath_loc)] = '\0';
    }
    n_entries = k210_file_listdir(dirpath, &dirlist);
    const size_t dirpath_len = strlen(dirpath);

    /* Retrieve the base path of file storage to construct the full path */
    strlcpy(entrypath, dirpath, sizeof(entrypath));
    if (debug_log >= 1) ESP_LOGI(TAG, "Open directory '%s' -> '%s'; path='%s'", dirpath, dirpath_loc, entrypath);

    if (n_entries < 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to open K210 directory: %s (%d)", dirpath_loc, n_entries);
        /* Respond with 404 Not Found */
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Mapa ne postoji");
        return ESP_FAIL;
    }

    /* Send HTML file header */
    httpd_resp_sendstr_chunk(req, "<!DOCTYPE html><html><head ><meta http-equiv=\"Content-Type\" content= \"text/html; charset=utf-8\">");
    httpd_resp_sendstr_chunk(req, "<title>ADOS MKM2018</title></head><body background=\"/bg_w2.jpg\")><div>");
    httpd_resp_sendstr_chunk(req, "<img src=\"/logo.png\" ALIGN=\"left\" HSPACE=\"20\" VSPACE=\"20\" alt=\"Higra d.o.o.\">");
    httpd_resp_sendstr_chunk(req, "<div><p><font face=\"verdana\" color=\"brown\"><h2>ADOS - Automatski Dojavni Sustav</h2></font></p>");
    httpd_resp_sendstr_chunk(req, "<h3>Mjerno dojavni uređaj: MKM-2018</h3>(c) Higra d.o.o. 2020</div><BR CLEAR=\"left\"/></div><hr><div style=\"background-image: url('/bg_w1.jpg');\">");

    /* Get handle to embedded file upload script */
    extern const unsigned char upload_script_start[] asm("_binary_upload_script_html_start");
    extern const unsigned char upload_script_end[]   asm("_binary_upload_script_html_end");
    const size_t upload_script_size = (upload_script_end - upload_script_start);

    /* Add file upload form and script which on execution sends a POST request to /upload */
    httpd_resp_send_chunk(req, (const char *)upload_script_start, upload_script_size);

    /* Send file-list table definition and column labels */
    httpd_resp_sendstr_chunk(req,
        "<br><table class=\"fixed\" style=\"border: 1px solid black; border-collapse: collapse;\">"
        "<col width=\"600px\" /><col width=\"200px\" /><col width=\"300px\" /><col width=\"300px\" /><col width=\"100px\" />"
        "<thead style=\"background-color:rgba(194, 214, 214, 80);\"><tr><th>Ime</th><th>Tip</th><th>Veličina (Bajta)</th><th>Vrijeme</th><th>Obriši</th></tr></thead>"
        "<tbody>");

    /* Iterate over all files / folders and fetch their names and sizes */
    while (1) {
        if (dirlist == NULL) entry = NULL;
        else {
            if (curr_entry >= n_entries) entry = NULL;
            else {
                entry = &k210_entry;
                entry->d_type = (*((uint8_t *)dirlist + list_ptr) == 0) ? DT_REG : DT_DIR;
                entry_stat.st_size = (entry->d_type == DT_REG) ? *((uint32_t *)(dirlist + list_ptr + 1)) : 0;
                entry_stat.st_mtime = *((uint32_t *)(dirlist + list_ptr + 5));
                char *name = (char *)(dirlist + list_ptr + 9);
                strcpy(entry->d_name, name);
                list_ptr += strlen(name) + 10;
                curr_entry++;
            }
        }
        if (entry == NULL) break;

        entrytype = (entry->d_type == DT_DIR ? "mapa" : "datoteka");

        strlcpy(entrypath + dirpath_len, entry->d_name, sizeof(entrypath) - dirpath_len);

        sprintf(entrysize, "%ld", entry_stat.st_size);
        tm_info = gmtime(&entry_stat.st_mtime);
        strftime(entrytime, 23, "%d. %m. %Y %H:%M:%S", tm_info);
        if (debug_log >= 2) ESP_LOGI(TAG, "Found %s : %s (%s bytes, %s)", entrytype, entry->d_name, entrysize, entrytime);

        /* Send chunk of HTML file containing table entries with file name and size */
        httpd_resp_sendstr_chunk(req, "<tr style=\"border: 1px solid black;\"><td style=\"padding-left: 10px;\"><a href=\"");
        httpd_resp_sendstr_chunk(req, req->uri);
        httpd_resp_sendstr_chunk(req, entry->d_name);
        if (entry->d_type == DT_DIR) {
            httpd_resp_sendstr_chunk(req, "/");
        }
        httpd_resp_sendstr_chunk(req, "\">");
        httpd_resp_sendstr_chunk(req, entry->d_name);
        httpd_resp_sendstr_chunk(req, "</a></td><td align=\"center\">");
        httpd_resp_sendstr_chunk(req, entrytype);
        httpd_resp_sendstr_chunk(req, "</td><td style=\"padding-left: 10px;\">");
        httpd_resp_sendstr_chunk(req, entrysize);
        httpd_resp_sendstr_chunk(req, "</td><td style=\"padding-left: 10px;\">");
        httpd_resp_sendstr_chunk(req, entrytime);
        httpd_resp_sendstr_chunk(req, "</td><td align=\"center\">");
        if (entry->d_type == DT_REG) {
            httpd_resp_sendstr_chunk(req, "<form method=\"post\" action=\"/delete");
            httpd_resp_sendstr_chunk(req, req->uri);
            httpd_resp_sendstr_chunk(req, entry->d_name);
            httpd_resp_sendstr_chunk(req, "\"><button type=\"submit\">Obriši</button></form>");
        }
        httpd_resp_sendstr_chunk(req, "</td></tr>\n");
    }
    if (dirlist) free(dirlist);

    /* Finish the file list table */
    httpd_resp_sendstr_chunk(req, "</tbody></table>");

    /* Send remaining chunk of HTML file to complete it */
    httpd_resp_sendstr_chunk(req, "<br></div></body></html>");

    /* Send empty chunk to signal HTTP response completion */
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

#define IS_FILE_EXT(filename, ext) \
    (strcasecmp(&filename[strlen(filename) - sizeof(ext) + 1], ext) == 0)

/* Set HTTP response content type according to file extension */
//---------------------------------------------------------------------------------
static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filename)
{
    if (IS_FILE_EXT(filename, ".pdf")) {
        return httpd_resp_set_type(req, "application/pdf");
    } else if (IS_FILE_EXT(filename, ".html")) {
        return httpd_resp_set_type(req, "text/html");
    } else if (IS_FILE_EXT(filename, ".jpeg")) {
        return httpd_resp_set_type(req, "image/jpeg");
    } else if (IS_FILE_EXT(filename, ".ico")) {
        return httpd_resp_set_type(req, "image/x-icon");
    }
    /* This is a limited set only */
    /* For any other type always set as plain text */
    return httpd_resp_set_type(req, "text/plain");
}

/* Copies the full path into destination buffer and returns
 * pointer to path (skipping the preceding base path) */
//-----------------------------------------------------------------------------------------------------------
static const char* get_path_from_uri(char *dest, const char *base_path, const char *uri_src, size_t destsize)
{
    const char *uri = uri_src;
    /* Remove more than one leading '/' */
    while (strstr(uri, "//") == uri) {
        uri++;
    }

    const size_t base_pathlen = strlen(base_path);
    size_t pathlen = strlen(uri);

    const char *quest = strchr(uri, '?');
    if (quest) {
        pathlen = MIN(pathlen, quest - uri);
    }
    const char *hash = strchr(uri, '#');
    if (hash) {
        pathlen = MIN(pathlen, hash - uri);
    }

    if (base_pathlen + pathlen + 1 > destsize) {
        /* Full path string won't fit into destination buffer */
        return NULL;
    }

    /* Construct full path (base + path) */
    strcpy(dest, base_path);
    strlcpy(dest + base_pathlen, uri, pathlen + 1);

    /* Return pointer to path, skipping the base */
    return dest + base_pathlen;
}

/* Handler to download a file kept on the server */
//-----------------------------------------------------
static esp_err_t download_get_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    k210_fstat_t fstat;
    int fres = -1;
    int fdd = -1;

    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri, sizeof(filepath));
    if (!filename) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Filename is too long");
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Ime datoteke predugo");
        return ESP_FAIL;
    }

    /* If name has trailing '/', respond with directory contents */
    if (filename[strlen(filename) - 1] == '/') {
        return http_resp_dir_html(req, filepath);
    }

    if (debug_log >= 1) ESP_LOGI(TAG, "Requested file : '%s', '%s'", filepath, filename);
    fres = k210_file_stat(filepath, &fstat);
    if (fres < 0) {
        /* If file not present on file system check if URI
         * corresponds to one of the hardcoded paths */
        if (strcmp(filename, "/index.html") == 0) {
            return index_html_get_handler(req);
        } else if (strcmp(filename, "/favicon.ico") == 0) {
            return favicon_get_handler(req);
        } else if (strcmp(filename, "/logo.png") == 0) {
            return logo_get_handler(req);
        }
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to stat file : %s", filepath);
        /* Respond with 404 Not Found */
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Datoteka ne postoji");
        return ESP_FAIL;
    }

    fdd = k210_file_open(filepath, ESP_FILE_MODE_RO);
    if (fdd < 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to read existing file : %s (%d)", filepath, fdd);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Greška pri otvaranju datoteke");
        return ESP_FAIL;
    }

    if (debug_log >= 1) ESP_LOGI(TAG, "Sending file : %s (%d bytes)...", filename, fstat.size);
    set_content_type_from_file(req, filename);

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char *chunk = ((struct file_server_data *)req->user_ctx)->scratch;
    size_t chunksize;
    do {
        /* Read file in chunks into the scratch buffer */
        int rdlen = k210_file_read(fdd, (void *)chunk, SCRATCH_BUFSIZE);
        if (rdlen < 0) chunksize = 0;
        else chunksize = rdlen;

        /* Send the buffer contents as HTTP response chunk */
        esp_err_t ret = httpd_resp_send_chunk(req, chunk, chunksize);
        if (ret != ESP_OK) {
            k210_file_close(fdd);
            if (debug_log >= 1) ESP_LOGW(TAG, "File sending failed (size=%d, err=%d)!", chunksize, ret);
            /* Abort sending file */
            httpd_resp_sendstr_chunk(req, NULL);
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Greška pri slanju datoteke");
            return ESP_FAIL;
        }

        /* Keep looping till the whole file is sent */
    } while (chunksize != 0);

    /* Close file after sending complete */
    k210_file_close(fdd);
    if (debug_log >= 1) ESP_LOGI(TAG, "File sending complete");

    /* Respond with an empty chunk to signal HTTP response completion */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

//-------------------------------------------------
static void reloc(httpd_req_t *req, char *filepath)
{
    char *reloc = filepath;
    const char *base_path = ((struct file_server_data *)req->user_ctx)->base_path;
    int base_path_len = strlen(base_path);
    for (int i=strlen(filepath)-1; i >= 0; i--) {
        if (filepath[i] == '/') {
            filepath[i+1] = '\0';
            break;
        }
    }
    if (strstr(filepath, base_path) == filepath) {
        reloc += base_path_len;
    }
    if (debug_log >= 1) ESP_LOGI(TAG, "Relocate to '%s'", reloc);

    /* Refresh to see the updated file list */
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", reloc);
    httpd_resp_sendstr(req, "Datoteka prenesena uspješno");
}

/* Handler to upload a file onto the server */
//----------------------------------------------------
static esp_err_t upload_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    k210_fstat_t fstat;
    int fres = -1;
    int fdd = -1;

    /* Skip leading "/upload" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri + sizeof("/upload") - 1, sizeof(filepath));

    if (debug_log >= 1) ESP_LOGI(TAG, "Upload request: file '%s' ('%s').", filename, filepath);
    if (!filename) {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Ime datoteke predugo");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/') {
        if (debug_log >= 1) ESP_LOGE(TAG, "Invalid filename : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Nepravilno ime datoteke");
        return ESP_FAIL;
    }

    fres = k210_file_stat(filepath, &fstat);
    if (fres == 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "File already exists : %s", filepath);
        /* Respond with 400 Bad Request */
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Datoteka već postoji");
        return ESP_FAIL;
    }

    /* File cannot be larger than a limit */
    if (req->content_len > MAX_FILE_SIZE) {
        if (debug_log >= 1) ESP_LOGE(TAG, "File too large : %d bytes", req->content_len);
        /* Respond with 400 Bad Request */
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Veličina datoteke mora biti manja od "
                            MAX_FILE_SIZE_STR "!");
        /* Return failure to close underlying connection else the
         * incoming file content will keep the socket busy */
        return ESP_FAIL;
    }

    if (debug_log >= 1) ESP_LOGI(TAG, "Open file '%s' for writing.", filepath);
    fdd = k210_file_open(filepath, ESP_FILE_MODE_WR);
    if (fdd < 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to create file : %s (%d)", filepath, fdd);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Greška pri stvaranju datoteke");
        return ESP_FAIL;
    }

    if (debug_log >= 1) ESP_LOGI(TAG, "Receiving file : %s...", filename);

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char *buf = ((struct file_server_data *)req->user_ctx)->scratch;
    int received, written;

    /* Content length of the request gives
     * the size of the file being uploaded */
    int remaining = req->content_len;

    while (remaining > 0) {
        if (debug_log >= 1) ESP_LOGI(TAG, "Remaining size : %d", remaining);
        /* Receive the file part by part into a buffer */
        if ((received = httpd_req_recv(req, buf, MIN(remaining, SCRATCH_BUFSIZE))) <= 0) {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry if timeout occurred */
                continue;
            }

            /* In case of unrecoverable error,
             * close and delete the unfinished file*/
            k210_file_close(fdd);

            if (debug_log >= 1) ESP_LOGE(TAG, "File reception failed!");
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Greška u prijemu datoteke");
            return ESP_FAIL;
        }

        /* Write buffer content to file on storage */
        written = k210_file_write(fdd, buf, received);
        if (received && (received != written)) {
            /* Couldn't write everything to file!
             * Storage may be full? */
            k210_file_close(fdd);

            if (debug_log >= 1) ESP_LOGE(TAG, "File write failed (%d)!", written);
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Greška pri spremanju datotekee");
            return ESP_FAIL;
        }

        /* Keep track of remaining size of
         * the file left to be uploaded */
        remaining -= received;
    }

    /* Close file upon upload completion */
    k210_file_close(fdd);
    if (debug_log >= 1) ESP_LOGI(TAG, "File reception complete");

    reloc(req, filepath);
    return ESP_OK;
}

/* URI handler for making new directory on server */
static esp_err_t newdir_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    struct stat file_stat;

    /* Skip leading "/upload" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri + sizeof("/upload") - 1, sizeof(filepath));

    if (debug_log >= 1) ESP_LOGI(TAG, "Make dir request: dir '%s' ('%s').", filename, filepath);
    if (!filename) {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Ime mape predugo");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/') {
        if (debug_log >= 1) ESP_LOGE(TAG, "Invalid dirname : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Nepravilno ime mape");
        return ESP_FAIL;
    }

    if (stat(filepath, &file_stat) == 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Dir already exists : %s", filepath);
        /* Respond with 400 Bad Request */
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Mapa ili datoteka istog imena već postoji");
        return ESP_FAIL;
    }

    if (debug_log >= 1) ESP_LOGI(TAG, "Make dir '%s'", filepath);
    int res = mkdir(filepath, 0775);
    if (res < 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to create directory: %d", errno);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Greška pri stvaranju mape");
        return ESP_FAIL;
    }

    reloc(req, filepath);
    return ESP_OK;
}

/* Handler to delete a file from the server */
//----------------------------------------------------
static esp_err_t delete_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    int res;
    k210_fstat_t fstat;
    int fres = -1;
    uint32_t fmode = 0;

    /* Skip leading "/delete" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri  + sizeof("/delete") - 1, sizeof(filepath));
    if (!filename) {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Ime datoteke predugo");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/') {
        if (debug_log >= 1) ESP_LOGE(TAG, "Invalid filename : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Nepravilno ime datoteke");
        return ESP_FAIL;
    }

    fres = k210_file_stat(filepath, &fstat);
    if (fres >= 0) fmode = fstat.mode;
    if (fres < 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "File does not exist : %s", filename);
        /* Respond with 400 Bad Request */
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Datoteka ne postoji");
        return ESP_FAIL;
    }

    if (fmode & S_IFDIR) {
        if (debug_log >= 1) ESP_LOGI(TAG, "Deleting directory : '%s' ('%s')", filename, filepath);
        /* Remove directory */
        res = k210_file_rmdir(filepath);
    }
    else {
        if (debug_log >= 1) ESP_LOGI(TAG, "Deleting file : '%s' ('%s')", filename, filepath);
        /* Delete file */
        res = k210_file_remove(filepath);
    }
    if (res != 0) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to delete file or directory: %d", errno);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Greška pri brisanju datoteke ili  mape");
        return ESP_FAIL;
    }

    reloc(req, filepath);
    return ESP_OK;
}

/* Function to start the file server */
//------------------------------------------------
esp_err_t start_file_server(const char *base_path)
{
    static struct file_server_data *server_data = NULL;

    /* Validate file storage base path */
    /*if ((strlen(base_path) != 0) && (strcmp(base_path, "/spiffs") != 0)) {
        if (debug_log >= 1) ESP_LOGE(TAG, "File server presently supports only '/spiffs' or '' as base path");
        return ESP_ERR_INVALID_ARG;
    }*/

    if (server_data) {
        if (debug_log >= 1) ESP_LOGE(TAG, "File server already started");
        return ESP_ERR_INVALID_STATE;
    }

    /* Allocate memory for server data */
    server_data = calloc(1, sizeof(struct file_server_data));
    if (!server_data) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to allocate memory for server data");
        return ESP_ERR_NO_MEM;
    }
    if (strlen(base_path) != 0) strlcpy(server_data->base_path, base_path, sizeof(server_data->base_path));

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    /* Use the URI wildcard matching function in order to
     * allow the same handler to respond to multiple different
     * target URIs which match the wildcard scheme */
    config.uri_match_fn = httpd_uri_match_wildcard;

    if (debug_log >= 1) ESP_LOGI(TAG, "Starting HTTP Server");
    if (httpd_start(&server, &config) != ESP_OK) {
        if (debug_log >= 1) ESP_LOGE(TAG, "Failed to start file server!");
        return ESP_FAIL;
    }

    /* URI handler for getting uploaded files */
    httpd_uri_t file_download = {
        .uri       = "/*",  // Match all URIs of type /path/to/file
        .method    = HTTP_GET,
        .handler   = download_get_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &file_download);

    /* URI handler for uploading files to server */
    httpd_uri_t file_upload = {
        .uri       = "/upload/*",   // Match all URIs of type /upload/path/to/file
        .method    = HTTP_POST,
        .handler   = upload_post_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &file_upload);

    /* URI handler for making new directory on server */
    httpd_uri_t dir_create = {
        .uri       = "/newdir/*",   // Match all URIs of type /upload/path/to/file
        .method    = HTTP_POST,
        .handler   = newdir_post_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &dir_create);

    /* URI handler for deleting files from server */
    httpd_uri_t file_delete = {
        .uri       = "/delete/*",   // Match all URIs of type /delete/path/to/file
        .method    = HTTP_POST,
        .handler   = delete_post_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &file_delete);

    return ESP_OK;
}

/* Function to start the file server */
esp_err_t stop_file_server(void)
{
    esp_err_t ret = ESP_OK;
    if (server) ret = httpd_stop(server);
    server = NULL;
    return ret;
}
