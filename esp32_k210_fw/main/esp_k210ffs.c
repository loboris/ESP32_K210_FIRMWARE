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

// -------------------------------------------------
// Modified by LoBo to include the directory support
// -------------------------------------------------

#include "global.h"

#include <unistd.h>
#include <dirent.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include "esp_vfs.h"
#include "esp_err.h"


//----------------------------------------------------------------------------
static int vfs_k210ffs_open(const char * path, int flags, int mode)
{
    if (path == NULL) return -1;
    int fd = k210_file_open(path, flags);
    if (fd < 0) {
        errno = K210_errno;
        K210_errno = 0;
        return -1;
    }
    return fd;
}

//----------------------------------------------------------------------
static ssize_t vfs_k210ffs_write(int fd, const void * data, size_t size)
{
    ssize_t res = k210_file_write(fd, (void *)data, size);
    if (res < 0) {
        errno = K210_errno;
        K210_errno = 0;
        return -1;
    }
    return res;
}

//--------------------------------------------------------------
static ssize_t vfs_k210ffs_read(int fd, void * dst, size_t size)
{
    ESP_LOGI(SPI_TAG, "k210ffs: File read: %d, %d", fd, size);
    vTaskDelay(50);
    ssize_t res = k210_file_read(fd, dst, size);
    if (res < 0) {
        errno = K210_errno;
        K210_errno = 0;
        return -1;
    }
    return res;
}

//---------------------------------------------
static int vfs_k210ffs_close(int fd)
{
    int res = k210_file_close(fd);
    if (res < 0) {
        errno = K210_errno;
        K210_errno = 0;
        return -1;
    }
    return res;
}

//-----------------------------------------------------------------------
static off_t vfs_k210ffs_lseek(int fd, off_t offset, int mode)
{
    errno = ENOTSUP;
    return -1;
/*
    off_t res = k210_file_lseek(fd, offset, mode);
    if (res < 0) {
        errno = K210_errno;
        K210_errno = 0;
        return -1;
    }
    return res;
*/
}

//--------------------------------------------------------------
static int vfs_k210ffs_fstat(int fd, struct stat *st)
{
    if (st == NULL) return -1;
    int res = k210_file_fstat(fd, st);
    if (res < 0) {
        errno = K210_errno;
        K210_errno = 0;
        return -1;
    }
    return res;
}

//-----------------------------------------------------------------------
static int vfs_k210ffs_stat(const char *path, struct stat *st)
{
    if ((path == NULL) || (st == NULL))  return -1;

    int res = k210_file_stat(path, st);
    if (res < 0) {
        errno = K210_errno;
        K210_errno = 0;
        return -1;
    }

    return res;
}

static int vfs_k210ffs_rename(const char *src, const char *dst)
{
    errno = ENOTSUP;
    return -1;
}

static int vfs_k210ffs_unlink(const char *path)
{
    errno = ENOTSUP;
    return -1;
}

static DIR* vfs_k210ffs_opendir(const char* name)
{
    errno = ENOTSUP;
    return NULL;
}

static int vfs_k210ffs_closedir(DIR* pdir)
{
    errno = ENOTSUP;
    return -1;
}

static struct dirent* vfs_k210ffs_readdir(DIR* pdir)
{
    return NULL;
}

static int vfs_k210ffs_readdir_r(DIR* pdir, struct dirent* entry,
                                struct dirent** out_dirent)
{
    errno = ENOTSUP;
    return -1;
}

static long vfs_k210ffs_telldir(DIR* pdir)
{
    return 0;
}

static void vfs_k210ffs_seekdir(DIR* pdir, long offset)
{
}

static int vfs_k210ffs_mkdir(const char* name, mode_t mode)
{
    errno = ENOTSUP;
    return -1;
}

static int vfs_k210ffs_rmdir(const char* name)
{
    errno = ENOTSUP;
    return -1;
}

//--------------------------------------------------------------------
static int vfs_k210ffs_link(const char* n1, const char* n2)
{
    errno = ENOTSUP;
    return -1;
}


//==================================
esp_err_t esp_vfs_k210ffs_register()
{
    const esp_vfs_t vfs = {
        .flags = ESP_VFS_FLAG_DEFAULT,
        .write = &vfs_k210ffs_write,
        .read = &vfs_k210ffs_read,
        .lseek = &vfs_k210ffs_lseek,
        .open = &vfs_k210ffs_open,
        .close = &vfs_k210ffs_close,
        .fstat = &vfs_k210ffs_fstat,
        .stat = &vfs_k210ffs_stat,
        .link = &vfs_k210ffs_link,
        .unlink = &vfs_k210ffs_unlink,
        .rename = &vfs_k210ffs_rename,
        .opendir = &vfs_k210ffs_opendir,
        .closedir = &vfs_k210ffs_closedir,
        .readdir = &vfs_k210ffs_readdir,
        .readdir_r = &vfs_k210ffs_readdir_r,
        .seekdir = &vfs_k210ffs_seekdir,
        .telldir = &vfs_k210ffs_telldir,
        .mkdir = &vfs_k210ffs_mkdir,
        .rmdir = &vfs_k210ffs_rmdir
    };

    esp_err_t err = esp_vfs_register(K210VFS_BASE_PATH, &vfs, NULL);

    return err;
}

//====================================
esp_err_t esp_vfs_k210ffs_unregister()
{
    esp_err_t err = esp_vfs_unregister(K210VFS_BASE_PATH);
    return err;
}

