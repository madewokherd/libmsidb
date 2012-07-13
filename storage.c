/*
    Copyright 2012 Vincent Povirk

    This file is part of libmsidb.

    libmsidb is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libmsidb is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libmsidb.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <assert.h>

#include "storage.h"

typedef struct _CachedSegment {
    char *data;
    unsigned int sector;
} CachedSegment;

typedef struct _CachedStream {
    CachedSegment *segments;
    unsigned int segments_len;
    unsigned int segments_size;
} CachedStream;

typedef struct _RootStorage {
    int fd;
    char header[512];
    int sector_size;
    CachedStream difat;
} RootStorage;

#define HEADER_OFS_MAGIC 0
#define HEADER_OFS_CLSID 8
#define HEADER_OFS_MINOR_VERSION 24
#define HEADER_OFS_MAJOR_VERSION 26
#define HEADER_OFS_BYTE_ORDER 28
#define HEADER_OFS_SECTOR_SHIFT 30
#define HEADER_OFS_MINI_SECTOR_SHIFT 32
#define HEADER_OFS_DIR_SECTOR_COUNT 40
#define HEADER_OFS_FAT_SECTOR_COUNT 44
#define HEADER_OFS_FIRST_DIR_SECTOR 48
#define HEADER_OFS_TRANSACTION_SIGNATURE 52
#define HEADER_OFS_MINI_STREAM_CUTOFF 56
#define HEADER_OFS_FIRST_MINIFAT_SECTOR 60
#define HEADER_OFS_MINIFAT_SECTOR_COUNT 64
#define HEADER_OFS_FIRST_DIFAT_SECTOR 68
#define HEADER_OFS_DIFAT_SECTOR_COUNT 72
#define HEADER_OFS_DIFAT_START 76

#define MAXREGSECT 0xfffffffa
#define DIFSECT 0xfffffffc
#define FATSECT 0xfffffffd
#define ENDOFCHAIN 0xfffffffe
#define FREESECT 0xffffffff

const char header_magic[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};

struct _MsidbStorage {
    MsidbStorage *parent;
    RootStorage *root;
    unsigned int dir_root;
    unsigned int ref;
    unsigned int sector_size;
};

static int msidb_storage_readat(RootStorage *root, uint64_t offset, void *buf, size_t count, MsidbError *err)
{
    size_t total_bytes_read=0;
    if (root->fd == -1)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "MsidbStorage used after msidb_storage_close was called");
        return -1;
    }
    if (lseek64(root->fd, offset, SEEK_SET) < 0)
    {
        msidb_set_os_error(err, NULL);
        return -1;
    }
    while (count > 0)
    {
        ssize_t bytes_read = read(root->fd, buf, count);
        if (bytes_read < 0)
        {
            msidb_set_os_error(err, NULL);
            return -1;
        }
        total_bytes_read += bytes_read;
        count -= bytes_read;
        buf = ((char*)buf) + bytes_read;
    }
    return total_bytes_read;
}

static uint32_t read_uint32(RootStorage *root, void *data)
{
    return le32toh(*(uint32_t*)data);
}

static uint64_t sector_offset(RootStorage *root, unsigned int sector)
{
    assert(sector < MAXREGSECT);
    return ((uint64_t)sector + 1) * root->sector_size;
}

static char* alloc_and_read_sector(RootStorage *root, unsigned int sector, MsidbError *err)
{
    char *result;
    int bytesread;

    result = malloc(root->sector_size);
    if (!result)
    {
        msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
        return NULL;
    }

    bytesread = msidb_storage_readat(root, sector_offset(root, sector), result, root->sector_size, err);
    if (bytesread > -1 && bytesread < root->sector_size)
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "sector reference past end of file");

    if (!msidb_check_error(err))
    {
        free(result);
        return NULL;
    }

    return result;
}

static void msidb_storage_open(MsidbStorage *storage, MsidbError *err)
{
    int bytesread, i;
    unsigned int sector;

    bytesread = msidb_storage_readat(storage->root, 0, &storage->root->header, 512, err);

    if (bytesread < 0)
        msidb_set_os_error(err, NULL);
    else if (bytesread < 512)
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "file is too small");

    if (msidb_check_error(err))
    {
        if (memcmp(&storage->root->header[HEADER_OFS_MAGIC], header_magic, 8))
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "bad magic number");
    }

    if (msidb_check_error(err))
    {
        storage->root->sector_size = 1 << read_uint32(storage->root, &storage->root->header[HEADER_OFS_SECTOR_SHIFT]);

        /* read DIFAT */
        storage->root->difat.segments_len = read_uint32(storage->root, &storage->root->header[HEADER_OFS_DIFAT_SECTOR_COUNT]);

        storage->root->difat.segments = malloc(sizeof(*storage->root->difat.segments) * storage->root->difat.segments_len);
        if (!storage->root->difat.segments)
        {
            msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
            return;
        }

        memset(storage->root->difat.segments, 0, sizeof(*storage->root->difat.segments) * storage->root->difat.segments_len);

        storage->root->difat.segments_size = storage->root->difat.segments_len;

        sector = read_uint32(storage->root, &storage->root->header[HEADER_OFS_FIRST_DIFAT_SECTOR]);
        for (i=0; i < storage->root->difat.segments_len; i++)
        {
            if (sector > MAXREGSECT)
            {
                msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "DIFAT is smaller than header claims");
                return;
            }
            storage->root->difat.segments[i].sector = sector;
            storage->root->difat.segments[i].data = alloc_and_read_sector(storage->root, sector, err);
            if (!msidb_check_error(err))
                return;

            sector = read_uint32(storage->root, &storage->root->difat.segments[i].data[storage->root->sector_size-4]);
        }

        if (sector <= MAXREGSECT)
        {
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "DIFAT is larger than header claims");
            return;
        }
    }
}

void msidb_storage_ref(MsidbStorage *storage)
{
    storage->ref++;
}

void msidb_storage_flush(MsidbStorage *storage, MsidbError *err)
{
    /* Nothing to do. */
    return;
}

void msidb_storage_close(MsidbStorage *storage, MsidbError *err)
{
    if (storage->parent)
        return;
    if (storage->root->fd != -1)
    {
        msidb_storage_flush(storage, err);
        if (close(storage->root->fd) == -1 && msidb_check_error(err))
            msidb_set_os_error(err, NULL);
        storage->root->fd = -1;
    }
}

static void free_cached_stream(CachedStream *cached_stream)
{
    unsigned int i;
    if (cached_stream->segments)
    {
        for (i=0; i<cached_stream->segments_len; i++)
            free(cached_stream->segments[i].data);
        free(cached_stream->segments);
    }
}

static void msidb_storage_free(MsidbStorage *storage)
{
    if (storage->parent)
    {
        msidb_storage_unref(storage->parent);
    }
    else
    {
        if (storage->root->fd != -1)
            close(storage->root->fd);
        free_cached_stream(&storage->root->difat);
        free(storage->root);
        free(storage);
    }
}

void msidb_storage_unref(MsidbStorage *storage)
{
    if (--storage->ref == 0)
    {
        msidb_storage_close(storage, NULL);
        msidb_storage_free(storage);
    }
}

MsidbStorage* msidb_storage_open_file(const char *filename, const char *mode, MsidbError *err)
{
    if (strcmp(mode, "r") == 0)
    {
        MsidbStorage *result;
        result = malloc(sizeof(*result));
        if (!result)
        {
            msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
            return NULL;
        }
        result->parent = NULL;
        result->dir_root = 0;
        result->ref = 1;
        result->root = malloc(sizeof(*result->root));
        if (!result->root)
        {
            msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
            free(result);
            return NULL;
        }
        memset(result->root, 0, sizeof(*result->root));

        result->root->fd = open(filename, O_RDONLY);
        if (result->root->fd == -1)
            msidb_set_os_error(err, filename);

        if (msidb_check_error(err))
            msidb_storage_open(result, err);

        if (!msidb_check_error(err))
        {
            msidb_storage_free(result);
            result = NULL;
        }

        return result;
    }
    else
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "Invalid mode passed to msidb_storage_open_file");
        return NULL;
    }
}

