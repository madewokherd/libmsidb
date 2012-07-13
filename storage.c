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
    uint32_t sector;
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
    int fat_sector_length;
    CachedStream difat;
    CachedStream dir;
    char cached_fat_sector_data[8192];
    uint32_t cached_fat_sector[16];
    int cached_fat_sector_to_evict;
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

#define DIRENT_OFS_NAME 0
#define DIRENT_OFS_NAME_LENGTH 64
#define DIRENT_OFS_TYPE 66
#define DIRENT_OFS_COLOR 67
#define DIRENT_OFS_LEFT_SIBLING 68
#define DIRENT_OFS_RIGHT_SIBLING 72
#define DIRENT_OFS_CHILD 76
#define DIRENT_OFS_CLSID 80
#define DIRENT_OFS_STATE 96
#define DIRENT_OFS_CTIME 100
#define DIRENT_OFS_MTIME 108
#define DIRENT_OFS_FIRST_SECTOR 116
#define DIRENT_OFS_SIZE 120

#define DIRENT_SIZE 128

#define MAXREGSECT 0xfffffffa
#define INVALIDSECT 0xfffffffb
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

static uint64_t read_uint64(RootStorage *root, const void *data)
{
    return le64toh(*(uint64_t*)data);
}

static uint32_t read_uint32(RootStorage *root, const void *data)
{
    return le32toh(*(uint32_t*)data);
}

static uint16_t read_uint16(RootStorage *root, const void *data)
{
    return le16toh(*(uint16_t*)data);
}

static uint64_t sector_offset(RootStorage *root, unsigned int sector)
{
    assert(sector <= MAXREGSECT);
    return ((uint64_t)sector + 1) * root->sector_size;
}

static char* get_cached_fat_sector(RootStorage *root, unsigned int sector, MsidbError *err)
{
    int cache_size = sizeof(root->cached_fat_sector_data) / root->sector_size;
    int i;
    int bytesread;
    char *result;

    for (i=0; i<cache_size; i++)
    {
        if (root->cached_fat_sector[i] == sector)
            return &root->cached_fat_sector_data[i*root->sector_size];
    }

    result = &root->cached_fat_sector_data[root->sector_size * root->cached_fat_sector_to_evict];

    bytesread = msidb_storage_readat(root, sector_offset(root, sector), result, root->sector_size, err);

    if (bytesread == root->sector_size)
    {
        root->cached_fat_sector[root->cached_fat_sector_to_evict] = sector;
        root->cached_fat_sector_to_evict = (root->cached_fat_sector_to_evict+1) % cache_size;
        return result;
    }
    else
    {
        if (bytesread > -1)
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "sector reference past end of file");
        root->cached_fat_sector[root->cached_fat_sector_to_evict] = FREESECT;
        return NULL;
    }
}

static uint32_t sector_get_next(RootStorage *root, unsigned int sector, MsidbError *err)
{
    uint32_t difat_sector, fat_sector;
    char *fat_block;

    fat_sector = sector / root->fat_sector_length;

    if (fat_sector < 109)
    {
        /* beginning of difat is stored in header */
        fat_sector = read_uint32(root, &root->header[HEADER_OFS_DIFAT_START+4*fat_sector]);
    }
    else
    {
        fat_sector -= 109;
        difat_sector = fat_sector / (root->fat_sector_length-1);
        if (difat_sector >= root->difat.segments_len)
        {
            return FREESECT;
        }
        else
            fat_sector = read_uint32(root, &root->difat.segments[difat_sector].data[4*(fat_sector % (root->fat_sector_length-1))]);
    }

    if (fat_sector == FREESECT)
    {
        return FREESECT;
    }

    fat_block = get_cached_fat_sector(root, fat_sector, err);

    if (!msidb_check_error(err))
    {
        return INVALIDSECT;
    }
    else
    {
        return read_uint32(root, &fat_block[(sector % root->fat_sector_length) * 4]);
    }
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

static uint32_t stream_index_to_sector(RootStorage *root, CachedStream *stream,
    uint32_t index, int expand, MsidbError *err)
{
    assert(!expand); /* not implemented yet */

    if (index >= stream->segments_size)
    {
        unsigned int new_size;
        CachedSegment *new_segments;

        assert(stream->segments_size >= 1);

        if (index+1 > stream->segments_size*2)
            new_size = index+1;
        else
            new_size = stream->segments_size*2;
        new_segments = malloc(sizeof(*new_segments) * new_size);

        if (!new_segments)
        {
            msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
            return FREESECT;
        }

        memcpy(new_segments, stream->segments, sizeof(*new_segments) * stream->segments_len);
        free(stream->segments);
        stream->segments = new_segments;
        stream->segments_size = new_size;
    }

    while (index >= stream->segments_len)
    {
        stream->segments[stream->segments_len].sector = sector_get_next(root,
            stream->segments[stream->segments_len-1].sector, err);
        if (stream->segments[stream->segments_len].sector > MAXREGSECT)
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "invalid sector reference");
        if (!msidb_check_error(err))
            return FREESECT;
        stream->segments[stream->segments_len].data = NULL;
        stream->segments_len++;
    }

    return stream->segments[index].sector;
}

static char* get_stream_data(RootStorage *root, CachedStream *stream,
    uint32_t index, int expand, MsidbError *err)
{
    uint32_t sector;

    sector = stream_index_to_sector(root, stream, index, expand, err);

    if (!msidb_check_error(err))
        return NULL;

    if (!stream->segments[index].data)
        stream->segments[index].data = alloc_and_read_sector(root, sector, err);

    return stream->segments[index].data;
}

static char* get_dir_entry(RootStorage *root, uint32_t sid, int expand, MsidbError *err)
{
    char *block;

    assert(sid <= MAXREGSECT);

    block = get_stream_data(root, &root->dir, sid / (root->sector_size / DIRENT_SIZE), expand, err);

    if (!block)
        return NULL;

    return block + DIRENT_SIZE * (sid % (root->sector_size / DIRENT_SIZE));
}

static void msidb_storage_open(MsidbStorage *storage, MsidbError *err)
{
    int bytesread, i;
    unsigned int sector;

    bytesread = msidb_storage_readat(storage->root, 0, &storage->root->header, 512, err);

    if (bytesread < 0)
    {
        msidb_set_os_error(err, NULL);
        return;
    }
    else if (bytesread < 512)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "file is too small");
        return;
    }

    if (memcmp(&storage->root->header[HEADER_OFS_MAGIC], header_magic, 8))
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "bad magic number");
        return;
    }

    storage->root->sector_size = 1 << read_uint32(storage->root, &storage->root->header[HEADER_OFS_SECTOR_SHIFT]);
    storage->root->fat_sector_length = storage->root->sector_size/4;

    if (storage->root->sector_size > 4096 || storage->root->sector_size < 512)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "bad sector shift");
        return;
    }

    memset(storage->root->cached_fat_sector, 0xff, sizeof(storage->root->cached_fat_sector));

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

    /* read DIR */
    if (storage->root->sector_size == 512)
        storage->root->dir.segments_size = 16;
    else
    {
        storage->root->dir.segments_size = read_uint32(storage->root, &storage->root->header[HEADER_OFS_DIR_SECTOR_COUNT]);

        if (!storage->root->dir.segments_size)
        {
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "header claims no DIR segments");
            return;
        }
    }

    storage->root->dir.segments = malloc(sizeof(*storage->root->dir.segments) * storage->root->dir.segments_size);
    if (!storage->root->dir.segments)
    {
        msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
        return;
    }

    memset(storage->root->dir.segments, 0, sizeof(*storage->root->dir.segments) * storage->root->dir.segments_size);

    storage->root->dir.segments_len = 1;

    storage->root->dir.segments[0].sector = read_uint32(storage->root, &storage->root->header[HEADER_OFS_FIRST_DIR_SECTOR]);

    storage->dir_root = 0;
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
        free_cached_stream(&storage->root->dir);
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

static int encode_utf8_char(uint16_t c, char *outbuf)
{
    unsigned char *outptr = (unsigned char *) outbuf;
    int base, n;
    
    if (c < 0x80) {
        outptr[0] = c;
        return 1;
    } else if (c < 0x800) {
        base = 192;
        n = 2;
    } else if (c < 0x10000) {
        base = 224;
        n = 3;
    }
    
    switch (n) {
    case 3: outptr[2] = (c & 0x3f) | 0x80; c >>= 6;
    case 2: outptr[1] = (c & 0x3f) | 0x80; c >>= 6;
    case 1: outptr[0] = c | base;
    }

    return n;
}

static void fill_msidb_stat(RootStorage *root, const char *dir_entry, msidb_stat_t *st, MsidbError *err)
{
    int i, j;
    j=0;
    for (i=0; i<64; i+=2)
    {
        j += encode_utf8_char(read_uint16(root, &dir_entry[DIRENT_OFS_NAME+i]), &st->name[j]);
        if (st->name[j-1] == 0)
            break;
    }

    if (i == 64)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "name lacks NULL terminator");
        return;
    }

    st->is_dir = dir_entry[DIRENT_OFS_TYPE] == 2 || dir_entry[DIRENT_OFS_TYPE] == 5;
    st->stream_size = read_uint64(root, &dir_entry[DIRENT_OFS_SIZE]);
    memcpy(&st->clsid, &dir_entry[DIRENT_OFS_CLSID], 16);
    st->state_bits = read_uint32(root, &dir_entry[DIRENT_OFS_STATE]);
    st->ctime = read_uint64(root, &dir_entry[DIRENT_OFS_CTIME]);
    st->mtime = read_uint64(root, &dir_entry[DIRENT_OFS_MTIME]);
}

static int msidb_storage_enum_children_recurse(MsidbStorage *storage,
    uint32_t child, msidb_storage_enum_children_proc enum_func,
    void *user_data, MsidbError *err)
{
    char *dir_entry;
    uint32_t sibling;
    msidb_stat_t st;
    int ret;

    if (child == FREESECT)
        return 0;
    else if (child > MAXREGSECT)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "Invalid reference in dir table");
        return -1;
    }

    dir_entry = get_dir_entry(storage->root, child, 0, err);

    if (!dir_entry)
        return -1;

    sibling = read_uint32(storage->root, &dir_entry[DIRENT_OFS_LEFT_SIBLING]);
    ret = msidb_storage_enum_children_recurse(storage, sibling, enum_func, user_data, err);
    if (ret)
        return ret;

    fill_msidb_stat(storage->root, dir_entry, &st, err);

    if (!msidb_check_error(err))
        return -1;

    ret = enum_func(storage, &st, user_data);
    if (ret)
        return ret;

    sibling = read_uint32(storage->root, &dir_entry[DIRENT_OFS_RIGHT_SIBLING]);
    return msidb_storage_enum_children_recurse(storage, sibling, enum_func, user_data, err);
}

int msidb_storage_enum_children(MsidbStorage *storage,
    msidb_storage_enum_children_proc enum_func, void *user_data, MsidbError *err)
{
    char *root_dir_entry;
    uint32_t child;

    root_dir_entry = get_dir_entry(storage->root, storage->dir_root, 0, err);

    if (!root_dir_entry)
        return -1;

    child = read_uint32(storage->root, &root_dir_entry[DIRENT_OFS_CHILD]);

    return msidb_storage_enum_children_recurse(storage, child, enum_func, user_data, err);
}

