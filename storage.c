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
    int mini_sector_size;
    uint32_t mini_stream_cutoff;
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
    unsigned int ref;
    MsidbStorage *parent;
    RootStorage *root;
    uint32_t dir_root;
    MsidbStream *open_streams;
};

struct _MsidbStream {
    unsigned int ref;
    MsidbStorage *parent;
    uint32_t sid;
    uint64_t stream_size;
    char name[96];
    uint32_t cached_segment;
    uint32_t cached_segment_index;
    char *cached_segment_data;
    int cached_segment_data_valid;
    char *dir_entry;
    /* linked list of open streams in parent */
    MsidbStream **prev;
    MsidbStream *next;
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

static uint64_t sector_offset(RootStorage *root, uint32_t sector)
{
    assert(sector <= MAXREGSECT);
    return ((uint64_t)sector + 1) * root->sector_size;
}

static char* get_cached_fat_sector(RootStorage *root, uint32_t sector, MsidbError *err)
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

static uint32_t sector_get_next(RootStorage *root, uint32_t sector, MsidbError *err)
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

static char* alloc_and_read_sector(RootStorage *root, uint32_t sector, MsidbError *err)
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
    storage->root->mini_sector_size = 1 << read_uint32(storage->root, &storage->root->header[HEADER_OFS_MINI_SECTOR_SHIFT]);
    storage->root->mini_stream_cutoff = read_uint32(storage->root, &storage->root->header[HEADER_OFS_MINI_STREAM_CUTOFF]);

    if (storage->root->sector_size > 4096 || storage->root->sector_size < 512)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "bad sector shift");
        return;
    }

    if (storage->root->mini_sector_size != 64)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "bad mini sector shift");
        return;
    }

    if (storage->root->mini_stream_cutoff != 0x1000)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "bad mini sector shift");
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

    storage->open_streams = NULL;
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
    uint16_t c;
    j=0;
    for (i=0; i<64; i+=2)
    {
        c = read_uint16(root, &dir_entry[DIRENT_OFS_NAME+i]);
        if (c >= 0xd800 && c < 0xe000)
        {
            msidb_set_error(err, MSIDB_ERROR_NOTIMPL, 0, "UTF-16 sequence in stream name");
            return;
        }
        j += encode_utf8_char(c, &st->name[j]);
        if (st->name[j-1] == 0)
            break;
    }

    if (i == 64)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "name lacks NULL terminator");
        return;
    }

    st->is_dir = dir_entry[DIRENT_OFS_TYPE] == 1 || dir_entry[DIRENT_OFS_TYPE] == 5;
    st->stream_size = read_uint64(root, &dir_entry[DIRENT_OFS_SIZE]);
    memcpy(&st->clsid, &dir_entry[DIRENT_OFS_CLSID], 16);
    st->state_bits = read_uint32(root, &dir_entry[DIRENT_OFS_STATE]);
    st->ctime = read_uint64(root, &dir_entry[DIRENT_OFS_CTIME]);
    st->mtime = read_uint64(root, &dir_entry[DIRENT_OFS_MTIME]);
}

static int decode_utf8_char(const char *c, uint16_t *outchar, MsidbError *err)
{
    const unsigned char *inptr = (const unsigned char *) c;
    uint16_t u;
    int n;
    
    u = *inptr;
    
    if (u < 0x80) {
        /* simple ascii case */
        *outchar = u;
        return 1;
    } else if (u < 0xc2) {
        msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "Bad utf8 sequence");
        return -1;
    } else if (u < 0xe0) {
        u &= 0x1f;
        n = 2;
    } else if (u < 0xf0) {
        u &= 0x0f;
        n = 3;
    } else {
        msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "Bad utf8 sequence");
        return -1;
    }

    switch (n) {
    case 3:
        u = (u << 6) | (*++inptr ^ 0x80);
        if ((*inptr & 0xc0) != 0x80)
        {
            msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "Bad utf8 sequence");
            return -1;
        }
    case 2:
        u = (u << 6) | (*++inptr ^ 0x80);
        if ((*inptr & 0xc0) != 0x80)
        {
            msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "Bad utf8 sequence");
            return -1;
        }
    }

    *outchar = u;
    
    return n;
}

static int utf8_name_to_ucs2(const char *name, uint16_t *outbuf, MsidbError *err)
{
    int length=0;
    uint16_t unichr;

    while (*name && length < 31)
    {
        if (*name == '/' || *name == '\\' || *name == ':' || *name == '!')
        {
            msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "Stream or storage name must not contain the characters: /\\:!");
            return -1;
        }
        name += decode_utf8_char(name, &unichr, err);
        if (!msidb_check_error(err))
            return -1;
        if (unichr >= 0xd800 && unichr < 0xe000)
        {
            msidb_set_error(err, MSIDB_ERROR_NOTIMPL, 0, "UTF-16 sequence in stream name");
            return -1;
        }
        outbuf[length] = unichr;
        length++;
    }

    if (length == 32)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "Stream or storage name too long (must be at most 31 characters)");
        return -1;
    }

    outbuf[length] = 0;

    return length;
}

static uint16_t toupper_ucs2(uint16_t c, MsidbError *err)
{
    if (c >= 0x61 && c < 0x7b)
        return c-0x20;

    /* The MS-CFB spec doesn't make it clear exactly how case conversion should
     * be handled. Since names inside a storage file aren't normally exposed to
     * users, this probably doesn't matter. Therefore, for now we fail in any
     * non-ascii case that might involve a conversion */
    if (c < 0x2d26)
    {
        if (c == 0xaa) goto fail;
        if (c == 0xb5) goto fail;
        if (c == 0xba) goto fail;
        if (c < 0xc0) return c;
        if (c < 0xd7) goto fail;
        if (c < 0xd8) return c;
        if (c < 0xf7) goto fail;
        if (c < 0xf8) return c;
        if (c < 0x1bb) goto fail;
        if (c < 0x1bc) return c;
        if (c < 0x1c0) goto fail;
        if (c == 0x1c4) goto fail;
        if (c < 0x1c6) return c;
        if (c < 0x1c8) goto fail;
        if (c < 0x1c9) return c;
        if (c < 0x1cb) goto fail;
        if (c < 0x1cc) return c;
        if (c < 0x1f2) goto fail;
        if (c < 0x1f3) return c;
        if (c < 0x294) goto fail;
        if (c < 0x295) return c;
        if (c < 0x2b0) goto fail;
        if (c < 0x370) return c;
        if (c < 0x374) goto fail;
        if (c < 0x376) return c;
        if (c < 0x378) goto fail;
        if (c < 0x37b) return c;
        if (c < 0x37e) goto fail;
        if (c == 0x386) goto fail;
        if (c < 0x388) return c;
        if (c < 0x38b) goto fail;
        if (c == 0x38c) goto fail;
        if (c < 0x38e) return c;
        if (c < 0x3a2) goto fail;
        if (c < 0x3a3) return c;
        if (c < 0x3f6) goto fail;
        if (c < 0x3f7) return c;
        if (c < 0x482) goto fail;
        if (c < 0x48a) return c;
        if (c < 0x524) goto fail;
        if (c < 0x531) return c;
        if (c < 0x557) goto fail;
        if (c < 0x561) return c;
        if (c < 0x588) goto fail;
        if (c < 0x10a0) return c;
        if (c < 0x10c6) goto fail;
        if (c < 0x1d00) return c;
        if (c < 0x1d2c) goto fail;
        if (c < 0x1d62) return c;
        if (c < 0x1d78) goto fail;
        if (c < 0x1d79) return c;
        if (c < 0x1d9b) goto fail;
        if (c < 0x1e00) return c;
        if (c < 0x1f16) goto fail;
        if (c < 0x1f18) return c;
        if (c < 0x1f1e) goto fail;
        if (c < 0x1f20) return c;
        if (c < 0x1f46) goto fail;
        if (c < 0x1f48) return c;
        if (c < 0x1f4e) goto fail;
        if (c < 0x1f50) return c;
        if (c < 0x1f58) goto fail;
        if (c == 0x1f59) goto fail;
        if (c == 0x1f5b) goto fail;
        if (c == 0x1f5d) goto fail;
        if (c < 0x1f5f) return c;
        if (c < 0x1f7e) goto fail;
        if (c < 0x1f80) return c;
        if (c < 0x1f88) goto fail;
        if (c < 0x1f90) return c;
        if (c < 0x1f98) goto fail;
        if (c < 0x1fa0) return c;
        if (c < 0x1fa8) goto fail;
        if (c < 0x1fb0) return c;
        if (c < 0x1fb5) goto fail;
        if (c < 0x1fb6) return c;
        if (c < 0x1fbc) goto fail;
        if (c == 0x1fbe) goto fail;
        if (c < 0x1fc2) return c;
        if (c < 0x1fc5) goto fail;
        if (c < 0x1fc6) return c;
        if (c < 0x1fcc) goto fail;
        if (c < 0x1fd0) return c;
        if (c < 0x1fd4) goto fail;
        if (c < 0x1fd6) return c;
        if (c < 0x1fdc) goto fail;
        if (c < 0x1fe0) return c;
        if (c < 0x1fed) goto fail;
        if (c < 0x1ff2) return c;
        if (c < 0x1ff5) goto fail;
        if (c < 0x1ff6) return c;
        if (c < 0x1ffc) goto fail;
        if (c == 0x2071) goto fail;
        if (c == 0x207f) goto fail;
        if (c == 0x2102) goto fail;
        if (c == 0x2107) goto fail;
        if (c < 0x210a) return c;
        if (c < 0x2114) goto fail;
        if (c == 0x2115) goto fail;
        if (c < 0x2119) return c;
        if (c < 0x211e) goto fail;
        if (c == 0x2124) goto fail;
        if (c == 0x2126) goto fail;
        if (c == 0x2128) goto fail;
        if (c < 0x212a) return c;
        if (c < 0x212e) goto fail;
        if (c < 0x212f) return c;
        if (c < 0x2135) goto fail;
        if (c == 0x2139) goto fail;
        if (c < 0x213c) return c;
        if (c < 0x2140) goto fail;
        if (c < 0x2145) return c;
        if (c < 0x214a) goto fail;
        if (c == 0x214e) goto fail;
        if (c < 0x2183) return c;
        if (c < 0x2185) goto fail;
        if (c < 0x2c00) return c;
        if (c < 0x2c2f) goto fail;
        if (c < 0x2c30) return c;
        if (c < 0x2c5f) goto fail;
        if (c < 0x2c60) return c;
        if (c < 0x2c70) goto fail;
        if (c < 0x2c71) return c;
        if (c < 0x2c7d) goto fail;
        if (c < 0x2c80) return c;
        if (c < 0x2ce5) goto fail;
        if (c < 0x2d00) return c;
        goto fail;
    }
    else
    {
        if (c < 0xa640) return c;
        if (c < 0xa660) goto fail;
        if (c < 0xa662) return c;
        if (c < 0xa66e) goto fail;
        if (c < 0xa680) return c;
        if (c < 0xa698) goto fail;
        if (c < 0xa722) return c;
        if (c < 0xa770) goto fail;
        if (c < 0xa771) return c;
        if (c < 0xa788) goto fail;
        if (c < 0xa78b) return c;
        if (c < 0xa78d) goto fail;
        if (c < 0xfb00) return c;
        if (c < 0xfb07) goto fail;
        if (c < 0xfb13) return c;
        if (c < 0xfb18) goto fail;
        if (c < 0xff21) return c;
        if (c < 0xff3b) goto fail;
        if (c < 0xff41) return c;
        if (c < 0xff5b) goto fail;
        return c;
    }

fail:
    msidb_set_error(err, MSIDB_ERROR_NOTIMPL, 0, "Case mapping for non-ascii characters not implemented");
    return c;
}

static int name_cmp(RootStorage *root, const uint16_t *name1_upper, int length1,
    const char *dir_entry2, MsidbError *err)
{
    int length2, i;
    length2 = read_uint16(root, dir_entry2 + DIRENT_OFS_NAME_LENGTH);

    if ((length1*2+2) != length2)
        return (length1*2+2) - length2;

    for (i=0; i<length1; i++)
    {
        int c = name1_upper[i] - toupper_ucs2(read_uint16(root, dir_entry2 + DIRENT_OFS_NAME + 2 * i), err);
        if (c != 0) return c;
    }

    return 0;
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

enum child_ref {
    REF_LEFT,
    REF_RIGHT,
    REF_DIR
};

static uint32_t msidb_storage_find_child(MsidbStorage *storage, const char *name,
    char **dir_entry, uint32_t *ref_sid, enum child_ref *ref_type, MsidbError *err)
{
    char *read_dir_entry;
    uint32_t sid;
    int length;
    uint16_t normalized_name[32];
    int c, i;

    length = utf8_name_to_ucs2(name, normalized_name, err);
    if (!msidb_check_error(err)) return FREESECT;

    for (i=0; i<length; i++)
        normalized_name[i] = toupper_ucs2(normalized_name[i], err);
    if (!msidb_check_error(err)) return FREESECT;

    if (ref_type) *ref_type = REF_DIR;
    if (ref_sid) *ref_sid = storage->dir_root;
    read_dir_entry = get_dir_entry(storage->root, storage->dir_root, 0, err);
    if (!msidb_check_error(err)) return FREESECT;

    sid = read_uint32(storage->root, &read_dir_entry[DIRENT_OFS_CHILD]);

    while (sid != FREESECT)
    {
        if (sid > MAXREGSECT)
        {
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "Invalid reference in dir table");
            return FREESECT;
        }

        read_dir_entry = get_dir_entry(storage->root, sid, 0, err);
        if (!msidb_check_error(err)) return FREESECT;

        c = name_cmp(storage->root, normalized_name, length, read_dir_entry, err);
        if (!msidb_check_error(err)) return FREESECT;

        if (c == 0)
        {
            if (dir_entry) *dir_entry = read_dir_entry;
            return sid;
        }
        else if (c < 0)
        {
            if (ref_type) *ref_type = REF_LEFT;
            if (ref_sid) *ref_sid = sid;
            sid = read_uint32(storage->root, &read_dir_entry[DIRENT_OFS_LEFT_SIBLING]);
        }
        else if (c > 0)
        {
            if (ref_type) *ref_type = REF_RIGHT;
            if (ref_sid) *ref_sid = sid;
            sid = read_uint32(storage->root, &read_dir_entry[DIRENT_OFS_RIGHT_SIBLING]);
        }
    }

    return FREESECT;
}

void msidb_storage_stat_item(MsidbStorage *storage, const char *name,
    msidb_stat_t *stat, int *found, MsidbError *err)
{
    char *dir_entry;
    uint32_t sid;

    *found = 0;

    sid = msidb_storage_find_child(storage, name, &dir_entry, NULL, NULL, err);

    if (msidb_check_error(err))
    {
        if (sid != FREESECT)
        {
            fill_msidb_stat(storage->root, dir_entry, stat, err);
            if (msidb_check_error(err))
                *found = 1;
        }
    }

    return;
}

void msidb_stream_ref(MsidbStream *stream)
{
    stream->ref++;
}

void msidb_stream_unref(MsidbStream *stream)
{
    if (--stream->ref == 0)
    {
        msidb_storage_unref(stream->parent);
        free(stream->cached_segment_data);
        *stream->prev = stream->next;
        if (stream->next)
            stream->next->prev = stream->prev;
        free(stream);
    }
}

MsidbStream* msidb_storage_open_substream(MsidbStorage *parent,
    const char *name, int *found, MsidbError *err)
{
    char *dir_entry;
    uint32_t sid;
    uint64_t size;
    MsidbStream *result;

    /* Check if the stream is already open. */
    result = parent->open_streams;
    while (result)
    {
        if (!strcmp(result->name, name))
        {
            msidb_stream_ref(result);
            return (result);
        }
        result = result->next;
    }

    sid = msidb_storage_find_child(parent, name, &dir_entry, NULL, NULL, err);
    if (sid == FREESECT || dir_entry[DIRENT_OFS_TYPE] != 2)
    {
        *found = 0;
        return NULL;
    }

    size = read_uint64(parent->root, &dir_entry[DIRENT_OFS_SIZE]);
    if (size < parent->root->mini_stream_cutoff)
    {
        msidb_set_error(err, MSIDB_ERROR_NOTIMPL, 0, "Opening small streams not implemented");
        *found = 0;
        return NULL;
    }

    result = malloc(sizeof(*result));

    result->ref = 1;
    result->parent = parent;
    result->sid = sid;
    result->stream_size = size;
    strcpy(result->name, name);
    result->cached_segment = FREESECT;
    result->cached_segment_index = FREESECT;
    result->cached_segment_data = NULL;
    result->cached_segment_data_valid = 0;
    result->dir_entry = dir_entry;
    result->prev = &parent->open_streams;
    result->next = parent->open_streams;
    if (result->next)
        result->next->prev = &result->next;
    parent->open_streams = result;
    msidb_storage_ref(parent);

    *found = 1;

    return result;
}

size_t msidb_stream_readat(MsidbStream *stream, uint64_t offset, void *buf,
    size_t count, MsidbError *err)
{
    if (offset + count > stream->stream_size)
    {
        if (stream->stream_size <= offset)
            return 0;
        count = stream->stream_size - offset;
    }
    else if (count == 0)
        return 0;

    if (stream->stream_size >= stream->parent->root->mini_stream_cutoff)
    {
        uint32_t index, start_index, end_index;
        char *buf_pos = buf;
        start_index = offset/stream->parent->root->sector_size;
        end_index = (offset+count-1)/stream->parent->root->sector_size;

        if (stream->cached_segment_index > start_index)
        {
            stream->cached_segment_index = 0;
            stream->cached_segment = read_uint32(stream->parent->root, &stream->dir_entry[DIRENT_OFS_FIRST_SECTOR]);
            stream->cached_segment_data_valid = 0;
        }

        while (stream->cached_segment_index < start_index)
        {
            stream->cached_segment_index++;
            stream->cached_segment = sector_get_next(stream->parent->root, stream->cached_segment, err);
            if (!msidb_check_error(err))
                return 0;
            stream->cached_segment_data_valid = 0;
        }

        for (index=start_index; index<=end_index; index++)
        {
            int block_read_start, block_read_end, bytesread;

            if (index == start_index)
                block_read_start = offset % stream->parent->root->sector_size;
            else
                block_read_start = 0;
            if (index == end_index)
                block_read_end = (offset+count-1) % stream->parent->root->sector_size + 1;
            else
                block_read_end = stream->parent->root->sector_size;

            if (stream->cached_segment_data_valid)
            {
                memcpy(buf_pos, stream->cached_segment_data+block_read_start, block_read_end-block_read_start);
                buf_pos += block_read_end-block_read_start;
            }
            else if (index == end_index && (offset+count) % stream->parent->root->sector_size != 0 &&
                     offset+count != stream->stream_size)
            {
                if (!stream->cached_segment_data)
                {
                    stream->cached_segment_data = malloc(stream->parent->root->sector_size);
                    if (!stream->cached_segment_data)
                    {
                        msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
                        return 0;
                    }
                }

                bytesread = msidb_storage_readat(stream->parent->root,
                    sector_offset(stream->parent->root, stream->cached_segment),
                    stream->cached_segment_data, stream->parent->root->sector_size, err);
                if (bytesread > -1 && bytesread != stream->parent->root->sector_size)
                    msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "sector reference past end of file");
                if (!msidb_check_error(err))
                    return 0;

                stream->cached_segment_data_valid = 1;
                memcpy(buf_pos, stream->cached_segment_data+block_read_start, block_read_end-block_read_start);
                buf_pos += bytesread;
            }
            else
            {
                bytesread = msidb_storage_readat(stream->parent->root,
                    sector_offset(stream->parent->root, stream->cached_segment) + block_read_start,
                    buf_pos, block_read_end-block_read_start, err);
                if (bytesread > -1 && bytesread != block_read_end-block_read_start)
                    msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "sector reference past end of file");
                if (!msidb_check_error(err))
                    return 0;
                buf_pos += bytesread;
            }

            if (index != end_index)
            {
                stream->cached_segment_index++;
                stream->cached_segment = sector_get_next(stream->parent->root, stream->cached_segment, err);
                if (!msidb_check_error(err))
                    return 0;
                stream->cached_segment_data_valid = 0;
            }
        }

        return count;
    }
    else
    {
        msidb_set_error(err, MSIDB_ERROR_NOTIMPL, 0, "Opening small streams not implemented");
        return 0;
    }
}

