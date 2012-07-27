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

#include <inttypes.h>

#include "msidb-error.h"

typedef struct _MsidbStorage MsidbStorage;

typedef struct _MsidbStream MsidbStream;

MsidbStorage* msidb_storage_open_file(const char *filename, const char *mode, MsidbError *err);

void msidb_storage_ref(MsidbStorage *storage);

void msidb_storage_unref(MsidbStorage *storage);

void msidb_storage_close(MsidbStorage *storage, MsidbError *err);

void msidb_storage_flush(MsidbStorage *storage, MsidbError *err);

typedef struct _msidb_stat {
    char name[96];
    int is_dir;
    uint64_t stream_size;
    char clsid[16];
    uint32_t state_bits;
    uint64_t ctime; /* Equivalent of a Windows FILETIME */
    uint64_t mtime; /* Equivalent of a Windows FILETIME */
} msidb_stat_t;

#define MSIDB_MODIFY_NAME           0x00000001
#define MSIDB_MODIFY_STREAM_SIZE    0x00000002
#define MSIDB_MODIFY_CLSID          0x00000004
#define MSIDB_MODIFY_STATE_BITS     0x00000008
#define MSIDB_MODIFY_CTIME          0x00000010
#define MSIDB_MODIFY_MTIME          0x00000020

#if 0 /* Not yet implemented */
int msidb_storage_stat(MsidbStorage *storage, msidb_stat_t *stat, MsidbError *err);
#endif

void msidb_storage_stat_item(MsidbStorage *storage, const char *name, msidb_stat_t *stat, int *found, MsidbError *err);

#if 0 /* Not yet implemented */
int msidb_storage_modify(MsidbStorage *storage, uint32_t modify_flags, const msidb_stat_t *stat, MsidbError *err);

int msidb_storage_modify_item(MsidbStorage *storage, const char *name, uint32_t modify_flags, const msidb_stat_t *stat, MsidbError *err);
#endif

/* Return non-zero to stop enumeration. */
typedef int (*msidb_storage_enum_children_proc)(MsidbStorage *storage,
    const msidb_stat_t *stat, void *user_data);

int msidb_storage_enum_children(MsidbStorage *storage,
    msidb_storage_enum_children_proc enum_func, void *user_data, MsidbError *err);

#if 0 /* Not yet implemented */
MsidbStorage* msidb_storage_open_subdir(MsidbStorage *parent, const char *name, MsidbError *err);

MsidbStream* msidb_storage_open_substream(MsidbStorage *parent, const char *name, MsidbError *err);

int msidb_storage_delete_item(MsidbStorage *storage, const char *name, MsidbError *err);

void msidb_stream_ref(MsidbStream *stream);

void msidb_stream_unref(MsidbStream *stream);

int msidb_stream_readat(MsidbStream *stream, uint64_t offset, void *buf, size_t count, MsidbError *err);

int msidb_stream_writeat(MsidbStream *stream, uint64_t offset, const void *buf, size_t count, MsidbError *err);

int msidb_stream_stat(MsidbStream *stream, msidb_stat_t *result, MsidbError *err);

int msidb_stream_modify(MsidbStream *storage, uint32_t modify_flags, const msidb_stat_t *stat, MsidbError *err);

int msidb_stream_flush(MsidbStream *stream, MsidbError *err);
#endif

