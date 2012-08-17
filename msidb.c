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

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iconv.h>

#include "msidb.h"
#include "msidb-private.h"

struct known_codepage {
    uint32_t cp_constant;
    const char *cp_name;
};

struct known_codepage known_codepages[] = 
{
    {0, "ASCII"}, /* CP_ACP - Anything non-ascii would depend on the environment. */
    {1, "ASCII"}, /* CP_OEMCP - Anything non-ascii would depend on the environment. */
    {1250, "WINDOWS-1250"},
    {1251, "WINDOWS-1251"},
    {1252, "WINDOWS-1252"},
    {1253, "WINDOWS-1253"},
    {1254, "WINDOWS-1254"},
    {1255, "WINDOWS-1255"},
    {1256, "WINDOWS-1256"},
    {1257, "WINDOWS-1257"},
    {1258, "WINDOWS-1258"},
    {65000, "UTF7"},
    {65001, "UTF8"},
    {}
};

typedef struct _StringTableEntry {
    uint32_t refcount;
    uint32_t len;
    char *data;
} StringTableEntry;

typedef struct _StringTable {
    StringTableEntry *entries;
    size_t entries_size;
    size_t entries_len;
    int strref_size;
    const char *codepage;
} StringTable;

struct _MsidbDatabase {
    unsigned int ref;
    MsidbStorage *storage;
    int shared_storage;
    MsidbStream *stringpool_stream;
    MsidbStream *stringdata_stream;
    StringTable stringtable;
};

static int16_t utf2mime(uint16_t x)
{
    if ((x>='0') && (x<='9'))
        return x-'0';
    if ((x>='A') && (x<='Z'))
        return x-'A'+10;
    if ((x>='a') && (x<='z'))
        return x-'a'+10+26;
    if (x=='.')
        return 10+26+26;
    if (x=='_')
        return 10+26+26+1;
    return -1;
}

static void encode_streamname(char* output, const char* input, int is_table, MsidbError *err)
{
    int chars_encoded=0;
    uint16_t ch, next;

    if (is_table)
    {
        output += encode_utf8_char(0x4840, output);
        chars_encoded++;
    }
    while (chars_encoded < 32)
    {
        input += decode_utf8_char(input, &ch, err);
        if (!msidb_check_error(err))
            return;

        if (!ch)
        {
            *output = 0;
            return;
        }

        if (utf2mime(ch) != -1)
        {
            int next_len;
            next_len = decode_utf8_char(input, &next, err);
            if (!msidb_check_error(err))
                return;
            if (utf2mime(next) != -1)
            {
                ch = 0x3800 + utf2mime(ch) + (utf2mime(next)<<6);
                input += next_len;
            }
            else
                ch = 0x4800 + utf2mime(ch);
        }
        output += encode_utf8_char(ch, output);
        chars_encoded++;
    }
    msidb_set_error(err, MSIDB_ERROR_INVALIDARG, 0, "stream or table name too long");
    return;
}

static MsidbStream* open_stream(MsidbStorage *parent, const char *decoded_name, int is_table, int *found, MsidbError *err)
{
    char encoded_name[96];

    *found = 0;

    encode_streamname(encoded_name, decoded_name, is_table, err);
    if (!msidb_check_error(err))
        return NULL;

    return msidb_storage_open_substream(parent, encoded_name, found, err);
}

static uint32_t read_uint(const void *data, int size)
{
    const unsigned char *d = data;
    uint32_t result = 0;
    int shift = 0;
    while (size)
    {
        result = result | *d << shift;
        d++;
        size--;
        shift+=8;
    }
    return result;
}

static void free_stringtable(StringTable *stringtable)
{
    int i;
    for (i=0; i<stringtable->entries_len; i++)
        free(stringtable->entries[i].data);
    free(stringtable->entries);
}

static void read_stringtable(MsidbStream *stringpool, MsidbStream *stringdata, StringTable *stringtable, MsidbError *err)
{
    msidb_stat_t st;
    uint64_t poolsize, data_offset = 0;
    char pool_entry[4];
    char static_input_buffer[4096];
    char *dyn_input_buffer = NULL;
    char *input_buffer = static_input_buffer;
    size_t input_buffer_size = sizeof(static_input_buffer);
    char static_output_buffer[4096];
    char *dyn_output_buffer = NULL;
    char *output_buffer = static_output_buffer;
    size_t output_buffer_size = sizeof(static_output_buffer);
    size_t bytesread, inbytesleft, outbytesleft;
    char *in, *out;
    uint32_t codepage;
    int i;
    int num_entries = 0;
    iconv_t cd;

    msidb_stream_stat(stringpool, &st, err);
    poolsize = st.stream_size;
    if (!msidb_check_error(err)) return;

    if (poolsize < 4)
    {
        msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "missing _StringPool header");
        return;
    }

    /* read header */
    msidb_stream_readat(stringpool, 0, pool_entry, 4, err);
    if (!msidb_check_error(err)) return;

    codepage = read_uint(pool_entry, 4);

    stringtable->strref_size = (codepage & 0x80000000) ? 3 : 2;

    codepage &= 0x7fffffff;

    for (i=0; known_codepages[i].cp_name; i++)
    {
        if (known_codepages[i].cp_constant == codepage)
        {
            stringtable->codepage = known_codepages[i].cp_name;
            break;
        }
    }

    if (!known_codepages[i].cp_name)
    {
        msidb_set_error(err, MSIDB_ERROR_NOTIMPL, codepage, "unknown codepage constant");
        return;
    }

    num_entries = poolsize / 4;

    stringtable->entries = malloc(num_entries * sizeof(StringTableEntry));

    if (!stringtable->entries)
    {
        msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
        return;
    }

    stringtable->entries_size = stringtable->entries_len = num_entries;

    memset(stringtable->entries, 0, num_entries * sizeof(StringTableEntry));

    cd = iconv_open("UTF8", stringtable->codepage);
    if (cd == (iconv_t)-1)
    {
        free(stringtable->entries);
        msidb_set_os_error(err, "iconv_open() failed when reading string table");
        return;
    }

    for (i=1; i<num_entries; i++)
    {
        msidb_stream_readat(stringpool, 4 * i, pool_entry, 4, err);
        if (!msidb_check_error(err)) break;

        stringtable->entries[i].len = read_uint(pool_entry, 2);
        stringtable->entries[i].refcount = read_uint(pool_entry+2, 2);

        if (!stringtable->entries[i].len)
            /* unused entry or overflow */
            continue;

        if (!stringtable->entries[i-1].len && stringtable->entries[i-1].refcount)
            /* previous entry contains the top bits of this entry's length */
            stringtable->entries[i].len += stringtable->entries[i-1].refcount << 16;

        if (input_buffer_size < stringtable->entries[i].len)
        {
            input_buffer_size = stringtable->entries[i].len * 2;
            free(dyn_input_buffer);
            input_buffer = dyn_input_buffer = malloc(input_buffer_size);
            if (!dyn_input_buffer)
            {
                msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
                break;
            }
        }

        bytesread = msidb_stream_readat(stringdata, data_offset, input_buffer, stringtable->entries[i].len, err);
        if (!msidb_check_error(err)) break;
        if (bytesread != stringtable->entries[i].len)
        {
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "too short _StringData stream");
            break;
        }

        while (1)
        {
            in = input_buffer;
            out = output_buffer;
            inbytesleft = stringtable->entries[i].len;
            outbytesleft = output_buffer_size;

            iconv(cd, NULL, NULL, NULL, NULL);

            if (iconv(cd, &in, &inbytesleft, &out, &outbytesleft) != (size_t)-1)
                break;

            if (errno != E2BIG)
            {
                msidb_set_os_error(err, "iconv() failed when reading string table");
                break;
            }

            output_buffer_size = output_buffer_size + inbytesleft * 3;
            free(dyn_output_buffer);
            output_buffer = dyn_output_buffer = malloc(output_buffer_size);
            if (!dyn_output_buffer)
            {
                msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
                break;
            }
        }

        if (!msidb_check_error(err))
            break;

        data_offset += stringtable->entries[i].len;

        stringtable->entries[i].len = output_buffer_size - outbytesleft;
        stringtable->entries[i].data = malloc(stringtable->entries[i].len + 1);
        if (!stringtable->entries[i].data)
        {
            msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
            break;
        }
        memcpy(stringtable->entries[i].data, output_buffer, stringtable->entries[i].len);
        stringtable->entries[i].data[stringtable->entries[i].len] = 0;
        printf("%s %i\n", stringtable->entries[i].data, stringtable->entries[i].refcount);
    }

    free(dyn_input_buffer);
    free(dyn_output_buffer);
    iconv_close(cd);

    if (!msidb_check_error(err))
        free_stringtable(stringtable);
}

MsidbDatabase* msidb_database_open_storage(MsidbStorage *storage, const char *mode, int shared_storage, MsidbError *err)
{
    MsidbDatabase *result;
    MsidbStream *stringpool, *stringdata;
    StringTable stringtable;
    int found;

    stringpool = open_stream(storage, "_StringPool", 1, &found, err);
    if (!msidb_check_error(err) || !found)
    {
        if (msidb_check_error(err))
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "missing _StringPool table");
        return NULL;
    }

    stringdata = open_stream(storage, "_StringData", 1, &found, err);
    if (!msidb_check_error(err) || !found)
    {
        if (msidb_check_error(err))
            msidb_set_error(err, MSIDB_ERROR_INVALIDDATA, 0, "missing _StringData table");
        msidb_stream_unref(stringpool);
        return NULL;
    }

    read_stringtable(stringpool, stringdata, &stringtable, err);
    if (!msidb_check_error(err))
    {
        msidb_stream_unref(stringpool);
        msidb_stream_unref(stringdata);
        return NULL;
    }

    result = malloc(sizeof(*result));
    if (!result)
    {
        msidb_set_error(err, MSIDB_ERROR_OUTOFMEMORY, 0, NULL);
        msidb_stream_unref(stringpool);
        msidb_stream_unref(stringdata);
        return NULL;
    }

    result->ref = 1;
    result->storage = storage;
    msidb_storage_ref(storage);
    result->shared_storage = shared_storage;
    result->stringpool_stream = stringpool;
    result->stringdata_stream = stringdata;
    result->stringtable = stringtable;

    return result;
}

MsidbDatabase* msidb_database_open_file(const char *filename, const char *mode, MsidbError *err)
{
    MsidbStorage *storage;
    MsidbDatabase *result = NULL;

    storage = msidb_storage_open_file(filename, mode, err);

    if (msidb_check_error(err))
    {
        result = msidb_database_open_storage(storage, mode, 0, err);
    }

    msidb_storage_unref(storage);

    return result;
}

void msidb_database_ref(MsidbDatabase *database)
{
    database->ref++;
}

void msidb_database_close(MsidbDatabase *database, MsidbError *err)
{
    if (!database->shared_storage)
        msidb_storage_close(database->storage, err);
}

void msidb_database_unref(MsidbDatabase *database)
{
    if (--database->ref == 0)
    {
        msidb_database_close(database, NULL);
        msidb_storage_unref(database->storage);
        msidb_stream_unref(database->stringpool_stream);
        msidb_stream_unref(database->stringdata_stream);
        free_stringtable(&database->stringtable);
        free(database);
    }
}

