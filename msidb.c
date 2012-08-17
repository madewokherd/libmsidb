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
#include <stdlib.h>

#include "msidb.h"
#include "msidb-private.h"

struct _MsidbDatabase {
    unsigned int ref;
    MsidbStorage *storage;
    int shared_storage;
    MsidbStream *stringpool_stream;
    MsidbStream *stringdata_stream;
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

    printf("%s\n", encoded_name);

    return msidb_storage_open_substream(parent, encoded_name, found, err);
}

MsidbDatabase* msidb_database_open_storage(MsidbStorage *storage, const char *mode, int shared_storage, MsidbError *err)
{
    MsidbDatabase *result;
    MsidbStream *stringpool, *stringdata;
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
        free(database);
    }
}

