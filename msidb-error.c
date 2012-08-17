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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "msidb-error.h"

const char *error_messages[] = {
    NULL, /* MSIDB_ERROR_SUCCESS */
    NULL, /* MSIDB_ERROR_ERRNO */
    NULL, /* MSIDB_ERROR_HRESULT */
    "Out of memory", /* MSIDB_ERROR_OUTOFMEMORY */
    "Invalid storage data", /* MSIDB_ERROR_INVALIDDATA */
    "Invalid argument", /* MSIDB_ERROR_INVALIDARG */
    "Not implemented" /* MSIDB_ERROR_NOTIMPL */
};

void msidb_set_error(MsidbError *err, MsidbErrorCode code, unsigned int extra_data, const char *extra_string_data)
{
    if (err)
    {
        err->code = code;
        err->extra_data = extra_data;
    }
    else
    {
        fprintf(stderr, "libmsidb error: ");
        if (code == MSIDB_ERROR_ERRNO)
            fprintf(stderr, "%s", strerror(extra_data));
        else if (code == MSIDB_ERROR_HRESULT)
            fprintf(stderr, "COM ERROR %x", extra_data);
        else if (extra_data != 0)
            fprintf(stderr, "%s (%x)", error_messages[code], extra_data);
        else
            fprintf(stderr, "%s", error_messages[code]);
        if (extra_string_data)
            fprintf(stderr, " (%s)", extra_string_data);
        fprintf(stderr, "\n");
        fflush(stderr);
        abort();
    }
}

void msidb_set_os_error(MsidbError *err, const char *extra_string_data)
{
    msidb_set_error(err, MSIDB_ERROR_ERRNO, errno, extra_string_data);
}

