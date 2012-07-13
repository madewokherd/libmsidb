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

typedef enum _MsidbErrorCode {
    MSIDB_ERROR_SUCCESS,
    MSIDB_ERROR_ERRNO,
    MSIDB_ERROR_HRESULT,
    MSIDB_ERROR_OUTOFMEMORY,
    MSIDB_ERROR_INVALIDDATA,
    MSIDB_ERROR_INVALIDARG
} MsidbErrorCode;

typedef struct _MsidbError {
    MsidbErrorCode code;
    unsigned int extra_data;
} MsidbError;

#define msidb_check_error(err) (!err || !err->code)

void msidb_set_error(MsidbError *err, MsidbErrorCode code, unsigned int extra_data, const char *extra_string_data);

void msidb_set_os_error(MsidbError *err, const char *extra_string_data);

