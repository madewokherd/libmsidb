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

#include "storage.h"

typedef struct _MsidbDatabase MsidbDatabase;

typedef struct _MsidbTable MsidbTable;

MsidbDatabase* msidb_database_open_storage(MsidbStorage *storage, const char *mode, int shared_storage, MsidbError *err);

MsidbDatabase* msidb_database_open_file(const char *filename, const char *mode, MsidbError *err);

void msidb_database_ref(MsidbDatabase *database);

void msidb_database_unref(MsidbDatabase *database);

void msidb_database_close(MsidbDatabase *database, MsidbError *err);

#if 0 /* not yet implemented */
void msidb_database_commit(MsidbDatabase *database, MsidbError *err);

void msidb_database_import_table(MsidbDatabase *database, const char *filename,
    MsidbError *err);
#endif

uint32_t msidb_database_num_tables(MsidbDatabase *database, MsidbError *err);

const char* msidb_database_nth_table_name(MsidbDatabase *database, uint32_t index, MsidbError *err);

#if 0
MsidbStream* msidb_database_open_stream(MsidbDatabase *database, const char *name, int *found, MsidbError *err);

MsidbStorage* msidb_database_get_storage_ref(MsidbDatabase *database);

MsidbTable* msidb_database_open_table(MsidbDatabase *database, const char *name, int *found, MsidbError *err);

void msidb_table_ref(MsidbTable *table);

void msidb_table_unref(MsidbTable *table);

uint32_t msidb_table_get_num_columns(MsidbTable *table, MsidbError *err);

const char* msidb_table_get_column_name(MsidbTable *table, uint32_t index, MsidbError *err);

uint32_t msidb_table_get_column_type(MsidbTable *table, uint32_t index, MsidbError *err);
#endif

#define MSIDB_COLTYPE_DATASIZEMASK 0x00ff
#define MSIDB_COLTYPE_VALID 0x0100
#define MSIDB_COLTYPE_LOCALIZABLE 0x200
#define MSIDB_COLTYPE_STRING 0x0800
#define MSIDB_COLTYPE_NULLABLE 0x1000
#define MSIDB_COLTYPE_KEY 0x2000
#define MSIDB_COLTYPE_TEMPORARY 0x4000
#define MSIDB_COLTYPE_UNKNOWN 0x8000

#if 0 /* not yet implemented */
char* msidb_table_get_column_type_string(MsidbTable *table, uint32_t index, MsidbError *err);

uint32_t msidb_table_get_num_rows(MsidbTable *table, MsidbError *err);

void msidb_table_get_nth_row(MsidbTable *table, uint32_t index, uint32_t *values,
    int num_values, MsidbError *err);

char* msidb_table_value_to_string(MsidbTable *table, const uint32_t *values,
    uint32_t index, MsidbError *err);

void msidb_table_value_from_string(MsidbTable *table, uint32_t *values,
    uint32_t index, const char *value, int create, int *found, MsidbError *err);

int32_t msidb_table_value_to_int(MsidbTable *table, const uint32_t *values,
    uint32_t index, MsidbError *err);

void msidb_table_value_from_int(MsidbTable *table, uint32_t *values,
    uint32_t index, int32_t value, MsidbError *err);

MsidbStream* msidb_table_value_open_stream(MsidbTable *table,
    const uint32_t *values, uint32_t index, MsidbError *err);
#endif

uint32_t msidb_table_find_row(MsidbTable *table, const uint32_t *values,
    int num_values, int *found, MsidbError *err);

#if 0
void msidb_table_update_row(MsidbTable *table, const uint32_t *values,
    int num_values, int create, int *found, MsidbError *err);

void msidb_table_delete_row(MsidbTable *table, const uint32_t *values,
    int num_values, MsidbError *err);

void msidb_table_update_row_by_index(MsidbTable *table, const uint32_t *values,
    int num_values, uint32_t index, int create, int *found, MsidbError *err);

void msidb_table_delete_row_by_index(MsidbTable *table, uint32_t index,
    MsidbError *err);

void msidb_table_export(MsidbTable *table, const char *filename,
    MsidbError *err);
#endif

const char *msidb_database_get_interned_string(MsidbDatabase *database,
    uint32_t id, int *found);

uint32_t msidb_database_intern_string(MsidbDatabase *database, const char *value,
    int create, int *found, MsidbError *err);

#if 0
void msidb_database_unref_interned_string(MsidbDatabase *database, uint32_t id,
    MsidbError *err);
#endif

