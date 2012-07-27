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
#include <stdio.h>
#include <ctype.h>

#include "storage.h"

int usage(void)
{
    printf("msidb -l filename\n");
    printf("    List the items at the top level of the file.\n\n");
    printf("msidb -t filename itemname\n");
    printf("    Check the type and size of the named item.\n\n");
    return 5;
}

int enum_children_proc(MsidbStorage *storage, const msidb_stat_t *stat, void *user_data)
{
    printf("%s\n", stat->name);
    return 0;
}

int enum_children(int argc, char** argv)
{
    MsidbStorage *storage;

    if (argc < 3)
        return usage();

    storage = msidb_storage_open_file(argv[2], "r", 0);

    msidb_storage_enum_children(storage, enum_children_proc, NULL, NULL);

    msidb_storage_unref(storage);

    return 0;
}

int stat_item(int argc, char** argv)
{
    MsidbStorage *storage;
    msidb_stat_t stat;
    int found;

    if (argc < 4)
        return usage();

    storage = msidb_storage_open_file(argv[2], "r", 0);

    msidb_storage_stat_item(storage, argv[3], &stat, &found, NULL);

    if (found)
    {
        if (stat.is_dir)
            printf("Storage\n");
        else
            printf("Stream (%" PRIu64 " bytes)\n", stat.stream_size);
    }
    else
    {
        printf("Item does not exist: %s\n", argv[3]);
    }

    msidb_storage_unref(storage);

    return !found;
}

int main(int argc, char** argv)
{
    if (argc < 2)
        return usage();

    if ((argv[1][0] == '-' || argv[1][0] == '/') && argv[1][1] && !argv[1][2])
    {
        char letter = tolower(argv[1][1]);
        switch (letter)
        {
        case 'l':
            return enum_children(argc, argv);
        case 't':
            return stat_item(argc, argv);
        default:
            return usage();
        }
    }
    else
        return usage();
}

