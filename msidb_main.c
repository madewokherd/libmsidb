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
#include <inttypes.h>
#include <stdio.h>
#include <ctype.h>

#include "msidb.h"

int usage(void)
{
    printf("msidb -e filename [tables]\n");
    printf("    Export the tables from an msi database.\n\n");
    return 5;
}

int export_tables(int argc, char** argv)
{
    MsidbDatabase *database;
    int i, num_tables;

    if (argc < 3)
        return usage();

    database = msidb_database_open_file(argv[2], "r", NULL);

    num_tables = msidb_database_num_tables(database, NULL);

    for (i=0; i<num_tables; i++)
        printf("%s\n", msidb_database_nth_table_name(database, i, NULL));

    msidb_database_unref(database);

    return 0;
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
        case 'e':
            return export_tables(argc, argv);
        default:
            return usage();
        }
    }
    else
        return usage();

}

