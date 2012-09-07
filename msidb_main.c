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
    printf("msidb -p filename [property]\n");
    printf("    Dump the property table, or a single property if specified, from the database.\n\n");
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

int dump_property_table(int argc, char** argv)
{
    MsidbDatabase *database;
    MsidbTable *table;
    int found;

    if (argc < 3)
        return usage();

    database = msidb_database_open_file(argv[2], "r", NULL);

    table = msidb_database_open_table(database, "Property", &found, NULL);

    if (found)
    {
        uint32_t values[2];
        uint32_t i;
        const char *str;

        if (argc == 3)
        {
            uint32_t num_rows;

            num_rows = msidb_table_get_num_rows(table, NULL);

            for (i=0; i<num_rows; i++)
            {
                /* FIXME: assuming two string value columns */
                msidb_table_get_nth_row(table, i, values, 2, NULL);

                str = msidb_database_get_interned_string(database, values[0], &found);

                if (!found)
                {
                    printf("Invalid string reference in Property table. Aborting!\n");
                    return 6;
                }

                printf("%s\t", str);

                str = msidb_database_get_interned_string(database, values[1], &found);

                if (!found)
                {
                    printf("Invalid string reference in Property table. Aborting!\n");
                    return 7;
                }

                printf("%s\n", str);
            }
        }
        else
        {
            values[0] = msidb_database_intern_string(database, argv[3], 0, &found, NULL);

            if (found)
            {
                i = msidb_table_find_row(table, values, 1, &found, NULL);

                if (found)
                {
                    msidb_table_get_nth_row(table, i, values, 2, NULL);

                    str = msidb_database_get_interned_string(database, values[1], &found);

                    if (!found)
                    {
                        printf("Invalid string reference in Property table. Aborting!\n");
                        return 8;
                    }

                    printf("%s", str);
                }
            }

            if (!found)
            {
                printf("Property not found\n");
                return 9;
            }
        }

        msidb_table_unref(table);
    }

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
        case 'p':
            return dump_property_table(argc, argv);
        default:
            return usage();
        }
    }
    else
        return usage();

}

