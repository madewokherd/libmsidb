/*
 * ghashtable.c: Hashtable implementation
 *
 * Author:
 * Miguel de Icaza (miguel@novell.com)
 *
 * (C) 2006 Novell, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Note: This was lifted from Mono's eglib library. The names have been changed
 * to protect the innocent (from accidentally linking to them). */

#include <stdint.h>

/*
* Basic data types
*/
typedef int gint;
typedef unsigned int guint;
typedef short gshort;
typedef unsigned short gushort;
typedef long glong;
typedef unsigned long gulong;
typedef void * gpointer;
typedef const void * gconstpointer;
typedef char gchar;
typedef unsigned char guchar;

typedef int8_t gint8;
typedef uint8_t guint8;
typedef int16_t gint16;
typedef uint16_t guint16;
typedef int32_t gint32;
typedef uint32_t guint32;
typedef int64_t gint64;
typedef uint64_t guint64;
typedef float gfloat;
typedef double gdouble;
typedef int32_t gboolean;

typedef size_t gsize;

/*
* Macros
*/
#define G_N_ELEMENTS(s) (sizeof(s) / sizeof ((s) [0]))

#define FALSE 0
#define TRUE 1

#define G_MINSHORT SHRT_MIN
#define G_MAXSHORT SHRT_MAX
#define G_MAXUSHORT USHRT_MAX
#define G_MAXINT INT_MAX
#define G_MININT INT_MIN
#define G_MAXINT32 INT32_MAX
#define G_MAXUINT32 UINT32_MAX
#define G_MININT32 INT32_MIN
#define G_MININT64 INT64_MIN
#define G_MAXINT64 INT64_MAX
#define G_MAXUINT64 UINT64_MAX

typedef void (*GFunc) (gpointer data, gpointer user_data);
typedef gint (*GCompareFunc) (gconstpointer a, gconstpointer b);
typedef gint (*GCompareDataFunc) (gconstpointer a, gconstpointer b, gpointer user_data);
typedef void (*GHFunc) (gpointer key, gpointer value, gpointer user_data);
typedef gboolean (*GHRFunc) (gpointer key, gpointer value, gpointer user_data);
typedef void (*GDestroyNotify) (gpointer data);
typedef guint (*GHashFunc) (gconstpointer key);
typedef gboolean (*GEqualFunc) (gconstpointer a, gconstpointer b);
typedef void (*GFreeFunc) (gpointer data);

/*
* Hashtables
*/
typedef struct _GHashTable GHashTable;
typedef struct _GHashTableIter GHashTableIter;

struct _GHashTableIter
{
gpointer dummy [8];
};

GHashTable *_msidb_hash_table_new (GHashFunc hash_func, GEqualFunc key_equal_func);
GHashTable *_msidb_hash_table_new_full (GHashFunc hash_func, GEqualFunc key_equal_func,
GDestroyNotify key_destroy_func, GDestroyNotify value_destroy_func);
gboolean _msidb_hash_table_insert_replace (GHashTable *hash, gpointer key, gpointer value, gboolean replace);
guint _msidb_hash_table_size (GHashTable *hash);
gpointer _msidb_hash_table_lookup (GHashTable *hash, gconstpointer key);
gboolean _msidb_hash_table_lookup_extended (GHashTable *hash, gconstpointer key, gpointer *orig_key, gpointer *value);
void _msidb_hash_table_foreach (GHashTable *hash, GHFunc func, gpointer user_data);
gpointer _msidb_hash_table_find (GHashTable *hash, GHRFunc predicate, gpointer user_data);
gboolean _msidb_hash_table_remove (GHashTable *hash, gconstpointer key);
gboolean _msidb_hash_table_steal (GHashTable *hash, gconstpointer key);
void _msidb_hash_table_remove_all (GHashTable *hash);
guint _msidb_hash_table_foreach_remove (GHashTable *hash, GHRFunc func, gpointer user_data);
guint _msidb_hash_table_foreach_steal (GHashTable *hash, GHRFunc func, gpointer user_data);
void _msidb_hash_table_destroy (GHashTable *hash);
void _msidb_hash_table_print_stats (GHashTable *table);

void _msidb_hash_table_iter_init (GHashTableIter *iter, GHashTable *hash_table);
gboolean _msidb_hash_table_iter_next (GHashTableIter *iter, gpointer *key, gpointer *value);

guint _msidb_spaced_primes_closest (guint x);

#define _msidb_hash_table_insert(h,k,v) _msidb_hash_table_insert_replace ((h),(k),(v),FALSE)
#define _msidb_hash_table_replace(h,k,v) _msidb_hash_table_insert_replace ((h),(k),(v),TRUE)

gboolean _msidb_direct_equal (gconstpointer v1, gconstpointer v2);
guint _msidb_direct_hash (gconstpointer v1);
gboolean _msidb_int_equal (gconstpointer v1, gconstpointer v2);
guint _msidb_int_hash (gconstpointer v1);
gboolean _msidb_str_equal (gconstpointer v1, gconstpointer v2);
guint _msidb_str_hash (gconstpointer v1);

