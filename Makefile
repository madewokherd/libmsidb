CFLAGS=-Wall -g

STORAGE_OBJECTS=msidb-error.o storage.o storage_main.o

MSIDB_OBJECTS=msidb-error.o storage.o msidb.o msidb_main.o ghashtable.o

all: msidb storage

storage: $(LIB_OBJECTS) $(STORAGE_OBJECTS)
	$(CC) $(LDFLAGS) $(LIB_OBJECTS) $(STORAGE_OBJECTS) -o storage

msidb: $(LIB_OBJECTS) $(MSIDB_OBJECTS)
	$(CC) $(LDFLAGS) $(LIB_OBJECTS) $(MSIDB_OBJECTS) -lm -o msidb

clean:
	rm -f $(LIB_OBJECTS) $(MSIDB_OBJECTS) storage msidb

