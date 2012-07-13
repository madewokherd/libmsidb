CFLAGS=-Wall -g

LIB_OBJECTS=msidb-error.o storage.o

MSIDB_OBJECTS=msidb_main.o

msidb: $(LIB_OBJECTS) $(MSIDB_OBJECTS)
	$(CC) $(LDFLAGS) $(LIB_OBJECTS) $(MSIDB_OBJECTS) -o msidb

all: msidb

clean:
	rm -f $(LIB_OBJECTS) $(MSIDB_OBJECTS) msidb
