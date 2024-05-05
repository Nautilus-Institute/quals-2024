CC++ = g++
CC = gcc
CFLAGS = -std=gnu++2b -g -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -fpermissive -Wno-write-strings
LDFLAGS = -lurcu -lurcu-memb -lurcu-cds -lurcu-common -I/usr/local/include

all: deen

deen: pd.cpp
		$(CC++) $(CFLAGS) pd.cpp -o deenzone $(LDFLAGS)

clean:
	rm -f deenzone
