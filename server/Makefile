all: aesdsocket

CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall -Werror
TARGET ?= aesdsocket
LDFLAGS ?= -lpthread -lrt

.PHONY: clean
clean:
	rm -rf aesdsocket *.o

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS) 
