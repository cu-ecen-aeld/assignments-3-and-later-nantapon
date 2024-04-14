all: aesdsocket

.PHONY: clean
clean:
	rm -rf aesdsocket *.o

aesdsocket: aesdsocket.c
	$(CC) -Wall -Werror -g aesdsocket.c -o aesdsocket 
