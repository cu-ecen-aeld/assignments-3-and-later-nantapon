all: writer

.PHONY: clean
clean:
	rm -rf writer *.o

writer: writer.c
ifeq ($(CROSS_COMPILE),)
	gcc writer.c -o writer 
else
	$(CROSS_COMPILE)gcc writer.c -o writer
endif
