CC = gcc
CFLAGS = -O0
LFLAGS = -lncurses

thumb-thumb: thumb-thumb.c
	$(CC) -o $@ $< $(CFLAGS) $(LFLAGS)

thumb-thumb-debug: thumb-thumb.c
	$(CC) -o $@ $< $(CFLAGS) $(LFLAGS) -ggdb
