all: libflaggen.so

libflaggen.so: flag.o
	gcc -shared -o $@ $<

flag.o: flag.c
	gcc -c -Wall -O2 -s -fpic $<
