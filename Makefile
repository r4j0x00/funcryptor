all: test.c
	gcc -s -O0 -o test test.c funcryptor.c

