all:
	gcc -o aes.o -c aes.c -O3 -s
	gcc -o test test.c funcryptor.c aes.o -O0 -s
	g++ -o encrypt encrypt.cpp aes.o -O3 -s
