#include <stdio.h>
#include "funcryptor.h"

encrypted void enc_function() {
	printf("This is the encrypted function\n");
}
encrypted void dummy() {}

int main() {
	decrypt((char*)&enc_function,(char*)&dummy,"mykey");
	enc_function();
}
