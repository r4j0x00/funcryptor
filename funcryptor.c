#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

int mp(void *addr) {
    int size = getpagesize();
    addr -= (unsigned long)addr % size;

    if(mprotect(addr, size, 7) == -1) {
        return -1;
    }
    return 0;
}
void xormem(char *addr,char key[],int size) {
	int keylen = strlen(key);
	if (keylen == 0){return ;}
	for (int i=0;i<size;i++) {
		addr[i] = addr[i] ^ key[i%keylen];
	}
}

void decrypt(char* addr,char* dummy,char key[]) {
	mp((void*)addr);
	xormem(addr,key,dummy-addr);
}
