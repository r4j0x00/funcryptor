#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#define decrypt(function_name, dummy, key) decrypt_mem((char*)&function_name, (char*)&dummy, key)

int mp(void *addr) {
    int size = getpagesize();
    addr -= (unsigned long)addr % size;

    if(mprotect(addr, size, PROT_READ| PROT_WRITE| PROT_EXEC) == -1) {
        return -1;
    }
    return 0;
}

void restore(void* addr)
{
	int size = getpagesize();
	addr -= (unsigned long)addr % size;
	assert(mprotect(addr, size, PROT_READ | PROT_EXEC) != -1);
}

void xormem(char *addr,char key[],int size) {
	int keylen = strlen(key);
	if (keylen == 0){return ;}
	for (int i=0;i<size;i++) {
		addr[i] = addr[i] ^ key[i%keylen];
	}
}

void decrypt_mem(char* addr,char* dummy,char key[]) {
	mp((void*)addr);
	xormem(addr,key,dummy-addr);
	restore((void*)addr);
}
