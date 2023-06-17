#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "aes.h"

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

void decrypt_mem(char* addr,char* dummy,char key[]) {
	mp((void*)addr);
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, "\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\x11\x22");
    static uint8_t const iv_all_zeroes[16u] = {};
    AES_ctx_set_iv(&ctx, iv_all_zeroes);
    AES_CTR_xcrypt_buffer(&ctx,addr,dummy-addr);
	restore((void*)addr);
}
