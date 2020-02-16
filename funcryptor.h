#define decrypt(function_name, dummy, key) decrypt_mem((char*)&function_name, (char*)&dummy, key)
#ifndef MY_FUN
    #define MY_FUN
    void xormem(char *addr,char key[],int size);
    void decrypt_mem(char* addr,char* dummy,char key[]);
    int mp(void *addr);
    void restore(void* addr);
#endif
#define encrypted __attribute__((section(".encrypted")))
