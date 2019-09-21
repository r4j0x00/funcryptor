#ifndef MY_FUN
    #define MY_FUN
    void xormem(char *addr,char key[],int size);
    void decrypt(char* addr,char* dummy,char key[]);
    int mp(void *addr);
#endif
#define encrypted __attribute__((section(".encrypted")))
