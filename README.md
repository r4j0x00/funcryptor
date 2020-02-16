# funcryptor
Encrypt C functions and decrypt them at runtime.  
The function is encrypted after the program is compiled. It is then decrypted at runtime by xoring the function with the key. 

## Prerequisites
Elftools
```bash
pip install pyelftools
```

## Usage
An example program is shown in test.c 
you need to include "funcryptor.h" in your c program and prepend `encrypted` to the function you want to encrypt.  
```c
encrypted void function_name() 
```
  
This should be followed by a dummy function. This is used to calculate the function size.
```c
encrypted void dummy() {}
```
  
You can then decrypt your function by -
```c
decrypt(function_name, dummy, "mykey");
``` 
To compile use `make`.  
Then run `python ./encrypt.py file_name encryption_key` to encrypt the binary.

Now if you run the binary it works as it should have.
```bash
root@kali:~/funcryptor# python encrypt.py test mykey
[+] Done
root@kali:~/funcryptor# ./test 
This is the encrypted function
```

## Looking at disassembly

Objdump 
```
root@kali:~/funcryptor# objdump -M intel -D ./test|grep encrypt -A 15
Disassembly of section .encrypted:

0000000000001311 <.encrypted>:
    1311:	38 31                	cmp    BYTE PTR [rcx],dh
    1313:	e2 80                	loop   1295 <__cxa_finalize@plt+0x225>
    1315:	31 e0                	xor    eax,esp
    1317:	44 87 69 79          	xchg   DWORD PTR [rcx+0x79],r13d
    131b:	6d                   	ins    DWORD PTR es:[rdi],dx
    131c:	91                   	xchg   ecx,eax
    131d:	64 98                	fs cwde 
    131f:	86 92 e9 36 a6 2c    	xchg   BYTE PTR [rdx+0x2ca636e9],dl
    1325:	25 f0 8e f5 24       	and    eax,0x24f58ef0
    132a:	ae                   	scas   al,BYTE PTR es:[rdi]
```
  
  radare2
  ```
  [0x00001080]> pdf @ fcn.00001311
        :   ;-- section..encrypted:
        :   ;-- rdi:
/ (fcn) fcn.00001311 36
|   fcn.00001311 (int32_t arg3, uint32_t arg4);
|       :   ; arg int32_t arg3 @ rdx
|       :   ; arg uint32_t arg4 @ rcx
|       :   ; CALL XREFS from main @ 0x1177, 0x1188
|       :   0x00001311      3831           cmp byte [rcx], dh          ; arg4 ; [15] -r-x section size 26 named .encrypted
|       `=< 0x00001313      e280           loop 0x1295
|           0x00001315      31e0           xor eax, esp
|           0x00001317      44876979       xchg dword [rcx + 0x79], r13d ; arg4
|           0x0000131b      6d             insd dword [rdi], dx
|           0x0000131c      91             xchg eax, ecx               ; arg4
|           0x0000131d      6498           cwde
|           0x0000131f  ~   8692e936a62c   xchg byte [rdx + 0x2ca636e9], dl ; arg3
|           ;-- rsi:
..
|           0x00001325      25f08ef524     and eax, 0x24f58ef0
|           0x0000132a      ae             scasb al, byte [rdi]
|           0x0000132b  ~   004883         add byte [rax - 0x7d], cl
|           ;-- section..fini:
..
|           0x0000132e      ec             in al, dx                   ; [16] -r-x section size 9 named .fini
|           0x0000132f      084883         or byte [rax - 0x7d], cl
  ```
