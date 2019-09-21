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
you need to include "funcryptor.h" in your c program and prepend `encrypted` to the function you wan't to encrypt.  
```c
encrypted void function_name() 
```
  
This should be followed by a dummy function. This is used to calculate the function size.
```c
encrypted void dummy() {}
```
  
You can then encrypt your function by -
```c
decrypt((char*)&function_name,(char*)&dummy,"mykey");
``` 
To compile use `make`.
