#!/usr/bin/env python2
from elftools.elf.elffile import ELFFile
from sys import argv,exit

def xor(string,key):
    enc = ''
    length = len(string)
    key_len = len(key)
    for i in range(length):
        enc += chr(ord(string[i]) ^ ord(key[i%key_len]))
    return enc

def encrypt(file_path,key):
    f = open(file_path,'rb')
    elf = ELFFile(f)
    encrypted_section = elf.get_section_by_name('.encrypted')['sh_addr']
    size = elf.get_section_by_name('.encrypted')['sh_size']
    f.close()
    f = open(file_path,'rb').read()
    encrypted = f[encrypted_section:encrypted_section+size]
    if len(encrypted) < len(key):
        return -1
    encrypted = f.replace(encrypted,xor(encrypted,key))
    f = open(file_path,'wb')
    f.write(encrypted)
    f.close()
    return True

def main():
    if len(argv)<3:
        print("[-] Usage: python3 {0} file_name encryption_key".format(argv[0]))
        exit(1)
    if encrypt(argv[1],argv[2]):
        print("[+] Done")
    else:
        print('[-] Length of key must be smaller than the length of the function')

if __name__ == '__main__':
    main()
