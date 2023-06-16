#include <cstddef>                     // size_t
#include <cstdint>                     // uint16_t, uint32_t
#include <cstring>                     // strcmp
#include <vector>                      // vector
#include <string>                      // string
#include <string_view>                 // string_view
#include <iostream>                    // cout, endl
#include <fstream>                     // ifstream, ofstream
#include <ios>                         // ios::binary, ios::trunc

#include "aes.h"                       // AES_init_ctx

using std::size_t, std::uint16_t, std::uint32_t,
      std::vector, std::string, std::string_view, std::cout, std::endl;

struct ELFHeader {
    uint32_t ident[4u];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} __attribute__((__packed__));

struct SectionHeader {
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
} __attribute__((__packed__));

void Encrypt_Bytes(uint8_t *const p, size_t const len, string_view const key)
{
    if ( (32u * 2u) != key.size() ) return;  // key should be 32 bytes represented by 64 hex chars

    // First we convert the ASCII string to raw binary

    uint8_t bin[32u];

    for ( unsigned i = 0u; i < 32u; ++i )
    {
        if ( (key[2u * i + 0u] >= '0') && (key[2u * i + 0u] <= '9') ) bin[i]  = (key[2u * i + 0u] - '0') << 4u;
        else
        {
            switch( key[2u * i + 0u] )
            {
            case 'a': case 'A':  bin[i] = 0xAu << 4u; break;
            case 'b': case 'B':  bin[i] = 0xBu << 4u; break;
            case 'c': case 'C':  bin[i] = 0xCu << 4u; break;
            case 'd': case 'D':  bin[i] = 0xDu << 4u; break;
            case 'e': case 'E':  bin[i] = 0xEu << 4u; break;
            case 'f': case 'F':  bin[i] = 0xFu << 4u; break;
            default:
                return;
            }
        }

        if ( (key[2u * i + 1u] >= '0') && (key[2u * i + 1u] <= '9') ) bin[i] |= (key[2u * i + 1u] - '0');
        else
        {
            switch( key[2u * i + 1u] )
            {
            case 'a': case 'A':  bin[i] |= 0xAu; break;
            case 'b': case 'B':  bin[i] |= 0xBu; break;
            case 'c': case 'C':  bin[i] |= 0xCu; break;
            case 'd': case 'D':  bin[i] |= 0xDu; break;
            case 'e': case 'E':  bin[i] |= 0xEu; break;
            case 'f': case 'F':  bin[i] |= 0xFu; break;
            default:
                return;
            }
        }
    }

    AES_ctx ctx;

    AES_init_ctx(&ctx, bin);

    static uint8_t const iv_all_zeroes[16u] = {};

    AES_ctx_set_iv(&ctx, iv_all_zeroes);

    AES_CTR_xcrypt_buffer(&ctx, p, len);
}

bool Encrypt_File(string const &file_path, string_view const key)
{
    std::ifstream input_file(file_path, std::ios::binary);

    if ( !input_file )
    {
        cout << "Error opening file: " << file_path << endl;
        return false;
    }

    vector<uint8_t> file_data{
        std::istreambuf_iterator<char>(input_file),
        std::istreambuf_iterator<char>()
    };

    input_file.close();

    ELFHeader const *const elf_header = static_cast<ELFHeader*>(static_cast<void*>(&file_data.front()));

    cout << "File size: " << file_data.size() << " bytes\n";
    cout << "Count Sections: " <<  elf_header->shnum << endl;

    // The next 2 lines are for finding the strings of the names of the sections
    SectionHeader const *const shdr = static_cast<SectionHeader*>(static_cast<void*>(&file_data.front() + elf_header->shoff));
    const char *const sh_strtab_p = (char*)elf_header + shdr[elf_header->shstrndx].offset;

    uint64_t offset_of_encrypted_section = 0u, size_of_encrypted_section = 0u;

    for ( unsigned i = 0u; i < elf_header->shnum; ++i )
    {
        SectionHeader const *const section_header = static_cast<SectionHeader*>(static_cast<void*>(
            &file_data[elf_header->shoff + (i * elf_header->shentsize)]
        ));

        cout << "Address: " << section_header->addr
             << ", size_of_encrypted_section: " << section_header->size
             << ", Name Offset: " << section_header->name;

        char const *const str_section_name = sh_strtab_p + shdr[i].name;

        cout << ", Name: " << str_section_name << endl;

        if ( 0 == strcmp(".encrypted", str_section_name) )
        {
            offset_of_encrypted_section = section_header->addr;
            size_of_encrypted_section = section_header->size;
            break;
        }
    }

    if ( (0u==offset_of_encrypted_section) || (0u==size_of_encrypted_section) )
    {
        cout << "Failed to find the encrypted section" << endl;
        return false;
    }

    cout << "Encrypted section found at " << offset_of_encrypted_section << " with length = " << size_of_encrypted_section << endl;

    Encrypt_Bytes(&file_data[offset_of_encrypted_section], size_of_encrypted_section, key);

    std::ofstream output_file;
    output_file.open(file_path, std::ios::binary | std::ios::trunc);
    if ( !output_file )
    {
        cout << "Error opening file for writing: " << file_path << endl;
        return false;
    }

    output_file.write( (char*)&file_data.front(), file_data.size() );
    return true;
}

int main(int argc, char* argv[])
{
    if ( argc < 3 )
    {
        cout << "[-] Usage: " << argv[0] << " filname encryption_key" << endl;
        return 1;
    }

    if ( Encrypt_File(argv[1], argv[2]))
    {
        cout << "Done." << endl;
    }
    else
    {
        cout << "FAILURE" << endl;
    }
}
