#pragma once
#include <vector>
#include <iostream>
#include <cassert>
#include "cryptlib.h"
#include "rijndael.h"
#include "serpent.h"
#include "kalyna.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "generate_random.h"

typedef unsigned char* ucp;
using namespace CryptoPP;
//return cipher
static const int text_size = 16;
static bool test = false;
std::string insertion_encryption(std::string plain, std::string password, std::string& random) {

    char indexes_for_inserting[text_size];
    for (int i = 0;i < text_size;++i) {
        indexes_for_inserting[i] = i;//arbitrary choice of initial value can be kept as secret
    }

    using namespace CryptoPP;
    HexEncoder ins_encoder(new FileSink(std::cout));

    SecByteBlock ins_key(32U);

    //prng.GenerateBlock(key, key.size());

    std::string ins_plain;
    ins_plain.append(indexes_for_inserting);
    std::string ins_cipher;

    int index_k = 0;
    for (auto& k : ins_key) {
        k = (byte)password[index_k];
        ++index_k;
    }
    try
    {
        ECB_Mode< Serpent >::Encryption ins_e;
        ins_e.SetKey(ins_key, ins_key.size());

        StringSource ins_s(ins_plain, true,
            new StreamTransformationFilter(ins_e,
                new StringSink(ins_cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    for (int n = 0;n < text_size;++n) {
        indexes_for_inserting[n] = ins_cipher[n];
    }
    for (int y = 0;y < text_size;++y) {
        random.insert((random.begin() + (unsigned char)indexes_for_inserting[y]), plain[y]);
    }


    return random;

}

//return plaintext
std::string insertion_decryption(std::string cipher, std::string password,std::string& random) {
    char indexes_for_inserting[text_size];
    for (int i = 0;i < text_size;++i) {
        indexes_for_inserting[i] = i;//arbitrary choice of initial value can be kept as secret
    }

    using namespace CryptoPP;
    HexEncoder ins_encoder(new FileSink(std::cout));

    SecByteBlock ins_key(32U);

    //prng.GenerateBlock(key, key.size());

    std::string ins_plain;
    ins_plain.append(indexes_for_inserting);
    std::string ins_cipher;

    int index_k = 0;
    for (auto& k : ins_key) {
        k = (byte)password[index_k];
        ++index_k;
    }
    try
    {
        ECB_Mode< Serpent >::Encryption ins_e;
        ins_e.SetKey(ins_key, ins_key.size());

        StringSource ins_s(ins_plain, true,
            new StreamTransformationFilter(ins_e,
                new StringSink(ins_cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    for (int n = 0;n < text_size;++n) {
        indexes_for_inserting[n] = ins_cipher[n];
    }
    std::string plain;
    for (int i = text_size-1;i >= 0;--i) {
        plain += cipher[(unsigned char)indexes_for_inserting[i]];
        cipher.erase((unsigned char)indexes_for_inserting[i], 1);
    }
    std::string reversed;
    for (int j = 0;j < text_size;++j) {
        reversed += plain[text_size-1 - j];
    }
    random = cipher;
    return reversed;
}

std::string xor_encryption(std::string plain, std::string password, std::string& random) {
    char indexes_for_xoring[32*text_size+1];
    for (int i = 1;i <= 32*text_size;++i) {
        indexes_for_xoring[i] = i;//arbitrary choice of initial value can be kept as secret
        if (indexes_for_xoring[i] == 0)++indexes_for_xoring[i];
    }
    HexEncoder xor_encoder(new FileSink(std::cout));

    SecByteBlock xor_key(32U);

    //prng.GenerateBlock(key, key.size());

    std::string xor_plain;
    xor_plain.append(indexes_for_xoring);
    std::string xor_cipher;
    
    int index_j = 0;
    for (auto& k : xor_key) {
        k = (byte)password[index_j];
        ++index_j;
    }
    //std::cout << "xor_plain size: "<< xor_plain.size()<<"\n";
    for (int z = 0;z < 32;++z) {
        std::string xor_partial_cipher;
        try
        {
            ECB_Mode< Kalyna256 >::Encryption xor_e;
            xor_e.SetKey(xor_key, xor_key.size());
            StringSource xor_s(xor_plain.substr(16*z,16), true,
                new StreamTransformationFilter(xor_e,
                    new StringSink(xor_partial_cipher)
                ) // StreamTransformationFilter
            ); // StringSource
        }
        catch (const Exception& e)
        {
            std::cerr << e.what() << std::endl;
            exit(1);
        }
        xor_cipher += xor_partial_cipher;
    }
    for (int m = 0;m < 32*text_size;++m) {
        indexes_for_xoring[m] = xor_cipher[m];
    }
    std::string cipher = plain;
    int xor_index = 0;
    //std::cout << "cipher length " << cipher.size() << "\n";
    for (int n = 0;n < text_size;++n) {
        for (int o = 0;o < 32;++o) {
            if (xor_index >= 512) {
                std::cout << "n " << n << " o : " << o << " " << "xor_index : " << xor_index << "\n";
            }
            if (((unsigned char)indexes_for_xoring[xor_index]) >= 256) {
                std::cout << "n " << n << " o : " << o << " " << "indexes_for_xoring[xor_index] : " << (unsigned char)indexes_for_xoring[xor_index] << "\n";
            }
            cipher[n] ^= (unsigned char)random[(unsigned char)indexes_for_xoring[xor_index]];
            ++xor_index;
        }
    }
    return cipher;
}

std::string AES_encryption(std::string plain, std::string password) {

    SecByteBlock key(32U);
    int index_i = 0;
    for (auto& k : key) {
        k = (byte)password[index_i];
        ++index_i;
    }
    //prng.GenerateBlock(key, key.size());

    //plain.append(indexes_for_xoring);
    std::string cipher;

    try
    {
        ECB_Mode< AES >::Encryption e;
        e.SetKey(key, key.size());

        StringSource s(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    return cipher;
}

std::string AES_decryption(std::string cipher, std::string password) {

    SecByteBlock key(32U);
    int index_i = 0;
    for (auto& k : key) {
        k = (byte)password[index_i];
        ++index_i;
    }
    //prng.GenerateBlock(key, key.size());

    //plain.append(indexes_for_xoring);
    std::string plain;

    try
    {
        ECB_Mode< AES >::Decryption d;
        d.SetKey(key, key.size());

        StringSource s(cipher, true,
            
                new StreamTransformationFilter(d,
                    new StringSink(plain),
                    StreamTransformationFilter::NO_PADDING
                ) // StreamTransformationFilter
            
        ); // StringSource
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    return plain;
}

//text have 16 chars base_passsword has 32 chars (or less)xor_pasword has 64 chars(or less) insertion_password in this case has 32 chars(or less)
std::string xor_insertion_encryption(std::string text, std::string base_password, std::string xor_password, std::string insertion_password, std::string random) {
    std::string AES = AES_encryption(text, base_password);
    if (test) {
        std::cout << "AES encrypted :" << AES << "\n\n";
    }
    std::string xored_text = xor_encryption(AES, xor_password, random);
    if (test) {
        std::cout << "xored text encrypted " << xored_text << "\n\n";
    }
    std::string extended_xored_text = insertion_encryption(xored_text, insertion_password, random);
    if (test) {
        std::cout << "extended_xored_text encrypted " << extended_xored_text << "\n\n";
    }
    return extended_xored_text;
}

std::string xor_insertion_decryption(std::string text, std::string base_password, std::string xor_password, std::string insertion_password) {
    std::string random;
    std::string xored_text = insertion_decryption(text, insertion_password, random);
    //std::cout << random << "\n\n";
    if (test) {
        std::cout << "xored text " << xored_text << "\n\n";
    }
    std::string AES = xor_encryption(xored_text, xor_password, random);
    if (test) {
        std::cout << "AES: " << AES << "\n\n";
    }
    std::string plain = AES_decryption(AES, base_password);
    if (test) {
        std::cout << "plain : " << plain << "\n\n";
    }
    return plain;
}

std::string xia_encryption(std::string plaintext, std::string base_password, std::string xor_password, std::string insertion_password) {
    const int size = plaintext.size();
    int iterations = size / text_size;
    std::string cipher="";
    for (int iter = 0;iter < iterations;++iter) {
        std::string random = "";
        for (int i = 0;i < 256;++i) {
            random += generate_random_char();
        }
        CryptoPP::byte out[256];
        CryptoPP::OS_GenerateRandomBlock(false, out, 256);
        for (int i = 0;i < 256;++i) {
            random[i] ^= out[i];
        }
        //std::cout << "Random " << random << "\n\n";
        //std::cout << plaintext.substr(iter * 16, 16) << " ";
        std::string partial_cipher = xor_insertion_encryption(plaintext.substr(iter * 16, 16), base_password, xor_password, insertion_password, random);
        //std::cout << "partial cipher "<<partial_cipher << "\n\n ";
        cipher += partial_cipher;
    }
    
    return cipher;
}

std::string xia_decryption(std::string cipher, std::string base_password, std::string xor_password, std::string insertion_password) {
    //std::cout << "xia_decryption\n\n";
    const int size = cipher.size();
    int iterations = size / (text_size*16+16);
    if (test) {
        std::cout << "Size : " << size << " " << "iterations : " << iterations << "\n\n";
    }
    std::string recovered = "";
    for (int iter = 0;iter < iterations;++iter) {
        //std::cout <<"cipher: "<< cipher.substr(0* (text_size * 16 + 16), (text_size * 16 + 16)) << "\n\n";
        std::string partial_recovered = xor_insertion_decryption(cipher.substr(iter * (text_size * 16 + 16), (text_size * 16 + 16)), base_password, xor_password, insertion_password);
        recovered += partial_recovered;
        //std::cout << "partial_recovered : " << partial_recovered << "\n\n";
    }
    return recovered;
}